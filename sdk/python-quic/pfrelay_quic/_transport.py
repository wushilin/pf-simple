"""The QUIC transport (PROTOCOL.md 13), plugged into pfrelay's Client:
discovery over HTTPS, one QUIC connection to the hub made again when it is
lost, and serve, connect and check as requests on its streams."""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Optional

from pfrelay import LinkError, PfRelayError, StatusError
from pfrelay import transport as spi

from ._quic import PinMismatch, QConn, QStream, background, dial
from ._wire import (
    MAX_MESSAGE,
    Answer,
    Code,
    Discovery,
    Malformed,
    MessageFin,
    clean_text,
    encode_message,
    end_reason,
    parse_message,
    request,
)

log = logging.getLogger("pfrelay")

PROTO = 3  # the tunnel protocol this transport speaks, only over QUIC
ANSWER_WAIT = 15.0  # how long the client waits for the hub's answer (13.4)
REQUEST_WAIT = 10.0  # for an open on a stream the hub opened, and its serve's answer (13.4)
WRITE_WAIT = 10.0  # bounds writing an answer to an open
OPEN_QUEUE = 128  # opens queued for a registration, beyond the listener's backlog
DELIVER_WAIT = 3.0

PATH = "/pf/api/tunnel/quic"
H_VERSION = "X-PF-Version"
H_OP = "X-PF-Tunnel-Op"
H_SERVE = "X-PF-Serve-Token"
H_WORD = "X-PF-Tunnel-Word"
H_CLIENT_TOKEN = "X-PF-Client-Token"

OP_SERVE = "serve"
OP_CONNECT = "connect"  # a check counts as connect (13.2)

NO_QUIC = (
    "this hub does not offer QUIC: it is older than pf-simple 0.16.0, or its relay hub is off; "
    "upgrade it, or use pf-client (WebSocket)"
)
PIN_MISMATCH = "the hub's QUIC certificate does not match what its HTTPS endpoint announced"


class QuicProtoError(PfRelayError):
    """The hub accepted a request in a QUIC protocol this client does not
    speak. Retrying cannot help: one side must be upgraded."""

    def __init__(self, proto: int):
        self.proto = proto
        super().__init__(f"the hub answered in QUIC protocol {proto}; this client speaks {PROTO}")


async def _read_exactly(s: QStream, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = await s.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


async def read_message(s: QStream) -> dict:
    """One message, reading exactly its bytes and nothing after, so the frames
    that follow stay on the stream."""
    head = await _read_exactly(s, 2)
    if not head:
        raise MessageFin("the stream ended")
    if len(head) < 2:
        raise Malformed("a message cut short")
    (size,) = struct.unpack("!H", head)
    if size > MAX_MESSAGE:
        raise Malformed("a message over 4096 bytes")
    body = await _read_exactly(s, size)
    if len(body) < size:
        raise Malformed("a message cut short")
    if body.lstrip()[:1] != b"{":
        raise Malformed("a message that is not a JSON object")
    return parse_message(body)


class Quic:
    """Reaches the hub over one QUIC connection, made again when it is lost."""

    name = "QUIC"

    def __init__(self) -> None:
        self._qc: Optional[QConn] = None
        self._lock: Optional[asyncio.Lock] = None
        # Connections no request goes to any more (a 429 for the connection,
        # 13.8), still holding streams or registrations: they close once
        # they hold nothing, or at close().
        self._retired: list[QConn] = []

    # ---------------------------------------------------------- the connection

    async def _discover(self, p: spi.Params, op: str) -> Discovery:
        """Ask the hub's HTTPS endpoint where its QUIC listener is (13.2)."""
        h = [(H_VERSION, p.agent), (H_OP, op)]
        if op == OP_SERVE:
            if p.serve_token:
                h.append((H_SERVE, p.serve_token))
        else:
            h.append((H_WORD, p.word))
            if p.client_token:
                h.append((H_CLIENT_TOKEN, p.client_token))
        a = await p.get(PATH, h)
        if a.status == 404:  # a hub without QUIC does not know the endpoint
            raise StatusError(404, NO_QUIC, a.headers)
        if a.status != 200:
            raise a.refusal()
        try:
            return Discovery.parse(a.body)
        except (ValueError, UnicodeDecodeError) as e:
            raise LinkError(str(e) or "the hub's answer to QUIC discovery is not understood") from None

    async def _get(self, p: spi.Params, op: str) -> QConn:
        """The QUIC connection to the hub, made if there is none: discovery,
        then a handshake that pins the certificate, with one more discovery
        after a mismatch (13.3)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            qc = self._qc
            if qc is not None and not qc.closed:
                return qc
            self._qc = None
            for _ in range(2):
                d = await self._discover(p, op)
                try:
                    qc = await dial(d.host, d.port, d.pins())
                except PinMismatch:
                    continue
                qc.on_open = lambda s, qc=qc: self._spawn(self._take_open(qc, s))
                self._qc = qc
                return qc
            raise LinkError(PIN_MISMATCH)

    def _forget(self, qc: QConn) -> None:
        if self._qc is qc:
            self._qc = None

    def _spawn(self, coro) -> None:
        background(coro)

    def close(self) -> None:
        qc, self._qc = self._qc, None
        retired, self._retired = self._retired, []
        for c in [qc, *retired]:
            if c is not None:
                c.close(Code.NONE)

    # ---------------------------------------------------------- requests

    async def _request(
        self, p: spi.Params, op: str, req: dict, qc: Optional[QConn] = None
    ) -> tuple[QConn, QStream, Answer]:
        """Open a stream, send req, and read the hub's answer: on qc, or on the
        connection to the hub. A refusal is raised, after the stream is
        ended."""
        if qc is None:
            qc = await self._get(p, op)
        try:
            s = qc.open_stream()
        except LinkError:
            self._forget(qc)
            raise
        try:
            async def exchange() -> dict:
                await s.write(encode_message(req))
                return await read_message(s)

            async with asyncio.timeout(ANSWER_WAIT):  # not wait_for: on 3.11 it can lose a cancellation
                m = await exchange()
        except asyncio.TimeoutError:
            s.reset(Code.REQUEST_TIMEOUT)
            raise LinkError("the hub did not answer in time") from None
        except Malformed as e:
            s.reset(Code.PROTOCOL)
            raise LinkError(f"the hub did not answer ({e})") from None
        except (MessageFin, ConnectionError) as e:
            s.reset(Code.REQUEST_TIMEOUT)
            if qc.closed:
                self._forget(qc)
            raise LinkError(f"the hub did not answer ({e})") from None
        except BaseException:
            s.cancel()
            raise
        a = Answer.of(m)
        if a.status not in (200, 204):
            # A refusal, a 426 included, whatever its proto says (13.4). The
            # hub sends FIN and STOP_SENDING; end this direction too.
            s.reset(Code.REFUSED)
            if a.status == 429 and a.scope == "connection":
                self._forget(qc)  # the next request opens a new connection (13.8)
                self._retired = [c for c in self._retired if not c.closed]
                self._retired.append(qc)
                qc.retire()
            raise spi.refused(a.status, a.error)
        if a.proto not in (0, PROTO):
            s.reset(Code.PROTOCOL)
            raise QuicProtoError(a.proto)
        return qc, s, a

    async def register(self, p: spi.Params, target: str) -> "QReg":
        req = request(
            "serve",
            PROTO,
            p.agent,
            p.word,
            serveToken=p.serve_token or None,
            name=p.name,
            target=target,
            clientTokenSHA256=p.client_token_sha256 or None,
        )
        qc = await self._get(p, OP_SERVE)
        qc.serves += 1  # an open may arrive before the answer (13.4)
        try:
            _, s, a = await self._request(p, OP_SERVE, req, qc)
            reg = QReg(qc, a.reg, s)
            qc.regs[a.reg] = reg
        finally:
            qc.serves -= 1
            qc.changed()
        reg.start()
        return reg

    async def connect(self, p: spi.Params) -> tuple[QStream, str]:
        req = request("connect", PROTO, p.agent, p.word, clientToken=p.client_token or None)
        _, s, a = await self._request(p, OP_CONNECT, req)
        return s, a.conn

    async def check(self, p: spi.Params) -> None:
        req = request("check", PROTO, p.agent, p.word, clientToken=p.client_token or None)
        _, s, _ = await self._request(p, OP_CONNECT, req)
        s.finish()  # the hub sends FIN after its answer
        s.close()

    # ---------------------------------------------------------- opens

    async def _take_open(self, qc: QConn, s: QStream) -> None:
        """Read the open on a stream the hub opened, and hand it to its
        registration."""
        try:
            async with asyncio.timeout(REQUEST_WAIT):  # not wait_for: on 3.11 it can lose a cancellation
                m = await read_message(s)
        except asyncio.TimeoutError:
            s.reset(Code.REQUEST_TIMEOUT)
            return
        except (Malformed, MessageFin):
            s.reset(Code.PROTOCOL)
            return
        except ConnectionError:
            s.cancel()
            return
        oid, rid = m.get("open"), m.get("reg")
        if not isinstance(oid, str) or not oid:
            s.reset(Code.PROTOCOL)
            return
        o = QOpen(s, oid)
        reg = await qc.find(rid if isinstance(rid, str) else "", REQUEST_WAIT)
        if reg is None or not reg.offer(o):
            await o.answer_and_finish(410, "no such registration")


class QReg:
    """One registration over QUIC, until its serve stream ends."""

    def __init__(self, qc: QConn, rid: str, s: QStream):
        self.qc = qc
        self.rid = rid
        self.s = s
        self.opens: asyncio.Queue[QOpen] = asyncio.Queue(OPEN_QUEUE)
        self.ended: Optional[str] = None
        # Set by an open and by the end. next() takes an open only when it
        # returns it, so a cancelled next() loses nothing.
        self._wake = asyncio.Event()
        self._closing = False
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.ensure_future(self._watch())

    def offer(self, o: "QOpen") -> bool:
        if self.ended is not None or self._closing:
            return False
        try:
            self.opens.put_nowait(o)
        except asyncio.QueueFull:
            return False
        self._wake.set()
        return True

    async def next(self) -> "QOpen":
        while True:
            if not self.opens.empty():
                return self.opens.get_nowait()
            if self.ended is not None:
                raise LinkError(self.ended)
            self._wake.clear()
            await self._wake.wait()

    def close(self) -> None:
        """Unregister: FIN on the serve stream; the hub answers with FIN."""
        if self._closing:
            return
        self._closing = True
        self.s.finish()
        asyncio.get_running_loop().call_later(DELIVER_WAIT, self._give_up)
        while not self.opens.empty():
            self.opens.get_nowait().s.cancel()

    def _give_up(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    async def _watch(self) -> None:
        """Read the serve stream until it ends: the hub's end message, its FIN,
        a lost connection, or this side unregistering."""
        s = self.s
        why = "the registration ended"
        try:
            while True:
                try:
                    m = await read_message(s)
                except MessageFin:
                    s.finish()
                    why = "unregistered" if self._closing else "the server ended the registration"
                    break
                except Malformed:
                    s.reset(Code.PROTOCOL)
                    why = "the server broke the protocol on the serve stream"
                    break
                except ConnectionError as e:
                    why = f"the link to the server was lost ({e})"
                    break
                end = m.get("end")
                if isinstance(end, str) and end:
                    s.finish()  # the hub's FIN follows; answer with ours
                    err = m.get("error")
                    why = end_reason(end, err if isinstance(err, str) else "")
                    break
                # other messages are ignored
        except asyncio.CancelledError:
            why = "unregistered"
            s.cancel()
        finally:
            s.close()
            if self.qc.regs.get(self.rid) is self:
                del self.qc.regs[self.rid]
            self.qc.changed()
            while not self.opens.empty():
                self.opens.get_nowait().s.cancel()
            self.ended = why
            self._wake.set()
            self.qc.close_if_idle()


class QOpen:
    """The hub asking for one connection, on a stream it opened."""

    def __init__(self, s: QStream, oid: str):
        self.s = s
        self._id = oid

    @property
    def id(self) -> str:
        return self._id

    async def _answer(self, status: int, error: str = "") -> None:
        msg: dict = {"status": status}
        if error:
            msg["error"] = error
        async with asyncio.timeout(WRITE_WAIT):  # not wait_for: on 3.11 it can lose a cancellation
            await self.s.write(encode_message(msg))

    async def accept(self) -> QStream:
        try:
            await self._answer(200)
        except (ConnectionError, asyncio.TimeoutError) as e:
            self.s.reset(Code.BROKEN)
            raise LinkError(f"cannot answer the server ({e or 'it took too long'})") from None
        except BaseException:
            self.s.cancel()
            raise
        return self.s

    async def refuse(self, reason: str) -> None:
        await self.answer_and_finish(502, clean_text(reason, 128) or "the serving side refused the connection")

    async def answer_and_finish(self, status: int, error: str) -> None:
        """Refuse: the answer, then FIN (13.5)."""
        try:
            await self._answer(status, error)
        except (ConnectionError, asyncio.TimeoutError):
            self.s.cancel()
            return
        except BaseException:
            self.s.cancel()
            raise
        self.s.finish()
        self.s.close()
