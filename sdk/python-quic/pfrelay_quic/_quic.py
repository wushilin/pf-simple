"""One QUIC connection to the hub on aioquic, and its streams (PROTOCOL.md
13.3, 13.5, 13.6).

aioquic leaves several of protocol 3's rules to the application, so they are
kept here:

- the certificate is pinned after the handshake, before any stream is
  opened (13.3), with aioquic's own chain check off; it still verifies the
  handshake's signature with the presented certificate's key;
- a PING goes out after KEEP_ALIVE without hearing anything (13.6), since
  aioquic has no keepalive of its own;
- a stream's receive credit follows what the application has read, not
  what has arrived, so a stalled reader holds up only its own stream
  (13.3); aioquic 1.8 is the first to grant credit by what was delivered
  rather than by what arrived, which this refines;
- a write waits while too much of the stream is unacknowledged, since
  aioquic buffers whatever it is given.
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import ipaddress
import logging
import socket
import ssl
from typing import Any, Callable, Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicErrorCode, QuicProtocolVersion
from cryptography.hazmat.primitives.serialization import Encoding

from pfrelay import LinkError, StatusError

from ._wire import ALPN, Code

log = logging.getLogger("pfrelay")

IDLE_TIMEOUT = 30.0  # the transport parameter max_idle_timeout (13.6)
KEEP_ALIVE = 10.0  # a PING after this long without hearing anything (13.6)
_KEEP_ALIVE_TICK = 0.5
MAX_STREAMS = 1000  # the bidirectional streams this end allows the hub (13.3)
# Each stream's receive window, to start with; aioquic lets it grow to 16
# times this while the application keeps up.
STREAM_WINDOW = 128 * 1024
CONN_WINDOW = 16 << 20  # the connection's receive window (13.3)
SEND_BUFFER = 256 * 1024  # unacknowledged bytes a stream holds before a write waits
DELIVER_WAIT = 3.0  # how long an end keeps a stream after its FIN (13.5)
HANDSHAKE_WAIT = 10.0

NO_QUIC_V1 = "the hub's QUIC listener does not speak QUIC version 1"
REFUSED = "the hub refused the QUIC connection; trying again later"


_background: set[asyncio.Future] = set()


def background(coro) -> None:
    """Run coro in a task of its own, kept until it is done."""
    t = asyncio.ensure_future(coro)
    _background.add(t)
    t.add_done_callback(_background.discard)


def fingerprint(der: bytes) -> str:
    """The lowercase hex SHA-256 of a certificate's DER encoding."""
    return hashlib.sha256(der).hexdigest()


def unreachable(why: str) -> LinkError:
    return LinkError(
        "cannot reach the hub over QUIC (UDP may be blocked on the way; "
        f"pf-client over WebSocket works where QUIC does not): {why}"
    )


class PinMismatch(Exception):
    """The hub presented a certificate that discovery did not announce."""


class _Connection(QuicConnection):
    """aioquic's connection, with each stream's receive credit following
    what the application has read: pf_held counts, per stream, what has
    arrived and not been read yet."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pf_held: dict[int, int] = {}

    def _write_stream_limits(self, builder, space, stream) -> None:  # type: ignore[override]
        held = self.pf_held.get(stream.stream_id, 0)
        if held <= 0:
            return super()._write_stream_limits(builder, space, stream)
        r = stream.receiver
        read = r.starting_offset() - held
        r.starting_offset = lambda: read  # what was read, not what arrived
        try:
            return super()._write_stream_limits(builder, space, stream)
        finally:
            del r.starting_offset


class _Protocol(QuicConnectionProtocol):
    def __init__(self, quic: QuicConnection, qc: "QConn"):
        super().__init__(quic)
        self._qc = qc

    def datagram_received(self, data, addr) -> None:
        self._qc.last_rx = self._loop.time()
        super().datagram_received(data, addr)
        self._qc.progress()

    def quic_event_received(self, event: events.QuicEvent) -> None:
        self._qc.event(event)


class QConn:
    """One QUIC connection to the hub."""

    def __init__(self, quic: QuicConnection):
        self.quic = quic
        # What has arrived and not been read, per stream: the credit of a
        # _Connection follows it.
        self.held: dict[int, int] = getattr(quic, "pf_held", {})
        # The streams the peer opens: the hub's are odd for a client.
        self._peer_kind = 1 if quic.configuration.is_client else 0
        self.loop = asyncio.get_running_loop()
        self.proto: Optional[_Protocol] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.streams: dict[int, QStream] = {}
        self.closed = False
        self.close_code: Optional[int] = None
        self.close_reason = ""
        self.last_rx = self.loop.time()
        self._last_ping = 0.0
        # The peer's streams this end has let go of while aioquic still
        # knows them: what still arrives on them is not a new stream.
        # Streams are not ordered with one another, so a newer id may come
        # first (13.4).
        self._let_go: set[int] = set()
        self._progress: Optional[asyncio.Future] = None
        self._keep: Optional[asyncio.Task] = None
        self._retired = False
        # Set by the transport: a stream the hub opened, and the end.
        self.on_open: Callable[["QStream"], None] = lambda s: s.cancel()
        self.on_lost: Callable[[str], None] = lambda why: None
        # Registrations, and serve requests not yet answered (13.4).
        self.regs: dict[str, Any] = {}
        self.serves = 0
        self._changed = asyncio.Event()

    # ---------------------------------------------------------- events

    def event(self, ev: events.QuicEvent) -> None:
        if isinstance(ev, events.StreamDataReceived):
            s = self.streams.get(ev.stream_id)
            if s is None:
                sid = ev.stream_id
                if sid % 4 != self._peer_kind or sid in self._let_go or self.closed:
                    return  # not the peer's, or already let go of
                s = QStream(self, sid)
                self.streams[sid] = s
                s.data(ev.data, ev.end_stream)
                self.on_open(s)
                return
            s.data(ev.data, ev.end_stream)
        elif isinstance(ev, events.StreamReset):
            s = self.streams.get(ev.stream_id)
            if s is not None:
                s.peer_reset(ev.error_code)
        elif isinstance(ev, events.StopSendingReceived):
            s = self.streams.get(ev.stream_id)
            if s is not None:
                s.peer_stopped(ev.error_code)  # aioquic has answered it with RESET_STREAM
        elif isinstance(ev, events.ConnectionTerminated):
            self._terminated(ev.error_code, ev.reason_phrase)

    def _terminated(self, code: int, reason: str) -> None:
        if self.closed:
            return
        self.closed = True
        self.close_code, self.close_reason = code, reason
        why = f"the QUIC connection to the hub was lost ({reason or code})"
        for s in list(self.streams.values()):
            s.lost(why)
        self.progress()
        if self._keep is not None:
            self._keep.cancel()
        if self.transport is not None:
            self.loop.call_soon(self.transport.close)
        self.on_lost(why)

    def progress(self) -> None:
        """Something arrived: acknowledgements or credit, for writers that
        wait."""
        f, self._progress = self._progress, None
        if f is not None and not f.done():
            f.set_result(None)

    async def wait_progress(self) -> None:
        if self.closed:
            return
        if self._progress is None:
            self._progress = self.loop.create_future()
        await asyncio.shield(self._progress)

    def changed(self) -> None:
        """Registrations or outstanding serves changed."""
        ev, self._changed = self._changed, asyncio.Event()
        ev.set()

    async def find(self, reg: str, wait: float) -> Any:
        """The registration reg names. An open can arrive before the answer to
        its serve, streams not being ordered with one another, so it waits
        while serves are outstanding, up to wait (13.4)."""
        deadline = self.loop.time() + wait
        while True:
            r = self.regs.get(reg)
            if r is not None:
                return r
            left = deadline - self.loop.time()
            if self.serves == 0 or left <= 0 or self.closed:
                return None
            try:
                await asyncio.wait_for(self._changed.wait(), left)
            except asyncio.TimeoutError:
                return None

    # ---------------------------------------------------------- sending

    def transmit(self) -> None:
        if self.proto is not None and not self.closed:
            self.proto.transmit()

    def transmit_soon(self) -> None:
        if self.proto is not None and not self.closed:
            self.proto._transmit_soon()

    def open_stream(self) -> "QStream":
        if self.closed:
            raise LinkError(f"the QUIC connection to the hub was lost ({self.close_reason or self.close_code})")
        sid = self.quic.get_next_available_stream_id()
        s = QStream(self, sid)
        self.streams[sid] = s
        return s

    def forget(self, s: "QStream") -> None:
        if self.streams.get(s.id) is s:
            del self.streams[s.id]
            if s.id % 4 == self._peer_kind:
                self._let_go.add(s.id)
                if len(self._let_go) > 256:  # what aioquic has discarded, it ignores itself
                    self._let_go = {i for i in self._let_go if i in self.quic._streams}
        self.held.pop(s.id, None)
        if self._retired and not self.streams and not self.regs:
            self.close(Code.NONE)

    def retire(self) -> None:
        """No new requests go here (a 429 for this connection, 13.8): close it
        once it holds nothing."""
        self._retired = True
        if not self.streams and not self.regs:
            self.close(Code.NONE)

    def close(self, code: int = Code.NONE, reason: str = "") -> None:
        """Close the connection: CONNECTION_CLOSE goes out at once, then the
        socket is let go of."""
        if self.closed or self.proto is None:
            return
        self.proto.close(error_code=code, reason_phrase=reason)
        self._terminated(code, "closed by this side")

    # ---------------------------------------------------------- keepalive

    def start_keepalive(self) -> None:
        self._keep = asyncio.ensure_future(self._keepalive())

    async def _keepalive(self) -> None:
        """A PING after KEEP_ALIVE in which nothing arrived (13.6)."""
        n = 0
        try:
            while not self.closed:
                await asyncio.sleep(_KEEP_ALIVE_TICK)
                now = self.loop.time()
                if now - max(self.last_rx, self._last_ping) >= KEEP_ALIVE - _KEEP_ALIVE_TICK:
                    n += 1
                    self._last_ping = now
                    self.quic.send_ping(n)
                    self.transmit()
        except asyncio.CancelledError:
            pass


class QStream:
    """One bidirectional QUIC stream, as pfrelay.transport.Stream: bytes both
    ways, FIN on finish, and every stream driven to its end in both
    directions (13.5)."""

    def __init__(self, qc: QConn, sid: int):
        self.qc = qc
        self.id = sid
        self._buf: collections.deque[bytes] = collections.deque()
        self._held = 0
        self._fin = False  # the peer's FIN arrived
        self._read_err: Optional[str] = None  # the peer reset, or the link was lost
        self._write_err: Optional[str] = None  # the peer stopped reading, or the stream was reset
        self._finished = False  # this end sent FIN
        self._stopped = False  # this end stopped reading
        self._readable = asyncio.Event()
        self._peer_done = asyncio.Event()  # the peer ended its direction
        self._let_go = False

    # ---------------------------------------------------------- from QConn

    def data(self, data: bytes, end: bool) -> None:
        if data and not self._stopped:
            self._buf.append(data)
            self._held += len(data)
            self.qc.held[self.id] = self._held
        if end:
            self._fin = True
            self._peer_done.set()
        self._readable.set()

    def peer_reset(self, code: int) -> None:
        if self._read_err is None:
            self._read_err = f"the peer reset the stream (code {code})"
        self._peer_done.set()
        self._readable.set()

    def peer_stopped(self, code: int) -> None:
        if self._write_err is None:
            self._write_err = f"the peer stopped reading the stream (code {code})"
        self.qc.progress()

    def lost(self, why: str) -> None:
        if self._read_err is None:
            self._read_err = why
        if self._write_err is None:
            self._write_err = why
        self._peer_done.set()
        self._readable.set()

    # ---------------------------------------------------------- reading

    async def read(self, n: int = 65536) -> bytes:
        while not self._buf:
            if self._stopped:
                raise ConnectionResetError("the stream was reset")
            if self._read_err is not None:
                raise ConnectionResetError(self._read_err)
            if self._fin:
                return b""
            self._readable.clear()
            await self._readable.wait()
        chunk = self._buf[0]
        if len(chunk) <= n:
            self._buf.popleft()
            out = chunk
        else:
            out, self._buf[0] = chunk[:n], chunk[n:]
        self._held -= len(out)
        if self._held > 0:
            self.qc.held[self.id] = self._held
        else:
            self.qc.held.pop(self.id, None)
        self.qc.transmit_soon()  # credit for what was read
        return out

    # ---------------------------------------------------------- writing

    def _unacked(self) -> int:
        st = self.qc.quic._streams.get(self.id)
        if st is None:
            return 0
        snd = st.sender
        return getattr(snd, "_buffer_stop", 0) - getattr(snd, "_buffer_start", 0)

    async def write(self, data: bytes) -> None:
        if self._write_err is not None:
            raise ConnectionResetError(self._write_err)
        if self._finished:
            raise ConnectionResetError("this end has finished the stream")
        try:
            self.qc.quic.send_stream_data(self.id, bytes(data))
        except Exception as e:  # the stream's state forbids it
            raise ConnectionResetError(f"the stream cannot be written ({e})") from None
        self.qc.transmit()
        while self._unacked() > SEND_BUFFER:
            if self._write_err is not None:
                raise ConnectionResetError(self._write_err)
            if self.qc.closed:
                raise ConnectionResetError(self._write_err or "the QUIC connection to the hub was lost")
            await self.qc.wait_progress()
        if self._write_err is not None:
            raise ConnectionResetError(self._write_err)

    def finish(self) -> None:
        """Send FIN."""
        if self._finished:
            return
        self._finished = True
        if self._write_err is None and not self.qc.closed:
            try:
                self.qc.quic.send_stream_data(self.id, b"", end_stream=True)
            except Exception:
                pass
            self.qc.transmit()

    # ---------------------------------------------------------- ending

    def reset_write(self, code: int) -> None:
        """End this direction with RESET_STREAM."""
        if self._write_err is None:
            self._write_err = "the stream was reset"
        if not self.qc.closed:
            try:
                self.qc.quic.reset_stream(self.id, code)
            except Exception:
                pass
            self.qc.transmit()

    def stop_read(self, code: int) -> None:
        """End the other direction with STOP_SENDING, unless the peer has
        ended it."""
        if not self._stopped:
            self._stopped = True
            self._buf.clear()
            self._held = 0
            self.qc.held.pop(self.id, None)
            self._readable.set()
        if not self._peer_done.is_set() and not self.qc.closed:
            try:
                self.qc.quic.stop_stream(self.id, code)
            except Exception:
                pass
            self.qc.transmit()

    def reset(self, code: int) -> None:
        """Reset the stream: RESET_STREAM for this direction and STOP_SENDING
        for the other, both with code (13.5)."""
        if not self._finished:
            self.reset_write(code)
        self.stop_read(code)
        self._forget()

    def cancel(self) -> None:
        self.reset(Code.CANCELLED)

    def broken(self) -> None:
        self.reset(Code.PROTOCOL)

    def close(self) -> None:
        """After FIN: keep reading (and discarding) until the peer ends its
        direction, for at most DELIVER_WAIT, then stop reading. Without FIN:
        reset both directions (cancelled)."""
        if self._let_go:
            return
        if not self._finished:
            self.cancel()
            return
        self._let_go = True
        self._buf.clear()
        self._held = 0
        self.qc.held.pop(self.id, None)
        self._stopped = True  # discard what still comes
        self.qc.transmit_soon()
        if self._peer_done.is_set():
            self._forget()
            return
        background(self._linger())

    async def _linger(self) -> None:
        try:
            await asyncio.wait_for(self._peer_done.wait(), DELIVER_WAIT)
        except asyncio.TimeoutError:
            if not self.qc.closed:
                try:
                    self.qc.quic.stop_stream(self.id, Code.CANCELLED)
                except Exception:
                    pass
                self.qc.transmit()
        finally:
            self._forget()

    def _forget(self) -> None:
        self._let_go = True
        self.qc.forget(self)


async def dial(host: str, port: int, pins: set[bytes]) -> QConn:
    """A QUIC connection to the hub's listener, its certificate pinned:
    QUIC version 1, ALPN pf-tunnel, no 0-RTT and no resumption (13.3).
    Raises PinMismatch when the certificate is not one of pins."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except OSError as e:
        raise unreachable(str(e)) from None
    if not infos:
        raise unreachable(f"{host} has no address")
    family, _, _, _, addr = infos[0]
    try:
        ipaddress.ip_address(host)
        sni: Optional[str] = None  # no SNI for an IP address (RFC 6066 3)
    except ValueError:
        sni = host
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=[ALPN],
        idle_timeout=IDLE_TIMEOUT,
        max_data=CONN_WINDOW,
        max_stream_data=STREAM_WINDOW,
        supported_versions=[QuicProtocolVersion.VERSION_1],
        # The chain, the name and the dates are not checked: the pin is
        # (below). The handshake's signature still is.
        verify_mode=ssl.CERT_NONE,
        server_name=sni,
    )
    quic = _Connection(configuration=cfg)
    # 1000 bidirectional streams for the hub, and no unidirectional ones
    # (13.3); they go out in the transport parameters.
    quic._local_max_streams_bidi.value = quic._local_max_streams_bidi.sent = MAX_STREAMS
    quic._local_max_streams_uni.value = quic._local_max_streams_uni.sent = 0
    qc = QConn(quic)
    local = ("::", 0) if family == socket.AF_INET6 else ("0.0.0.0", 0)
    try:
        transport, proto = await loop.create_datagram_endpoint(lambda: _Protocol(quic, qc), local_addr=local)
    except OSError as e:
        raise unreachable(str(e)) from None
    qc.transport, qc.proto = transport, proto  # type: ignore[assignment]
    ok = False
    try:
        proto.connect(addr)
        try:
            await asyncio.wait_for(proto.wait_connected(), HANDSHAKE_WAIT)
        except asyncio.TimeoutError:
            raise unreachable("the handshake timed out") from None
        except ConnectionError:
            raise _handshake_error(qc) from None
        leaf = _peer_leaf(quic)
        if leaf is None or hashlib.sha256(leaf.public_bytes(Encoding.DER)).digest() not in pins:
            raise PinMismatch()
        ok = True
    finally:
        if not ok:
            qc.close(Code.NONE)
            transport.close()
    qc.start_keepalive()
    return qc


def _peer_leaf(quic: QuicConnection) -> Any:
    """The certificate the hub presented: its leaf."""
    tls = quic.tls
    if tls is None:
        return None
    certs = tls.peer_certificates
    return certs[0] if certs else None


def _handshake_error(qc: QConn) -> Exception:
    """Words a failed handshake."""
    reason = qc.close_reason or ""
    if qc.close_code == QuicErrorCode.CONNECTION_REFUSED:
        return StatusError(429, REFUSED)  # retried later, as a 429 (13.7)
    if "version" in reason.lower():
        return LinkError(NO_QUIC_V1)
    return unreachable(reason or "the handshake failed")
