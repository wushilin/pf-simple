"""Streams: one TCP connection's bytes over one WebSocket (PROTOCOL.md 8)."""

from __future__ import annotations

import asyncio
import collections
import inspect
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, Union

from . import _ws
from ._proto import ClosedError, ConnID, DroppedError, LinkError, RemoteError, Side, clean_reason
from ._ws import OP_BINARY, OP_CLOSE, OP_CONT, OP_TEXT, FrameError, PeerClosedError, WebSocket

CHUNK_SIZE = 64 * 1024  # the most a sender puts in one frame
MAX_DATA_FRAME = 1 << 20  # the most a receiver accepts in one frame
MAX_TEXT_FRAME = 1024
_INBOX_LIMIT = 1 << 20  # bytes read ahead of the application

_EOF = b"eof"
_ERR = b"err:"
# Protocol 2 (PROTOCOL.md 12): the text frames on a leg offered reuse.
MSG_IDLE = b"idle"
MSG_BIND = b"bind"
MSG_BOUND = b"bound"

log = logging.getLogger("pfrelay")


async def emit(handler: Optional[Callable[..., Any]], *args: Any) -> None:
    """Call an event handler, awaiting it if it is a coroutine function. A
    handler that raises is logged, never passed on."""
    if handler is None:
        return
    try:
        result = handler(*args)
        if inspect.isawaitable(result):
            await result
    except Exception:  # an application's handler must not break the SDK
        log.exception("pfrelay event handler %r failed", handler)


class _Owner(Protocol):
    async def _conn_closed(self, conn: "Conn", err: Optional[BaseException]) -> None: ...


@dataclass(frozen=True)
class ConnInfo:
    """A snapshot of one connection."""

    id: ConnID  # the hub's id, the same on both ends
    side: Side
    opened: float  # time.time() when it was opened
    sent: int  # bytes sent into the tunnel
    received: int  # bytes received from the tunnel
    wrote_eof: bool  # this end has half-closed
    read_eof: bool  # the far end has half-closed


@dataclass(frozen=True)
class Stats:
    """A client's connections, open and closed, since it was made."""

    opened: int
    active: int
    failed: int
    sent: int
    received: int


class _Registry:
    def __init__(self) -> None:
        self.live: dict[int, "Conn"] = {}
        self.opened = 0
        self.failed = 0
        self.sent = 0
        self.received = 0

    def add(self, conn: "Conn") -> None:
        self.live[id(conn)] = conn
        self.opened += 1

    def finish(self, conn: "Conn", failed: bool) -> bool:
        """Move conn out of the live set; False if it already was."""
        if self.live.pop(id(conn), None) is None:
            return False
        if failed:
            self.failed += 1
        self.sent += conn._sent
        self.received += conn._received
        return True

    def find(self, cid: ConnID, side: Optional[Side] = None) -> Optional["Conn"]:
        """The live connection cid, on side if given; the oldest first."""
        for c in self.live.values():
            if c.id == cid and (side is None or c.side is side):
                return c
        return None

    def stats(self) -> Stats:
        sent, received = self.sent, self.received
        for c in self.live.values():
            sent += c._sent
            received += c._received
        return Stats(self.opened, len(self.live), self.failed, sent, received)

    def conns(self) -> list[ConnInfo]:
        return sorted((c.info() for c in self.live.values()), key=lambda i: i.opened)


class _Inbox:
    """What the reader has received and the application has not read yet,
    bounded so that an application that stops reading stops the far end."""

    def __init__(self, limit: int) -> None:
        self.items: collections.deque[bytes] = collections.deque()
        self.size = 0
        self.limit = limit
        self.end: Optional[BaseException] = None  # set once: what follows the data
        self.ended = False
        self.closed = False
        self.readable = asyncio.Event()
        self.writable = asyncio.Event()
        self.writable.set()

    async def put(self, data: bytes) -> None:
        while self.size >= self.limit and not self.closed:
            self.writable.clear()
            await self.writable.wait()
        if self.closed:
            return
        self.items.append(data)
        self.size += len(data)
        self.readable.set()

    def finish(self, end: Optional[BaseException]) -> None:
        """No more data: a clean half-close (None) or a failure."""
        if not self.ended:
            self.ended, self.end = True, end
            self.readable.set()

    def close(self) -> None:
        self.closed = True
        self.readable.set()
        self.writable.set()


class Conn:
    """One connection through a tunnel.

    read() returns b"" once the far end has half-closed, and raises
    RemoteError when the far end or the hub dropped the connection, with
    their reason, or LinkError when the link to the hub broke.
    """

    _PING_EVERY = 10.0
    _SILENCE = 30.0

    def __init__(
        self,
        ws: WebSocket,
        conn_id: Union[ConnID, str],
        side: Side,
        owner: Optional[_Owner] = None,
        *,
        reusable: bool = False,
        finisher: Optional[Callable[["Conn"], Any]] = None,
    ):
        self._ws = ws
        self._id = conn_id if isinstance(conn_id, ConnID) else ConnID(conn_id)
        self._side = Side(side)
        self._owner = owner
        self._opened = time.time()
        self._sent = 0
        self._received = 0
        self._inbox = _Inbox(_INBOX_LIMIT)
        self._pending = b""
        self._rlock = asyncio.Lock()
        self._wlock = asyncio.Lock()
        self._read_eof = False  # the far end's eof has arrived
        self._wrote_eof = False
        self._failure: Optional[BaseException] = None  # what broke reading
        self._gone_reason = ""  # err: that arrived after eof
        self._gone = asyncio.Event()  # the WebSocket has ended
        self._closing = False  # close or fail has begun: errors are ours
        self._failed = False
        self._broke: Optional[BaseException] = None  # the first error that broke it here
        self._close_sent = False
        self._done = False
        self._final: Optional[BaseException] = None  # why it ended, once it has
        self._dropping = False  # Client.drop has begun to fail it
        self._drop_reason: Optional[str] = None
        # Protocol 2: the leg was offered reuse; the hub's verdict after a
        # clean finish (PROTOCOL.md 12.5).
        self._reusable = reusable
        self._finisher = finisher  # async (conn) -> error the verdict reports
        self._idled = False  # the hub's valid "idle" arrived; the reader stopped
        self._detached = False  # the leg went on to its next connection
        self._verdict = asyncio.Event()  # idle, an err: after eof, or the end
        ws.start_keepalive(self._PING_EVERY, self._SILENCE)
        self._reader = asyncio.ensure_future(self._pump())

    # ---------------------------------------------------------- facts

    @property
    def id(self) -> ConnID:
        """The hub's id for this connection."""
        return self._id

    @property
    def side(self) -> Side:
        return self._side

    @property
    def headers(self):
        """The hub's handshake answer."""
        return self._ws.headers

    @property
    def err(self) -> Optional[BaseException]:
        """Why the connection failed, once that is known: the far end's or
        the hub's reason (RemoteError) or a lost link (LinkError). None while
        it is fine, or after a clean finish.

        It can say more than read() did: the hub may pass a failure of the
        far end on as a half-close first, so read() returns b"" and the
        reason arrives just after it."""
        if self._failure is not None:
            return self._failure
        if self._gone_reason:
            return RemoteError(self._gone_reason)
        return None

    def info(self) -> ConnInfo:
        return ConnInfo(
            self._id, self._side, self._opened, self._sent, self._received, self._wrote_eof, self._read_eof
        )

    async def wait_closed(self) -> None:
        """Wait until the WebSocket under this connection has ended."""
        await self._gone.wait()

    # ---------------------------------------------------------- reading

    async def _pump(self) -> None:
        ws = self._ws
        inbox = self._inbox
        try:
            while True:
                op, fin, payload = await ws.recv(MAX_DATA_FRAME, MAX_TEXT_FRAME)
                if op in (OP_BINARY, OP_CONT):
                    if self._read_eof:
                        raise FrameError("data after the far end's half-close")
                    if payload:
                        await inbox.put(payload)
                elif op == OP_TEXT:
                    if not fin:
                        raise FrameError("fragmented text frame")
                    if payload == _EOF:
                        if self._read_eof and self._reusable:
                            raise FrameError("a second eof")
                        if not self._read_eof:
                            self._read_eof = True
                            inbox.finish(None)
                    elif self._reusable and payload == MSG_IDLE:
                        if self._close_sent:
                            continue  # it crossed our close: ignored (12.5)
                        if not (self._read_eof and self._wrote_eof) or self._failure is not None:
                            raise FrameError("idle in the wrong state")  # a violation (12.4)
                        self._idled = True
                        return  # the leg goes on; nothing here reads it any more
                    elif self._reusable and (payload == MSG_BIND or payload.startswith(MSG_BIND + b" ")
                                             or payload == MSG_BOUND or payload.startswith(MSG_BOUND + b" ")):
                        raise FrameError("bind or bound on a carrying leg")  # a violation (12.4)
                    elif payload.startswith(_ERR):
                        reason = clean_reason(payload[len(_ERR):].decode("utf-8", "replace"))
                        if self._read_eof or inbox.ended:
                            if not self._gone_reason and self._failure is None:
                                self._gone_reason = reason or "the far end dropped the connection"
                                self._verdict.set()
                        elif not self._closing:
                            self._failure = RemoteError(reason)
                            inbox.finish(self._failure)
                    # any other text frame is ignored
                elif op == OP_CLOSE:
                    if not self._read_eof and not self._closing and self._failure is None and not inbox.ended:
                        self._failure = PeerClosedError("the server closed the connection")
                        inbox.finish(self._failure)
                    await self._send_close()
                    ws.close_transport()
                    return
                # pings are not answered on streams; pongs are ignored
        except asyncio.CancelledError:
            pass
        except Exception as e:  # the link broke, or the framing did
            if not self._closing and not self._read_eof and self._failure is None and not inbox.ended:
                err = e if isinstance(e, LinkError) else LinkError(str(e))
                self._failure = err
                inbox.finish(err)
            ws.abort()
        finally:
            inbox.finish(LinkError("the connection is closed"))
            ws.stop_keepalive()
            self._verdict.set()
            if not self._idled:  # after idle the leg lives on; _end marks the end
                self._gone.set()

    async def read(self, n: int = CHUNK_SIZE) -> bytes:
        """Up to n bytes of the stream; b"" after the far end's half-close."""
        if n <= 0:
            return b""
        async with self._rlock:
            inbox = self._inbox
            while not self._pending:
                if inbox.items:
                    self._pending = inbox.items.popleft()
                    inbox.size -= len(self._pending)
                    inbox.writable.set()
                    break
                if inbox.closed:
                    raise ClosedError("the connection is closed")
                if inbox.ended:
                    if inbox.end is None:
                        return b""
                    self._break(inbox.end)
                    raise inbox.end
                inbox.readable.clear()
                await inbox.readable.wait()
            out, self._pending = self._pending[:n], self._pending[n:]
            self._received += len(out)
            return out

    async def readexactly(self, n: int) -> bytes:
        """Exactly n bytes; asyncio.IncompleteReadError if the stream ends
        first."""
        buf = bytearray()
        while len(buf) < n:
            chunk = await self.read(n - len(buf))
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(buf), n)
            buf += chunk
        return bytes(buf)

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        chunk = await self.read()
        if not chunk:
            raise StopAsyncIteration
        return chunk

    # ---------------------------------------------------------- writing

    async def write(self, data: bytes) -> None:
        """Send data, in frames of at most 64 KiB. It waits while the link
        is full."""
        data = bytes(data)
        async with self._wlock:
            if self._done or self._closing:
                raise ClosedError("the connection is closed")
            if self._wrote_eof:
                raise ClosedError("this end has half-closed: nothing more may be written")
            try:
                for off in range(0, max(len(data), 1), CHUNK_SIZE):
                    piece = data[off:off + CHUNK_SIZE]
                    if not piece:
                        break
                    await self._ws.send(OP_BINARY, piece)
                    self._sent += len(piece)
            except (ConnectionError, OSError) as e:
                err = e if isinstance(e, LinkError) else LinkError(f"the connection to the server was lost ({e})")
                self._break(err)
                raise err from None

    async def close_write(self) -> None:
        """Half-close: the far end reads b"" after what was written so far,
        and may go on sending."""
        async with self._wlock:
            if self._wrote_eof:
                return
            self._wrote_eof = True
            try:
                await self._ws.send(OP_TEXT, _EOF)
            except (ConnectionError, OSError) as e:
                err = e if isinstance(e, LinkError) else LinkError(f"the connection to the server was lost ({e})")
                self._break(err)
                raise err from None

    # ---------------------------------------------------------- the end

    async def _send_close(self) -> None:
        if self._close_sent:
            return
        self._close_sent = True
        try:
            await self._ws.send(OP_CLOSE, b"", timeout=_ws.CLOSE_TIMEOUT)
        except (ConnectionError, OSError):
            pass

    def _break(self, err: BaseException) -> None:
        self._failed = True
        if self._broke is None:
            self._broke = err

    async def fail(self, reason: str) -> None:
        """Drop the connection and tell the far end why: its read raises a
        RemoteError with this reason. The connection ends with a
        DroppedError."""
        await self._fail(reason, DroppedError(reason))

    async def _fail(self, reason: str, err: BaseException) -> None:
        if self._done or self._detached:
            return
        self._done = self._closing = True
        self._break(err)
        reason = "".join(c for c in reason if c.isprintable()) or "the connection was dropped"
        payload = (_ERR + reason.encode("utf-8"))[:MAX_TEXT_FRAME]
        payload = payload.decode("utf-8", "ignore").encode("utf-8")
        try:
            await self._ws.send(OP_TEXT, payload, timeout=_ws.CLOSE_TIMEOUT)
            await self._send_close()
        except (ConnectionError, OSError):
            pass
        self._ws.close_transport()
        await self._end(self._broke)

    async def close(self) -> Optional[BaseException]:
        """End the connection. If this end has not half-closed, it does so
        first. When both ends had half-closed the close is clean; otherwise
        the far end sees the connection cut.

        On a leg offered reuse (protocol 2), a clean finish waits up to 3
        seconds for the hub's verdict before the connection is reported
        closed. Returns why it ended, or None after a clean finish."""
        if self._done:
            return self._final
        if self._drop_reason is not None:
            # Dropped: it fails, however the application then ends it.
            await self._fail(self._drop_reason, DroppedError(self._drop_reason))
            return self._final
        if not self._wrote_eof and not self._failed and not self._gone.is_set():
            try:
                await self.close_write()
            except (ConnectionError, OSError, ClosedError):
                pass
        if self._done:
            return self._final
        self._done = self._closing = True
        verdict_err: Optional[BaseException] = None
        ended = False
        try:
            if self._finisher is not None and self._clean():
                try:
                    verdict_err = await self._finisher(self)  # the hub's verdict; the leg kept if it may be
                except Exception as e:  # never leave a connection unreported
                    log.exception("pfrelay: ending a reusable leg failed")
                    verdict_err = e
                    if not self._detached:
                        self._ws.abort()
            else:
                await self._close_stream()
            if self._broke is not None:
                err = self._broke
            elif verdict_err is not None:
                err = verdict_err
            else:
                err = self.err
            ended = True
            await self._end(err)
            return err
        finally:
            if not ended:  # cancelled on the way: the leg still closes, the close is still reported
                if not self._detached:
                    self._ws.abort()
                await self._end(self._broke if self._broke is not None else self.err)

    def _clean(self) -> bool:
        """Finished cleanly so far: both half-closes, nothing failed."""
        return (
            self._reusable
            and self._read_eof
            and self._wrote_eof
            and self._failure is None
            and not self._failed
            and not self._dropping
        )

    async def _close_stream(self) -> None:
        """End the stream as protocol 1 does (PROTOCOL.md 8.4)."""
        if self._detached:
            return
        if self._idled:
            # Nothing reads the leg any more: a close reply would never be
            # seen, so do not wait for one (12.5).
            await self._send_close()
            self._ws.close_transport()
        elif self._read_eof and self._wrote_eof and not self._gone.is_set():
            await self._send_close()
            try:
                await asyncio.wait_for(self._gone.wait(), _ws.CLOSE_TIMEOUT)
            except asyncio.TimeoutError:
                pass
            self._ws.close_transport()
        elif self._gone.is_set():
            self._ws.close_transport()
        else:
            self._ws.abort()

    async def _await_verdict(self, timeout: float) -> tuple[bool, str]:
        """After both half-closes, wait for the hub's verdict (12.5): (True,
        "") on its "idle"; (False, reason) when it failed the connection;
        (False, "") when it closed, or said nothing in time."""
        try:
            await asyncio.wait_for(self._verdict.wait(), timeout)
        except asyncio.TimeoutError:
            return False, ""
        if self._idled:
            return True, ""
        return False, self._gone_reason

    def _detach(self) -> WebSocket:
        """Hand the leg on, after the hub's "idle": this connection lets go
        of it without closing it."""
        self._detached = True
        self._ws.stop_keepalive()
        return self._ws

    async def _close_with(self, err: Optional[BaseException]) -> Optional[BaseException]:
        """close(), recording err as why the connection ended."""
        if err is not None:
            self._break(err)
        return await self.close()

    async def _end(self, err: Optional[BaseException]) -> None:
        if self._drop_reason is not None:
            err = DroppedError(self._drop_reason)  # dropped is failed, whatever came after
        self._final = err
        self._gone.set()  # for wait_closed, also when the leg went on (idle)
        self._inbox.close()
        if not self._detached:
            self._ws.stop_keepalive()
        if self._owner is not None:
            await self._owner._conn_closed(self, err)

    async def __aenter__(self) -> "Conn":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if exc is not None and not isinstance(exc, (RemoteError, LinkError)):
            await self.fail(f"the application failed ({type(exc).__name__})")
        else:
            await self.close()

    def __repr__(self) -> str:
        return f"<pfrelay.Conn {self._id.short} {self._side}>"
