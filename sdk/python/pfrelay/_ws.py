"""A minimal HTTP/1.1 and RFC 6455 WebSocket client over asyncio and ssl.

The hub's answers carry what the protocol needs in the handshake response
(X-PF-Tunnel-Proto, X-PF-Tunnel-Conn) and in the status and JSON body of a
refusal, so the handshake is done here by hand. Only what the tunnel
protocol uses is implemented: no extensions, no subprotocols, no
fragmented sends.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import struct
from typing import Callable, Iterable, Optional

from ._proto import LinkError

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

DIAL_TIMEOUT = 10.0  # the TCP connection
HANDSHAKE_LIMIT = 15.0  # TCP, TLS and the HTTP exchange together
WRITE_TIMEOUT = 10.0  # one control frame
CLOSE_TIMEOUT = 3.0  # waiting for the far end's close

_BODY_LIMIT = 4096
_READ_PIECE = 64 * 1024


class Headers(dict):
    """Response headers, keyed by lower-case name; the first of repeats wins."""

    def get(self, name: str, default=None):  # type: ignore[override]
        return super().get(name.lower(), default)

    def __getitem__(self, name: str) -> str:
        return super().__getitem__(name.lower())

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and super().__contains__(name.lower())


class Response:
    def __init__(self, status: int, reason: str, headers: Headers, body: bytes = b""):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode("ascii") + _WS_GUID).digest()).decode("ascii")


def mask_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with the 4-byte masking key, fast enough for 64 KiB frames."""
    n = len(data)
    if n == 0:
        return b""
    pad = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "little") ^ int.from_bytes(pad, "little")).to_bytes(n, "little")


def encode_frame(op: int, payload: bytes, *, mask: bool = True, fin: bool = True) -> bytes:
    """One frame as a client (mask=True) or a server (mask=False) sends it."""
    n = len(payload)
    b0 = (0x80 if fin else 0) | op
    m = 0x80 if mask else 0
    if n < 126:
        head = struct.pack("!BB", b0, m | n)
    elif n <= 0xFFFF:
        head = struct.pack("!BBH", b0, m | 126, n)
    else:
        head = struct.pack("!BBQ", b0, m | 127, n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + mask_bytes(payload, key)


class FrameError(LinkError):
    """The far end broke the framing rules."""


class WebSocket:
    """One WebSocket, client side: it masks what it sends and expects
    unmasked frames."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: Optional[Headers] = None,
        *,
        client: bool = True,
    ):
        self.reader = reader
        self.writer = writer
        self.headers = headers if headers is not None else Headers()
        self.client = client
        self._wlock = asyncio.Lock()
        self._loop = asyncio.get_running_loop()
        self._mark = self._loop.time()  # start of the read in progress
        self._waiting = False  # a read from the socket is in progress
        self._keepalive: Optional[asyncio.Task] = None
        self.timed_out = False  # the watchdog found the link silent

    # ---------------------------------------------------------- sending

    @property
    def closing(self) -> bool:
        return self.writer.transport.is_closing()

    async def send(self, op: int, payload: bytes = b"", *, timeout: Optional[float] = None) -> None:
        """Send one frame. A send that does not finish within timeout breaks
        the connection, since part of a frame may be out."""
        if timeout is None:
            await self._send(op, payload)
            return
        try:
            await asyncio.wait_for(self._send(op, payload), timeout)
        except asyncio.TimeoutError:
            self.abort()
            raise LinkError("a write to the server did not finish in time") from None

    async def _send(self, op: int, payload: bytes) -> None:
        frame = encode_frame(op, payload, mask=self.client)
        async with self._wlock:
            if self.closing:
                raise LinkError("the connection to the server is closed")
            self.writer.write(frame)
            await self.writer.drain()

    # ---------------------------------------------------------- receiving

    async def _read(self, n: int) -> bytes:
        self._mark = self._loop.time()
        self._waiting = True
        try:
            return await self.reader.readexactly(n)
        except asyncio.IncompleteReadError:
            if self.timed_out:
                raise LinkError("the link to the server was silent for too long") from None
            raise LinkError("the connection to the server ended") from None
        except (ConnectionError, OSError, ssl.SSLError) as e:
            if self.timed_out:
                raise LinkError("the link to the server was silent for too long") from None
            raise LinkError(f"the connection to the server was lost ({e})") from None
        finally:
            self._waiting = False

    async def recv(self, max_data: int, max_small: int) -> tuple[int, bool, bytes]:
        """The next frame: (opcode, fin, payload). Data frames may carry up to
        max_data bytes, text and control frames up to max_small."""
        b0, b1 = await self._read(2)
        fin = bool(b0 & 0x80)
        op = b0 & 0x0F
        if b0 & 0x70:
            raise FrameError("the server set reserved bits in a frame")
        masked = bool(b1 & 0x80)
        if masked == self.client:
            raise FrameError("masked server frame" if self.client else "unmasked client frame")
        n = b1 & 0x7F
        if n == 126:
            (n,) = struct.unpack("!H", await self._read(2))
        elif n == 127:
            (n,) = struct.unpack("!Q", await self._read(8))
        limit = max_data if op in (OP_BINARY, OP_CONT) else max_small
        if op >= 0x8 and not fin:
            raise FrameError("fragmented control frame")
        if op not in (OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG):
            raise FrameError(f"unknown frame opcode {op}")
        if n > limit:
            raise FrameError("frame too large")
        key = await self._read(4) if masked else b""
        if n <= _READ_PIECE:
            payload = await self._read(n) if n else b""
        else:
            parts = []
            left = n
            while left:
                piece = await self._read(min(left, _READ_PIECE))
                parts.append(piece)
                left -= len(piece)
            payload = b"".join(parts)
        if masked:
            payload = mask_bytes(payload, key)
        return op, fin, payload

    # ---------------------------------------------------------- keepalive

    def start_keepalive(
        self, ping_every: float, silence: float, on_dead: Optional[Callable[[], None]] = None
    ) -> None:
        """Ping on a timer of our own, and break the link when a read waits
        longer than silence."""
        self._keepalive = asyncio.ensure_future(self._keep(ping_every, silence, on_dead))

    def stop_keepalive(self) -> None:
        t, self._keepalive = self._keepalive, None
        if t is not None and t is not asyncio.current_task():
            t.cancel()

    async def _keep(self, ping_every: float, silence: float, on_dead) -> None:
        loop = self._loop
        next_ping = loop.time() + ping_every
        try:
            while True:
                now = loop.time()
                wake = next_ping
                if self._waiting:
                    wake = min(wake, self._mark + silence)
                await asyncio.sleep(max(0.05, min(wake - now, 1.0)))
                now = loop.time()
                if self._waiting and now - self._mark >= silence:
                    self.timed_out = True
                    self.abort()
                    if on_dead:
                        on_dead()
                    return
                if now >= next_ping:
                    next_ping = now + ping_every
                    try:
                        await self.send(OP_PING, b"", timeout=WRITE_TIMEOUT)
                    except (LinkError, ConnectionError, OSError):
                        self.abort()  # wake whoever is reading
                        return
        except asyncio.CancelledError:
            pass

    # ---------------------------------------------------------- the end

    def abort(self) -> None:
        """Cut the connection at once."""
        try:
            self.writer.transport.abort()
        except Exception:  # pragma: no cover - already gone
            pass

    def close_transport(self) -> None:
        """Close the connection after what is buffered has gone out."""
        try:
            self.writer.close()
        except Exception:  # pragma: no cover
            pass


# ---------------------------------------------------------------- HTTP


async def _open(host: str, port: int, ssl_ctx: ssl.SSLContext):
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host, limit=1 << 20),
        DIAL_TIMEOUT,
    )


def _request_bytes(path: str, netloc: str, headers: Iterable[tuple[str, str]]) -> bytes:
    lines = [f"GET {path} HTTP/1.1", f"Host: {netloc}"]
    for name, value in headers:
        if any(c in value for c in "\r\n\0") or any(c in name for c in "\r\n\0: "):
            raise ValueError(f"invalid value for header {name}")
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


async def _read_head(reader: asyncio.StreamReader) -> tuple[int, str, Headers]:
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError:
        raise LinkError("the server closed the connection before answering") from None
    except asyncio.LimitOverrunError:
        raise LinkError("the server's answer has too many headers") from None
    lines = raw.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdigit():
        raise LinkError(f"the server's answer is not HTTP/1.1: {lines[0][:80]!r}")
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""
    headers = Headers()
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        key = name.strip().lower()
        if key not in headers:
            dict.__setitem__(headers, key, value.strip())
    return status, reason, headers


async def _read_body(reader: asyncio.StreamReader, headers: Headers, status: int) -> bytes:
    if status in (204, 304) or 100 <= status < 200:
        return b""
    try:
        if "chunked" in headers.get("transfer-encoding", "").lower():
            out = bytearray()
            while len(out) < _BODY_LIMIT:
                size_line = await reader.readline()
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    break
                out += await reader.readexactly(size)
                await reader.readexactly(2)
            return bytes(out[:_BODY_LIMIT])
        cl = headers.get("content-length")
        if cl is not None:
            n = min(int(cl), _BODY_LIMIT)
            return await reader.readexactly(n) if n > 0 else b""
        out = bytearray()
        while len(out) < _BODY_LIMIT:
            chunk = await reader.read(_BODY_LIMIT - len(out))
            if not chunk:
                break
            out += chunk
        return bytes(out)
    except (asyncio.IncompleteReadError, ValueError, ConnectionError, OSError):
        return b""


async def http_get(
    host: str, port: int, netloc: str, ssl_ctx: ssl.SSLContext, path: str, headers: list[tuple[str, str]]
) -> Response:
    """A plain GET; the connection is closed after the answer."""

    async def run() -> Response:
        reader, writer = await _open(host, port, ssl_ctx)
        try:
            writer.write(_request_bytes(path, netloc, list(headers) + [("Connection", "close")]))
            await writer.drain()
            status, reason, h = await _read_head(reader)
            body = await _read_body(reader, h, status)
            return Response(status, reason, h, body)
        finally:
            writer.transport.abort()

    try:
        return await asyncio.wait_for(run(), HANDSHAKE_LIMIT)
    except asyncio.TimeoutError:
        raise LinkError("the server did not answer in time") from None


async def ws_dial(
    host: str, port: int, netloc: str, ssl_ctx: ssl.SSLContext, path: str, headers: list[tuple[str, str]]
) -> tuple[Response, Optional[WebSocket]]:
    """A WebSocket handshake. On 101 the WebSocket is returned with the
    response; on any other status the response carries the body and no
    WebSocket."""

    async def run():
        reader, writer = await _open(host, port, ssl_ctx)
        ok = False
        try:
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            h = list(headers) + [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", key),
                ("Sec-WebSocket-Version", "13"),
            ]
            writer.write(_request_bytes(path, netloc, h))
            await writer.drain()
            status, reason, rh = await _read_head(reader)
            if status != 101:
                body = await _read_body(reader, rh, status)
                return Response(status, reason, rh, body), None
            if rh.get("sec-websocket-accept") != accept_key(key):
                raise LinkError("the server's websocket handshake is invalid")
            ok = True
            return Response(status, reason, rh), WebSocket(reader, writer, rh)
        finally:
            if not ok:
                writer.transport.abort()

    try:
        return await asyncio.wait_for(run(), HANDSHAKE_LIMIT)
    except asyncio.TimeoutError:
        raise LinkError("the server did not answer in time") from None
