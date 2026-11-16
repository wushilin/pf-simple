"""A transport's stream as a Conn's link: protocol 3's frames (PROTOCOL.md
13.5)

    type (1 byte)  length (2 bytes, big-endian)  payload
    0x00 data      0 to 65535                    the next bytes
    0x01 eof       0                             the sender's half-close
    0x02 err       1 to 1024                     why the stream is dropped

presented as the WebSocket frames they stand for, so that a Conn works on it
exactly as on a WebSocket: data, "eof", "err:why", and the stream's FIN in
place of the close. There are no pings: the transport keeps its connection
alive, not the stream.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Optional

from ._proto import LinkError
from ._ws import OP_BINARY, OP_CLOSE, OP_CONT, OP_TEXT, FrameError, Headers
from .transport import Stream

FRAME_DATA = 0x00
FRAME_EOF = 0x01
FRAME_ERR = 0x02
MAX_DATA = 0xFFFF  # the most one data frame carries
MAX_ERR = 1024  # the longest reason of an err frame
NO_REASON = "the peer gave no reason"  # what an empty reason becomes

_EOF_TEXT = b"eof"
_ERR_PREFIX = b"err:"
_READ_PIECE = 64 * 1024


def encode(typ: int, payload: bytes = b"") -> bytes:
    """One frame."""
    return struct.pack("!BH", typ, len(payload)) + payload


def err_payload(reason: str) -> bytes:
    """The reason of an err frame: never empty, cut at a UTF-8 boundary to
    fit."""
    b = (reason or NO_REASON).encode("utf-8")
    if len(b) <= MAX_ERR:
        return b
    return b[:MAX_ERR].decode("utf-8", "ignore").encode("utf-8")


class Framed:
    """A Stream with the interface of a WebSocket, as Conn uses it."""

    framed = True

    def __init__(self, stream: Stream):
        self.stream = stream
        self.headers = Headers()
        self._wlock = asyncio.Lock()
        self._buf = bytearray()
        self._finned = False  # FIN sent
        self._ended = False  # this side has let go of the stream
        self._read_eof = False
        self._read_err = False

    # ---------------------------------------------------------- sending

    async def send(self, op: int, payload: bytes = b"", *, timeout: Optional[float] = None) -> None:
        """Send what a WebSocket frame op says, in protocol 3's framing. A send
        that does not finish within timeout cuts the stream."""
        if timeout is None:
            await self._send(op, payload)
            return
        try:
            await asyncio.wait_for(self._send(op, payload), timeout)
        except asyncio.TimeoutError:
            self.abort()
            raise LinkError("a write to the server did not finish in time") from None

    async def _send(self, op: int, payload: bytes) -> None:
        async with self._wlock:
            if self._ended:
                raise LinkError("the connection is closed")
            if op in (OP_BINARY, OP_CONT):
                if not payload:
                    return  # an empty data frame carries nothing
                frames = [encode(FRAME_DATA, payload[i:i + MAX_DATA]) for i in range(0, len(payload), MAX_DATA)]
                await self._write(b"".join(frames))
            elif op == OP_TEXT:
                if payload == _EOF_TEXT:
                    await self._write(encode(FRAME_EOF))
                elif payload.startswith(_ERR_PREFIX):
                    reason = payload[len(_ERR_PREFIX):].decode("utf-8", "replace")
                    await self._write(encode(FRAME_ERR, err_payload(reason)))
                # nothing else is said on a framed stream
            elif op == OP_CLOSE:
                if not self._finned:
                    self._finned = True
                    self.stream.finish()
            # pings and pongs: the transport keeps the connection alive

    async def _write(self, data: bytes) -> None:
        try:
            await self.stream.write(data)
        except LinkError:
            raise
        except (ConnectionError, OSError) as e:
            raise LinkError(f"the connection to the server was lost ({e})") from None

    # ---------------------------------------------------------- receiving

    async def _fill(self, n: int) -> bool:
        """Make the buffer hold n bytes; False when the stream ended first."""
        while len(self._buf) < n:
            try:
                chunk = await self.stream.read(max(n - len(self._buf), _READ_PIECE))
            except LinkError:
                raise
            except (ConnectionError, OSError) as e:
                raise LinkError(f"the connection to the server was lost ({e})") from None
            if not chunk:
                return False
            self._buf += chunk
        return True

    def _take(self, n: int) -> bytes:
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _broken(self, what: str) -> FrameError:
        """The peer broke the protocol: reset the stream ("protocol")."""
        if not self._ended:
            self._ended = True
            self.stream.broken()
        return FrameError(f"the peer broke the protocol: {what}")

    async def recv(self, max_data: int, max_small: int) -> tuple[int, bool, bytes]:
        """The next frame, as the WebSocket frame it stands for: (opcode, fin,
        payload). The stream's FIN at a frame boundary is a close."""
        while True:
            if not await self._fill(3):
                if self._buf:
                    raise self._broken("the stream ended inside a frame")
                return OP_CLOSE, True, b""
            typ, size = struct.unpack("!BH", bytes(self._buf[:3]))
            if typ == FRAME_EOF and size != 0:
                raise self._broken("an eof frame with a payload")
            if typ == FRAME_ERR and not 1 <= size <= MAX_ERR:
                raise self._broken("an err frame of a bad length")
            if not await self._fill(3 + size):
                raise self._broken("the stream ended inside a frame")
            del self._buf[:3]
            payload = self._take(size)
            if typ == FRAME_DATA:
                if self._read_err:
                    raise self._broken("a frame after err")
                if self._read_eof:
                    raise self._broken("data after eof")
                if size > max_data:
                    raise self._broken("a frame too large")
                return OP_BINARY, True, payload
            if typ == FRAME_EOF:
                if self._read_err:
                    raise self._broken("a frame after err")
                if self._read_eof:
                    raise self._broken("a second eof")
                self._read_eof = True
                return OP_TEXT, True, _EOF_TEXT
            if typ == FRAME_ERR:
                if self._read_err:
                    raise self._broken("a frame after err")
                self._read_err = True
                return OP_TEXT, True, _ERR_PREFIX + payload
            # an unknown type: skipped by its length (13.5)

    # ---------------------------------------------------------- keepalive

    def start_keepalive(self, *args, **kwargs) -> None:
        """Nothing: the transport keeps its connection alive (13.6)."""

    def stop_keepalive(self) -> None:
        pass

    # ---------------------------------------------------------- the end

    def abort(self) -> None:
        """End the stream: after FIN, the peer has a short while to end its own
        direction; without FIN, both directions are reset at once."""
        if not self._ended:
            self._ended = True
            self.stream.close()

    def close_transport(self) -> None:
        self.abort()

    def peer_failed(self) -> None:
        """The far end dropped the connection with err: end this side's
        direction at once (13.5)."""
        if not self._ended:
            self._ended = True
            if self._finned:
                self.stream.close()
            else:
                self.stream.cancel()
