"""Protocol 3's framing (PROTOCOL.md 13.5) and the Client over an attached
transport (pfrelay.transport), against in-memory streams."""

import asyncio
import os
import struct
import sys
import unittest
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pfrelay  # noqa: E402
from pfrelay import _framed, transport  # noqa: E402
from pfrelay._framed import FRAME_DATA, FRAME_EOF, FRAME_ERR, Framed, encode  # noqa: E402
from pfrelay._ws import OP_BINARY, OP_CLOSE, OP_TEXT, FrameError  # noqa: E402
from support import WORD, new_client  # noqa: E402


class End:
    """One end of an in-memory bidirectional stream, with QUIC's ways of
    ending a direction: FIN, RESET_STREAM and STOP_SENDING."""

    def __init__(self) -> None:
        self.peer: Optional["End"] = None
        self.buf = bytearray()
        self.fin = False  # the peer sent FIN
        self.reset = False  # the peer reset its direction
        self.stopped = False  # the peer asked this end to stop sending
        self.finished = False  # this end sent FIN
        self.cancelled = False
        self.broke = False
        self.closed = False
        self.readable = asyncio.Event()

    def _wake(self) -> None:
        self.readable.set()

    async def read(self, n: int) -> bytes:
        while True:
            if self.cancelled or self.broke:
                raise ConnectionResetError("the stream was reset")
            if self.buf:
                out = bytes(self.buf[:n])
                del self.buf[:n]
                return out
            if self.reset:
                raise ConnectionResetError("the peer reset the stream")
            if self.fin:
                return b""
            self.readable.clear()
            await self.readable.wait()

    async def write(self, data: bytes) -> None:
        if self.stopped or self.cancelled or self.broke or self.finished:
            raise ConnectionResetError("the stream cannot be written")
        self.peer.buf += data
        self.peer._wake()

    def finish(self) -> None:
        if not self.finished:
            self.finished = True
            self.peer.fin = True
            self.peer._wake()

    def _reset_both(self) -> None:
        if not self.finished:
            self.peer.reset = True
        self.peer.stopped = True
        self.peer._wake()

    def cancel(self) -> None:
        self.cancelled = True
        self._reset_both()
        self._wake()

    def broken(self) -> None:
        self.broke = True
        self._reset_both()
        self._wake()

    def close(self) -> None:
        self.closed = True
        if not self.finished:
            self.cancel()


def pipe() -> tuple[End, End]:
    a, b = End(), End()
    a.peer, b.peer = b, a
    return a, b


async def frames(end: End, timeout: float = 5) -> list:
    """Everything the peer sent until its FIN or reset, as (type, payload)."""
    data = bytearray()
    while True:
        try:
            chunk = await asyncio.wait_for(end.read(1 << 20), timeout)
        except ConnectionResetError:
            break
        if not chunk:
            break
        data += chunk
    out = []
    while data:
        typ, n = struct.unpack("!BH", bytes(data[:3]))
        out.append((typ, bytes(data[3:3 + n])))
        del data[:3 + n]
    return out


class Encoding(unittest.TestCase):
    def test_frames(self):
        self.assertEqual(encode(FRAME_DATA, b"hi"), b"\x00\x00\x02hi")
        self.assertEqual(encode(FRAME_EOF), b"\x01\x00\x00")

    def test_reasons(self):
        self.assertEqual(_framed.err_payload(""), _framed.NO_REASON.encode())
        long = _framed.err_payload("é" * 600)
        self.assertTrue(_framed.MAX_ERR - 1 <= len(long) <= _framed.MAX_ERR)
        long.decode("utf-8")  # cut at a character boundary


class Framing(unittest.IsolatedAsyncioTestCase):
    async def test_read_frames(self):
        a, b = pipe()
        f = Framed(a)
        wire = encode(FRAME_DATA, b"x" * 300) + encode(0x7F, b"unknown, skipped") + encode(FRAME_EOF)
        wire += encode(FRAME_ERR, b"why")
        await b.write(wire)
        b.finish()
        self.assertEqual(await f.recv(1 << 20, 1024), (OP_BINARY, True, b"x" * 300))
        self.assertEqual(await f.recv(1 << 20, 1024), (OP_TEXT, True, b"eof"))
        self.assertEqual(await f.recv(1 << 20, 1024), (OP_TEXT, True, b"err:why"))
        self.assertEqual((await f.recv(1 << 20, 1024))[0], OP_CLOSE, "FIN at a boundary is the close")

    async def test_violations(self):
        cases = [
            (encode(FRAME_DATA, b"abc")[:4], "inside a frame"),
            (b"\x01\x00\x01x", "eof frame with a payload"),
            (b"\x02\x00\x00", "bad length"),
            (b"\x02\x04\x01", "bad length"),
            (encode(FRAME_EOF) + encode(FRAME_EOF), "second eof"),
            (encode(FRAME_EOF) + encode(FRAME_DATA, b"x"), "data after eof"),
            (encode(FRAME_ERR, b"a") + encode(FRAME_DATA, b"x"), "after err"),
        ]
        for wire, want in cases:
            with self.subTest(want=want):
                a, b = pipe()
                f = Framed(a)
                await b.write(wire)
                b.finish()
                with self.assertRaises(FrameError) as ctx:
                    for _ in range(3):
                        await f.recv(1 << 20, 1024)
                self.assertIn(want, str(ctx.exception))
                self.assertTrue(a.broke, "the stream is reset (protocol)")

    async def test_write_frames(self):
        a, b = pipe()
        f = Framed(a)
        await f.send(OP_BINARY, b"y" * 70000)
        await f.send(OP_TEXT, b"something else")  # not said on a framed stream
        await f.send(0x9, b"")  # a ping: not said either
        await f.send(OP_TEXT, b"eof")
        await f.send(OP_TEXT, b"err:")
        await f.send(OP_CLOSE)
        got = await frames(b)
        self.assertEqual([(t, len(p)) for t, p in got], [(0, 65535), (0, 70000 - 65535), (1, 0), (2, 23)])
        self.assertEqual(got[-1][1], _framed.NO_REASON.encode())
        self.assertTrue(a.finished, "a close is the stream's FIN")


class Conns(unittest.IsolatedAsyncioTestCase):
    async def test_clean_finish(self):
        a, b = pipe()
        conn = pfrelay.Conn(Framed(a), "8f14e45fceea167a", pfrelay.Side.CONNECT)
        await conn.write(b"hello")
        await b.write(encode(FRAME_DATA, b"world") + encode(FRAME_EOF))
        self.assertEqual(await conn.read(), b"world")
        self.assertEqual(await conn.read(), b"")
        closing = asyncio.ensure_future(conn.close())
        got = await frames(b)
        self.assertEqual(got, [(FRAME_DATA, b"hello"), (FRAME_EOF, b"")])
        self.assertTrue(a.finished, "eof, then FIN once the other eof is in")
        b.finish()
        self.assertIsNone(await asyncio.wait_for(closing, 5))

    async def test_peer_err_ends_this_direction(self):
        a, b = pipe()
        conn = pfrelay.Conn(Framed(a), "8f14e45fceea167a", pfrelay.Side.SERVE)
        await b.write(encode(FRAME_ERR, b"the target went away"))
        b.finish()
        with self.assertRaises(pfrelay.RemoteError) as ctx:
            await conn.read()
        self.assertEqual(ctx.exception.reason, "the target went away")
        self.assertTrue(a.cancelled, "the receiver of err ends its direction at once")
        self.assertIsInstance(await conn.close(), pfrelay.RemoteError)

    async def test_fail_sends_err_then_fin(self):
        a, b = pipe()
        conn = pfrelay.Conn(Framed(a), "8f14e45fceea167a", pfrelay.Side.CONNECT)
        await conn.fail("dropped here")
        got = await frames(b)
        self.assertEqual(got, [(FRAME_ERR, b"dropped here")])
        self.assertTrue(a.finished and a.closed)

    async def test_failed_write_reports_the_reason(self):
        # STOP_SENDING can overtake the err sent before it (13.5).
        a, b = pipe()
        conn = pfrelay.Conn(Framed(a), "8f14e45fceea167a", pfrelay.Side.CONNECT)
        a.stopped = True

        async def later():
            await asyncio.sleep(0.1)
            await b.write(encode(FRAME_ERR, b"the serving side refused"))
            b.finish()

        t = asyncio.ensure_future(later())
        with self.assertRaises(pfrelay.RemoteError) as ctx:
            await conn.write(b"early data")
        self.assertEqual(ctx.exception.reason, "the serving side refused")
        await t
        await conn.close()

    async def test_fin_out_of_turn_is_a_failure(self):
        a, b = pipe()
        conn = pfrelay.Conn(Framed(a), "8f14e45fceea167a", pfrelay.Side.CONNECT)
        b.finish()
        with self.assertRaises(pfrelay.LinkError):
            await conn.read()
        self.assertIsNotNone(await conn.close())


class FakeOpen:
    def __init__(self, cid: str):
        self._id = cid
        self.end, self.hub = pipe()
        self.refused: Optional[str] = None
        self.accepted = False

    @property
    def id(self) -> str:
        return self._id

    async def accept(self):
        self.accepted = True
        return self.end

    async def refuse(self, reason: str) -> None:
        self.refused = reason


class FakeReg:
    def __init__(self) -> None:
        self.opens: asyncio.Queue = asyncio.Queue()
        self.closed = False

    async def next(self):
        o = await self.opens.get()
        if o is None:
            raise pfrelay.LinkError("the hub ended the registration")
        return o

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    name = "fake"

    def __init__(self) -> None:
        self.refusals: list = []  # errors register raises first
        self.regs: list[FakeReg] = []
        self.registered = asyncio.Event()
        self.checks = 0
        self.dialed: list = []
        self.params: Optional[transport.Params] = None

    async def register(self, p, target):
        self.params = p
        if self.refusals:
            raise self.refusals.pop(0)
        reg = FakeReg()
        self.regs.append(reg)
        self.registered.set()
        return reg

    async def connect(self, p):
        a, b = pipe()
        self.dialed.append(b)
        return a, "8f14e45fceea167a"

    async def check(self, p):
        self.checks += 1
        if self.refusals:
            raise self.refusals.pop(0)

    def close(self) -> None:
        pass


class Client(unittest.IsolatedAsyncioTestCase):
    async def test_params(self):
        t = FakeTransport()
        c = new_client(transport=t, serve_token="s" * 40, client_token="c" * 20, name="Mon service é")
        lst = await c.listen()
        p = t.params
        self.assertEqual((p.word, p.serve_token, p.client_token, p.name), (WORD, "s" * 40, "c" * 20, "Mon service é"))
        self.assertEqual(len(p.client_token_sha256), 64)
        self.assertTrue(p.agent.startswith("pfrelay-py 0.3.0"))
        await lst.close()

    async def test_dial_and_check(self):
        t = FakeTransport()
        c = new_client(transport=t)
        await c.check()
        t.refusals.append(transport.refused(403, "no"))
        with self.assertRaises(pfrelay.AccessDenied):
            await c.check()
        conn = await c.dial()
        self.assertEqual(str(conn.id), "8f14e45fceea167a")
        await conn.write(b"hi")
        self.assertEqual(await t.dialed[0].read(100), encode(FRAME_DATA, b"hi"))
        await conn.fail("bye")
        self.assertEqual(c.stats().opened, 1)

    async def test_listen_accept_and_reregister(self):
        t = FakeTransport()
        t.refusals.append(pfrelay.LinkError("cannot reach the hub over QUIC"))
        ups = []
        c = new_client(transport=t, events=pfrelay.Events(on_serving=ups.append))
        lst = await asyncio.wait_for(c.listen(), 5)
        o = FakeOpen("0123456789abcdef")
        t.regs[0].opens.put_nowait(o)
        conn = await asyncio.wait_for(lst.accept(), 5)
        self.assertTrue(o.accepted)
        self.assertEqual(str(conn.id), "0123456789abcdef")
        self.assertEqual(conn.side, pfrelay.Side.SERVE)
        t.registered.clear()
        t.regs[0].opens.put_nowait(None)  # the hub ends the registration
        await asyncio.wait_for(t.registered.wait(), 5)
        self.assertTrue(t.regs[0].closed)
        self.assertEqual(len(t.regs), 2)
        await conn.fail("done")
        await lst.close()
        self.assertEqual(ups[:3], [True, False, True])

    async def test_first_refusal_is_final(self):
        t = FakeTransport()
        t.refusals.append(transport.refused(403, "bad token"))
        c = new_client(transport=t)
        with self.assertRaises(pfrelay.AccessDenied):
            await asyncio.wait_for(c.listen(), 5)

    async def test_serve_refuses_an_unreachable_target(self):
        t = FakeTransport()
        refused = []
        c = new_client(transport=t, events=pfrelay.Events(on_refuse=lambda cid, why: refused.append((str(cid), why))))
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()
        task = asyncio.ensure_future(c.serve(f"127.0.0.1:{port}"))
        await asyncio.wait_for(t.registered.wait(), 5)
        o = FakeOpen("0123456789abcdef")
        t.regs[0].opens.put_nowait(o)
        for _ in range(100):
            if o.refused:
                break
            await asyncio.sleep(0.05)
        self.assertEqual(o.refused, pfrelay.REASON_UNREACHABLE)
        self.assertEqual(refused, [("0123456789abcdef", pfrelay.REASON_UNREACHABLE)])
        self.assertFalse(o.accepted)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
