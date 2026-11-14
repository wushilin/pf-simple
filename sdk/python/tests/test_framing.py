"""Framing and stream semantics, against a fake hub over plain TCP."""

import asyncio
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pfrelay  # noqa: E402
from pfrelay import _conn, _ws  # noqa: E402
from pfrelay._ws import OP_BINARY, OP_CLOSE, OP_CONT, OP_PING, OP_TEXT  # noqa: E402
from support import Pair, new_client  # noqa: E402


class Encoding(unittest.TestCase):
    def test_mask_roundtrip(self):
        key = b"\x01\x02\x03\x04"
        for n in (0, 1, 3, 4, 5, 125, 126, 65535, 65536, 100001):
            data = os.urandom(n)
            masked = _ws.mask_bytes(data, key)
            self.assertEqual(len(masked), n)
            self.assertEqual(_ws.mask_bytes(masked, key), data)
            want = bytes(b ^ key[i % 4] for i, b in enumerate(data[:64]))
            self.assertEqual(masked[:64], want)

    def test_lengths(self):
        for n, hdr in ((0, 2), (125, 2), (126, 4), (65535, 4), (65536, 10)):
            f = _ws.encode_frame(OP_BINARY, b"x" * n, mask=False)
            self.assertEqual(len(f), hdr + n)
            self.assertEqual(f[0], 0x82)
            fm = _ws.encode_frame(OP_BINARY, b"x" * n, mask=True)
            self.assertEqual(len(fm), hdr + 4 + n)
            self.assertTrue(fm[1] & 0x80)

    def test_accept_key(self):  # RFC 6455's example
        self.assertEqual(_ws.accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")


def fed(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


class HTTP(unittest.IsolatedAsyncioTestCase):
    async def test_head_and_json_body(self):
        body = b'{"error":"this word belongs to another tenant"}'
        r = fed(
            b"HTTP/1.1 409 Conflict\r\nX-Pf-Tunnel-Proto: 1\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        status, _, h = await _ws._read_head(r)
        self.assertEqual(status, 409)
        self.assertEqual(h.get("X-PF-Tunnel-Proto"), "1")
        self.assertEqual(await _ws._read_body(r, h, status), body)

    async def test_chunked(self):
        r = fed(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\n!!!\r\n0\r\n\r\n")
        status, _, h = await _ws._read_head(r)
        self.assertEqual(await _ws._read_body(r, h, status), b"hello!!!")

    async def test_not_http(self):
        with self.assertRaises(pfrelay.LinkError):
            await _ws._read_head(fed(b"SSH-2.0-x\r\n\r\n"))

    def test_request_refuses_injection(self):
        with self.assertRaises(ValueError):
            _ws._request_bytes("/", "h", [("X-A", "a\r\nX-B: b")])


class Frames(unittest.IsolatedAsyncioTestCase):
    async def test_masked_server_frame_is_refused(self):
        async with Pair() as p:
            p.hub.writer.write(_ws.encode_frame(OP_BINARY, b"x", mask=True))
            with self.assertRaises(pfrelay.LinkError):
                await p.client.recv(1 << 20, 1024)

    async def test_too_large(self):
        async with Pair() as p:
            p.hub.writer.write(struct.pack("!BBQ", 0x82, 127, (1 << 20) + 1))
            with self.assertRaises(pfrelay.LinkError):
                await p.client.recv(1 << 20, 1024)

    async def test_rsv_bits(self):
        async with Pair() as p:
            p.hub.writer.write(b"\xc2\x00")
            with self.assertRaises(pfrelay.LinkError):
                await p.client.recv(1 << 20, 1024)

    async def test_client_masks(self):
        async with Pair() as p:
            p.hub.writer.write(b"")
            await p.client.send(OP_TEXT, b"eof")
            raw = await p.hub.reader.readexactly(9)
            self.assertEqual(raw[0], 0x81)
            self.assertEqual(raw[1], 0x80 | 3)
            self.assertEqual(_ws.mask_bytes(raw[6:], raw[2:6]), b"eof")


class Streams(unittest.IsolatedAsyncioTestCase):
    async def test_data_and_half_close(self):
        async with Pair() as p:
            reg = new_client()
            conn = await reg._new_conn(p.client, pfrelay.ConnID("0123456789abcdef"), pfrelay.Side.CONNECT)
            await p.hub.send(OP_BINARY, b"hello ")
            await p.hub.send(OP_CONT, b"world")
            await p.hub.send(OP_BINARY, b"")
            await p.hub.send(OP_TEXT, b"something else")  # ignored
            await p.hub.send(OP_PING, b"")  # not answered
            await p.hub.send(OP_TEXT, b"eof")
            got = b""
            while True:
                chunk = await conn.read(4)
                if not chunk:
                    break
                got += chunk
            self.assertEqual(got, b"hello world")
            self.assertEqual(await conn.read(), b"")
            self.assertTrue(conn.info().read_eof)

            # After the far end's eof this end may go on sending.
            big = os.urandom(200_000)
            await conn.write(big)
            seen = b""
            while len(seen) < len(big):
                op, fin, payload = await p.hub_recv_skip_pings()
                self.assertEqual(op, OP_BINARY)
                self.assertTrue(fin)
                self.assertLessEqual(len(payload), 64 * 1024)
                seen += payload
            self.assertEqual(seen, big)

            close = asyncio.ensure_future(conn.close())
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_TEXT, True, b"eof"))
            self.assertEqual((await p.hub_recv_skip_pings())[0], OP_CLOSE)
            await p.hub.send(OP_CLOSE, b"")
            await asyncio.wait_for(close, 5)
            self.assertIsNone(conn.err)
            st = reg.stats()
            self.assertEqual((st.opened, st.active, st.failed), (1, 0, 0))
            self.assertEqual((st.sent, st.received), (len(big), 11))
            with self.assertRaises(pfrelay.ClosedError):
                await conn.write(b"x")

    async def test_err_before_eof(self):
        async with Pair() as p:
            conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
            await p.hub.send(OP_BINARY, b"abc")
            await p.hub.send(OP_TEXT, b"err:the target reset\x07 its connection")
            await p.hub.send(OP_CLOSE, b"")
            self.assertEqual(await conn.read(), b"abc")
            with self.assertRaises(pfrelay.RemoteError) as cm:
                await conn.read()
            self.assertEqual(cm.exception.reason, "the target reset its connection")
            self.assertIsInstance(conn.err, pfrelay.RemoteError)
            # The close is answered.
            self.assertEqual((await p.hub_recv_skip_pings())[0], OP_CLOSE)
            await conn.close()

    async def test_err_after_eof(self):
        # PROTOCOL.md 8.3: a failure may arrive as eof first, err: later.
        async with Pair() as p:
            conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
            await p.hub.send(OP_TEXT, b"eof")
            self.assertEqual(await conn.read(), b"")
            self.assertIsNone(conn.err)
            await p.hub.send(OP_TEXT, b"err:the serving side could not reach its target")
            await p.hub.send(OP_CLOSE, b"")
            await asyncio.wait_for(conn.wait_closed(), 5)
            self.assertIsInstance(conn.err, pfrelay.RemoteError)
            self.assertEqual(conn.err.reason, "the serving side could not reach its target")
            self.assertEqual(await conn.read(), b"")
            await conn.close()

    async def test_close_without_eof_is_a_failure(self):
        async with Pair() as p:
            conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
            await p.hub.send(OP_CLOSE, b"")
            with self.assertRaises(pfrelay.LinkError):
                await conn.read()
            await conn.close()

    async def test_tcp_end_without_close_is_a_failure(self):
        async with Pair() as p:
            conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
            p.hub.close_transport()
            with self.assertRaises(pfrelay.LinkError):
                await asyncio.wait_for(conn.read(), 5)
            await conn.close()

    async def test_data_after_eof_breaks(self):
        async with Pair() as p:
            conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
            await p.hub.send(OP_TEXT, b"eof")
            await p.hub.send(OP_BINARY, b"late")
            self.assertEqual(await conn.read(), b"")
            await asyncio.wait_for(conn.wait_closed(), 5)
            await conn.close()

    async def test_fail(self):
        async with Pair() as p:
            reg = new_client()
            conn = await reg._new_conn(p.client, pfrelay.ConnID("id"), pfrelay.Side.SERVE)
            await conn.fail("the target\nwent away")
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_TEXT, True, b"err:the targetwent away"))
            self.assertEqual((await p.hub_recv_skip_pings())[0], OP_CLOSE)
            self.assertEqual(reg.stats().failed, 1)

    async def test_close_before_far_eof_cuts(self):
        async with Pair() as p:
            conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
            await conn.close()
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_TEXT, True, b"eof"))
            with self.assertRaises(pfrelay.LinkError):
                await p.hub_recv()  # cut: no close frame

    async def test_pings_and_silence(self):
        async with Pair() as p:
            old = (_conn.Conn._PING_EVERY, _conn.Conn._SILENCE)
            _conn.Conn._PING_EVERY, _conn.Conn._SILENCE = 0.1, 0.5
            try:
                conn = _conn.Conn(p.client, "id", pfrelay.Side.CONNECT)
                op, _, _ = await p.hub_recv(2)
                self.assertEqual(op, OP_PING)
                # The hub stays silent: the link counts as dead.
                with self.assertRaises(pfrelay.LinkError):
                    await asyncio.wait_for(conn.read(), 5)
                self.assertIsInstance(conn.err, pfrelay.LinkError)
                await conn.close()
            finally:
                _conn.Conn._PING_EVERY, _conn.Conn._SILENCE = old


if __name__ == "__main__":
    unittest.main()
