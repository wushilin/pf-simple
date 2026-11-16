"""pfrelay-quic against a fake hub's QUIC listener (tests/hub.py)."""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hub import (  # noqa: E402
    FRAME_DATA,
    FRAME_EOF,
    FRAME_ERR,
    Hub,
    answer,
    client,
    echo,
    encode,
    open_to,
    read_frame,
    refuse,
)

import pfrelay  # noqa: E402
import pfrelay_quic  # noqa: E402
from pfrelay import transport as spi  # noqa: E402
from pfrelay_quic import _quic, _transport, _wire  # noqa: E402


class Wire(unittest.TestCase):
    def test_requests(self):
        r = _wire.request("connect", 3, "pfrelay-quic-py test", "k3f9-x2mq-7hpa", clientToken="secret", name=None)
        self.assertEqual(
            r, {"op": "connect", "proto": "3", "version": "pfrelay-quic-py test", "word": "k3f9-x2mq-7hpa",
                "clientToken": "secret"}
        )
        m = _wire.encode_message({"op": "serve", "name": "Mon service é"})
        self.assertEqual(int.from_bytes(m[:2], "big"), len(m) - 2)
        self.assertIn("Mon service é".encode("utf-8"), m, "plain UTF-8, not escaped")
        with self.assertRaises(ValueError):
            _wire.encode_message({"x": "a" * 5000})

    def test_answers(self):
        a = _wire.Answer.of({"status": 429, "proto": 3, "scope": "connection", "retryAfter": 5, "new": 1})
        self.assertEqual((a.status, a.proto, a.scope, a.retry_after), (429, 3, "connection", 5))
        self.assertEqual(_wire.Answer.of({"status": "200"}).status, 0, "a field of the wrong type is ignored")

    def test_discovery(self):
        fp = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        d = _wire.Discovery.parse(b'{"host":"2001:db8::1","port":443,"fingerprints":["%s"],"more":true}' % fp.encode())
        self.assertEqual(d.pins(), {bytes.fromhex(fp)})
        for bad in [
            '{"host":"","port":443,"fingerprints":["%s"]}' % fp,
            '{"host":"[::1]","port":443,"fingerprints":["%s"]}' % fp,
            '{"host":"h","port":0,"fingerprints":["%s"]}' % fp,
            '{"host":"h","port":65536,"fingerprints":["%s"]}' % fp,
            '{"host":"h","port":1,"fingerprints":[]}',
            '{"host":"h","port":1,"fingerprints":["abc"]}',
            '{"host":"h","port":1,"fingerprints":["%s","%s","%s","%s","%s"]}' % ((fp,) * 5),
            "[1]",
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _wire.Discovery.parse(bad.encode())

    def test_end_reasons(self):
        self.assertEqual(
            _wire.end_reason("takeover", "another registration of this word took over\x07"),
            "another registration of this word took over (another serving side registered the same word)",
        )
        self.assertEqual(_wire.end_reason("off", ""), "the server ended the registration")


class FakeParams:
    """Params whose HTTPS GET answers as the test says."""

    def __init__(self, status, body=b"", serve_token="", client_token=""):
        self.status, self.body = status, body
        self.agent, self.word = "test", "k3f9-x2mq-7hpa"
        self.serve_token, self.client_token = serve_token, client_token
        self.asked = []

    async def get(self, path, headers):
        self.asked.append((path, dict(headers)))
        return spi.HttpAnswer(self.status, {}, self.body)


class Discovery(unittest.IsolatedAsyncioTestCase):
    async def test_headers(self):
        fp = "ab" * 32
        p = FakeParams(200, b'{"host":"h","port":1,"fingerprints":["%s"]}' % fp.encode(), serve_token="t" * 32)
        q = _transport.Quic()
        await q._discover(p, _transport.OP_SERVE)
        path, h = p.asked[0]
        self.assertEqual(path, "/pf/api/tunnel/quic")
        self.assertEqual((h["X-PF-Tunnel-Op"], h["X-PF-Serve-Token"]), ("serve", "t" * 32))
        self.assertNotIn("X-PF-Tunnel-Word", h)
        p = FakeParams(200, b'{"host":"h","port":1,"fingerprints":["%s"]}' % fp.encode(), client_token="c" * 20)
        await q._discover(p, _transport.OP_CONNECT)
        h = p.asked[0][1]
        self.assertEqual((h["X-PF-Tunnel-Op"], h["X-PF-Tunnel-Word"], h["X-PF-Client-Token"]),
                         ("connect", "k3f9-x2mq-7hpa", "c" * 20))

    async def test_answers(self):
        q = _transport.Quic()
        with self.assertRaises(pfrelay.StatusError) as ctx:
            await q._discover(FakeParams(404), _transport.OP_CONNECT)
        self.assertEqual(ctx.exception.message, pfrelay_quic.NO_QUIC)
        self.assertTrue(ctx.exception.final, "a hub without QUIC: waiting cannot help")
        with self.assertRaises(pfrelay.StatusError) as ctx:
            await q._discover(FakeParams(501, b'{"error":"the QUIC listener is off"}'), _transport.OP_SERVE)
        self.assertEqual((ctx.exception.code, ctx.exception.final), (501, False))
        with self.assertRaises(pfrelay.AccessDenied):
            await q._discover(FakeParams(403, b'{"error":"no"}'), _transport.OP_CONNECT)
        with self.assertRaises(pfrelay.LinkError):
            await q._discover(FakeParams(200, b"not json"), _transport.OP_CONNECT)


class WithHub(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hub = await Hub().start()

    async def asyncTearDown(self):
        self.hub.close()


class Handshake(WithHub):
    async def test_pin(self):
        qc = await _quic.dial("127.0.0.1", self.hub.port, {bytes.fromhex(self.hub.fingerprint)})
        self.assertEqual(qc.quic.tls.alpn_negotiated, "pf-tunnel")
        qc.close()
        with self.assertRaises(_quic.PinMismatch):
            await _quic.dial("127.0.0.1", self.hub.port, {b"\0" * 32})

    async def test_mismatch_discovers_again(self):
        c, t = client(self.hub)
        t.wrong_first = 1
        await c.check()
        self.assertEqual(t.discoveries, 2)
        t.close()
        t.wrong_first = 2
        with self.assertRaises(pfrelay.LinkError) as ctx:
            await c.check()
        self.assertEqual(str(ctx.exception), pfrelay_quic.PIN_MISMATCH)

    async def test_one_connection(self):
        c, t = client(self.hub)
        await c.check()
        await c.check()
        self.assertEqual(len(self.hub.conns), 1, "requests share one QUIC connection")
        self.assertEqual(t.discoveries, 1)
        t.close()
        await asyncio.sleep(0.1)
        await c.check()
        self.assertEqual(len(self.hub.conns), 2, "a closed connection is made again")


FLOOD = 160  # data frames of 64 KiB: 10 MiB, well past what a stream may hold


class Connecting(WithHub):
    async def test_check(self):
        c, _ = client(self.hub, client_token="c" * 20)
        await c.check()
        req = self.hub.requests[0]
        self.assertEqual((req["op"], req["proto"], req["clientToken"]), ("check", "3", "c" * 20))

        async def denied(hub, qc, s, req):
            await refuse(s, 403, "no such tunnel")

        self.hub.handlers["check"] = denied
        with self.assertRaises(pfrelay.AccessDenied):
            await c.check()

    async def test_dial_echo(self):
        c, _ = client(self.hub)
        conn = await c.dial()
        self.assertEqual(str(conn.id), "8f14e45fceea167a")
        await conn.write(b"hello " * 30000)  # several frames
        await conn.close_write()
        got = bytearray()
        while data := await conn.read():
            got += data
        self.assertEqual(bytes(got), b"hello " * 30000)
        self.assertIsNone(await asyncio.wait_for(conn.close(), 5))
        st = c.stats()
        self.assertEqual((st.opened, st.active, st.failed), (1, 0, 0))

    async def test_refused_after_200(self):
        async def refused(hub, qc, s, req):
            await answer(s, status=200, conn="8f14e45fceea167a")
            await s.write(encode(0x7F, b"an unknown frame, skipped"))
            await s.write(encode(FRAME_ERR, b"the serving side could not reach its target"))
            s.finish()
            s.close()

        self.hub.handlers["connect"] = refused
        c, _ = client(self.hub)
        conn = await c.dial()
        with self.assertRaises(pfrelay.RemoteError) as ctx:
            await conn.read()
        self.assertEqual(ctx.exception.reason, "the serving side could not reach its target")
        self.assertIsInstance(await conn.close(), pfrelay.RemoteError)

    async def test_a_failed_write_reports_the_reason(self):
        # The hub's STOP_SENDING overtakes the err sent before it (13.5).
        async def stop_first(hub, qc, s, req):
            await answer(s, status=200, conn="8f14e45fceea167a")
            s.stop_read(_wire.Code.CANCELLED)
            await asyncio.sleep(0.3)
            await s.write(encode(FRAME_ERR, b"the tunnel closed"))
            s.finish()
            s.close()

        self.hub.handlers["connect"] = stop_first
        c, _ = client(self.hub)
        conn = await c.dial()
        await asyncio.sleep(0.1)
        with self.assertRaises(pfrelay.RemoteError) as ctx:
            for _ in range(50):
                await conn.write(b"x" * 1000)
                await asyncio.sleep(0.02)
        self.assertEqual(ctx.exception.reason, "the tunnel closed")
        await conn.close()

    async def test_refusals(self):
        async def busy(hub, qc, s, req):
            await refuse(s, 429, "slow down", scope="connection", retryAfter=1)

        self.hub.handlers["connect"] = busy
        c, _ = client(self.hub)
        with self.assertRaises(pfrelay.StatusError) as ctx:
            await c.dial()
        self.assertEqual(ctx.exception.code, 429)
        self.hub.handlers["connect"] = lambda hub, qc, s, req: refuse(s, 426, "upgrade pf-client-quic")
        with self.assertRaises(pfrelay.StatusError):
            await c.dial()
        self.assertEqual(len(self.hub.conns), 2, "a 429 for the connection opens a new one (13.8)")

    async def test_a_hub_that_does_not_answer(self):
        async def silent(hub, qc, s, req):
            await asyncio.sleep(30)

        self.hub.handlers["check"] = silent
        _transport.ANSWER_WAIT, old = 0.3, _transport.ANSWER_WAIT
        try:
            c, _ = client(self.hub)
            with self.assertRaises(pfrelay.LinkError):
                await c.check()
        finally:
            _transport.ANSWER_WAIT = old

    async def test_a_stalled_stream_holds_up_only_itself(self):
        # The hub sends far more than the window on one stream, which the
        # application does not read; another stream still flows.
        async def flood(hub, qc, s, req):
            await answer(s, status=200, conn="0000000000000001")
            for _ in range(FLOOD):
                await s.write(encode(FRAME_DATA, b"z" * 65535))
                hub.flood_sent += 1

        self.hub.flood_sent = 0
        self.hub.handlers["connect"] = flood
        c, t = client(self.hub)
        stalled = await c.dial()
        await asyncio.sleep(1.5)
        held_back = self.hub.flood_sent
        await asyncio.sleep(0.5)
        self.assertEqual(self.hub.flood_sent, held_back, "flow control holds the sender back")
        self.assertLess(held_back, FLOOD // 2)
        self.assertLess(sum(t._qc.held.values()), 3 << 20, "what is held unread stays bounded")
        self.hub.handlers["connect"] = __import__("hub").connect_echo
        conn = await c.dial()
        await conn.write(b"still flowing")
        await conn.close_write()
        self.assertEqual(await asyncio.wait_for(conn.readexactly(13), 5), b"still flowing")
        await conn.close()
        got = 0
        while got < FLOOD * 65535:
            data = await asyncio.wait_for(stalled.read(), 5)
            got += len(data)
        self.assertEqual(got, FLOOD * 65535, "reading lets the rest through")
        await stalled.fail("done")


class Serving(WithHub):
    async def test_listen_and_accept(self):
        c, _ = client(self.hub, serve_token="s" * 32, client_token="c" * 20, name="Mon service é", target="db:5432")
        lst = await asyncio.wait_for(c.listen(), 5)
        req = self.hub.requests[0]
        self.assertEqual(
            (req["op"], req["serveToken"], req["name"], req["target"]), ("serve", "s" * 32, "Mon service é", "db:5432")
        )
        self.assertEqual(len(req["clientTokenSHA256"]), 64)
        qc, _, reg = self.hub.regs[0]
        s, m = await open_to(qc, reg, "0123456789abcdef")
        self.assertEqual(m, {"status": 200})
        conn = await asyncio.wait_for(lst.accept(), 5)
        self.assertEqual((str(conn.id), conn.side), ("0123456789abcdef", pfrelay.Side.SERVE))
        await s.write(encode(FRAME_DATA, b"ping") + encode(FRAME_EOF))
        self.assertEqual(await conn.readexactly(4), b"ping")
        await conn.write(b"pong")
        await conn.close_write()
        self.assertEqual(await read_frame(s), (FRAME_DATA, b"pong"))
        self.assertEqual(await read_frame(s), (FRAME_EOF, b""))
        s.finish()
        self.assertIsNone(await asyncio.wait_for(conn.close(), 5))
        await lst.close()

    async def test_an_open_before_the_serve_answer(self):
        async def open_first(hub, qc, s, req):
            reg = "5b2d4e8f1a6c9b0d"
            got = asyncio.ensure_future(open_to(qc, reg, "8f14e45fceea167a"))
            await asyncio.sleep(0.3)  # the open goes out before the answer
            await answer(s, status=200, reg=reg)
            hub.regs.append((qc, s, reg))
            hub.open_answer = await got

        self.hub.handlers["serve"] = open_first
        c, _ = client(self.hub)
        lst = await asyncio.wait_for(c.listen(), 5)
        conn = await asyncio.wait_for(lst.accept(), 5)
        self.assertEqual(str(conn.id), "8f14e45fceea167a")
        for _ in range(100):
            if hasattr(self.hub, "open_answer"):
                break
            await asyncio.sleep(0.02)
        self.assertEqual(self.hub.open_answer[1], {"status": 200})
        await conn.fail("done")
        await lst.close()

    async def test_streams_arrive_out_of_order(self):
        # Streams are not ordered with one another: the hub's newer stream
        # may arrive first, and the older one is still a new stream.
        c, _ = client(self.hub)
        lst = await asyncio.wait_for(c.listen(), 5)
        qc, _, reg = self.hub.regs[0]
        older = qc.open_stream()
        qc.quic.send_stream_data(older.id, b"")  # the stream exists, nothing is sent yet
        newer = qc.open_stream()
        self.assertLess(older.id, newer.id)
        await newer.write(_wire.encode_message({"open": "0000000000000002", "reg": reg}))
        await asyncio.sleep(0.2)
        await older.write(_wire.encode_message({"open": "0000000000000001", "reg": reg}))
        for s in (newer, older):
            self.assertEqual(await asyncio.wait_for(_transport.read_message(s), 5), {"status": 200})
        ids = {str((await asyncio.wait_for(lst.accept(), 5)).id) for _ in range(2)}
        self.assertEqual(ids, {"0000000000000001", "0000000000000002"})
        await lst.close()

    async def test_an_unknown_registration(self):
        c, _ = client(self.hub)
        lst = await asyncio.wait_for(c.listen(), 5)
        qc = self.hub.regs[0][0]
        _, m = await open_to(qc, "ffffffffffffffff", "8f14e45fceea167a")
        self.assertEqual(m, {"status": 410, "error": "no such registration"})
        await lst.close()

    async def test_a_backlog_full_refuses(self):
        c, _ = client(self.hub)
        lst = await asyncio.wait_for(c.listen(), 5)
        qc, _, reg = self.hub.regs[0]
        answers = await asyncio.gather(*[open_to(qc, reg, f"{i:016x}") for i in range(pfrelay.LISTEN_BACKLOG + 2)])
        refused = [m for _, m in answers if m["status"] == 502]
        self.assertEqual(len(refused), 2)
        self.assertEqual(refused[0]["error"], pfrelay.REASON_BACKLOG)
        await lst.close()

    async def test_an_unreachable_target_is_refused(self):
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()
        c, _ = client(self.hub)
        task = asyncio.ensure_future(c.serve(f"127.0.0.1:{port}"))
        await asyncio.wait_for(self.hub.registered.wait(), 5)
        qc, _, reg = self.hub.regs[0]
        _, m = await open_to(qc, reg, "8f14e45fceea167a")
        self.assertEqual(m, {"status": 502, "error": pfrelay.REASON_UNREACHABLE})
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_the_serve_forwarder(self):
        async def target(r, w):
            w.write(b"hello from the target")
            await w.drain()
            w.write_eof()
            await r.read()
            w.close()

        server = await asyncio.start_server(target, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        c, _ = client(self.hub)
        task = asyncio.ensure_future(c.serve(f"127.0.0.1:{port}"))
        await asyncio.wait_for(self.hub.registered.wait(), 5)
        qc, _, reg = self.hub.regs[0]
        s, m = await open_to(qc, reg, "8f14e45fceea167a")
        self.assertEqual(m, {"status": 200})
        self.assertEqual(await read_frame(s), (FRAME_DATA, b"hello from the target"))
        self.assertEqual(await read_frame(s), (FRAME_EOF, b""))
        await s.write(encode(FRAME_EOF))
        self.assertIsNone(await asyncio.wait_for(read_frame(s), 5), "FIN after both eofs")
        s.finish()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        server.close()

    async def test_an_end_registers_again(self):
        ups = []
        c, _ = client(self.hub, events=pfrelay.Events(on_serving=ups.append))
        lst = await asyncio.wait_for(c.listen(), 5)
        qc, s, _ = self.hub.regs[0]
        self.hub.registered.clear()
        await s.write(_wire.encode_message({"note": "an unknown message, ignored"}))
        await s.write(_wire.encode_message({"end": "takeover", "error": "another registration of this word took over"}))
        s.finish()
        await asyncio.wait_for(self.hub.registered.wait(), 5)
        self.assertEqual(len(self.hub.regs), 2)
        for _ in range(100):
            if len(ups) >= 3:
                break
            await asyncio.sleep(0.02)
        self.assertEqual(ups[:3], [True, False, True])
        self.assertIsNone(await asyncio.wait_for(read_frame(s), 5), "the client answered the end with FIN")
        await lst.close()

    async def test_close_unregisters(self):
        c, _ = client(self.hub)
        lst = await asyncio.wait_for(c.listen(), 5)
        _, s, _ = self.hub.regs[0]
        await lst.close()
        self.assertIsNone(await asyncio.wait_for(read_frame(s), 5), "unregister is FIN on the serve stream")

    async def test_a_lost_connection_registers_again(self):
        c, t = client(self.hub)
        lst = await asyncio.wait_for(c.listen(), 5)
        self.hub.registered.clear()
        self.hub.regs[0][0].close(_wire.Code.GOING_AWAY)
        await asyncio.wait_for(self.hub.registered.wait(), 5)
        self.assertEqual(len(self.hub.conns), 2)
        await lst.close()


class Keepalive(WithHub):
    async def test_pings_when_nothing_arrives(self):
        _quic.KEEP_ALIVE, old = 1.0, _quic.KEEP_ALIVE
        try:
            c, t = client(self.hub)
            await c.check()
            hub_side = self.hub.conns[0]
            before = hub_side.last_rx
            await asyncio.sleep(1.8)
            self.assertGreater(hub_side.last_rx, before, "the client pinged")
        finally:
            _quic.KEEP_ALIVE = old


class PublicClient(unittest.TestCase):
    def test_is_a_pfrelay_client(self):
        c = pfrelay_quic.Client("https://hub.example", "k3f9-x2mq-7hpa", name="x")
        self.assertIsInstance(c, pfrelay.Client)
        self.assertTrue(c.agent.startswith("pfrelay-quic-py 0.3.0"))
        self.assertEqual(c.transport.name, "QUIC")


if __name__ == "__main__":
    unittest.main()
