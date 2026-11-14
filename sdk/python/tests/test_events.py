"""Events, drop, stats and conns, the forwarders, watch and the retry
schedule, against a fake hub."""

import asyncio
import json
import os
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from support import SERVE_TOKEN, Pair, new_client  # noqa: E402

import pfrelay  # noqa: E402
from pfrelay import _forward, _ws  # noqa: E402
from pfrelay._ws import OP_BINARY, OP_CLOSE, OP_TEXT  # noqa: E402

ID = pfrelay.ConnID("0123456789abcdef")


class Recorder:
    """Events, as a list of (name, args)."""

    def __init__(self):
        self.seen = []

    def events(self, *, coroutines=False) -> pfrelay.Events:
        def rec(name):
            if coroutines:
                async def handler(*args):
                    self.seen.append((name, args))
            else:
                def handler(*args):
                    self.seen.append((name, args))
            return handler

        return pfrelay.Events(
            on_serving=rec("serving"),
            on_tunnel=rec("tunnel"),
            on_open=rec("open"),
            on_close=rec("close"),
            on_refuse=rec("refuse"),
        )

    def named(self, name):
        return [args for n, args in self.seen if n == name]


def resp(status, body=b"", **headers):
    h = _ws.Headers()
    for k, v in headers.items():
        dict.__setitem__(h, k.replace("_", "-").lower(), v)
    return _ws.Response(status, "", h, body)


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ConnID(unittest.TestCase):
    def test_value_semantics(self):
        a, b = pfrelay.ConnID("0123456789abcdef"), pfrelay.ConnID("0123456789abcdef")
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertEqual({a: 1}[b], 1)
        self.assertEqual(str(a), "0123456789abcdef")
        self.assertEqual(a.short, "01234567")
        self.assertNotEqual(a, "0123456789abcdef")  # opaque: not a str
        self.assertFalse(pfrelay.ConnID(""))
        with self.assertRaises(AttributeError):
            a._value = "x"


class Events(unittest.IsolatedAsyncioTestCase):
    async def test_open_and_close_once(self):
        for coroutines in (False, True):
            rec = Recorder()
            c = new_client(events=rec.events(coroutines=coroutines))
            async with Pair() as p:
                conn = await c._new_conn(p.client, ID, pfrelay.Side.CONNECT)
                self.assertEqual(len(rec.named("open")), 1)
                info = rec.named("open")[0][0]
                self.assertEqual((info.id, info.side, info.sent), (ID, pfrelay.Side.CONNECT, 0))
                await conn.write(b"abc")
                await p.hub.send(OP_BINARY, b"xy")
                await p.hub.send(OP_TEXT, b"eof")
                self.assertEqual(await conn.read(), b"xy")
                self.assertEqual(await conn.read(), b"")
                closing = asyncio.ensure_future(conn.close())
                while (await p.hub_recv_skip_pings())[0] != OP_CLOSE:
                    pass
                await p.hub.send(OP_CLOSE)
                await closing
                await conn.close()
                await conn.fail("again")
                closes = rec.named("close")
                self.assertEqual(len(closes), 1)
                info, err = closes[0]
                self.assertIsNone(err)
                self.assertEqual((info.sent, info.received, info.wrote_eof, info.read_eof), (3, 2, True, True))

    async def test_failure_is_reported(self):
        rec = Recorder()
        c = new_client(events=rec.events())
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            await p.hub.send(OP_TEXT, b"err:the far end broke")
            with self.assertRaises(pfrelay.RemoteError):
                await conn.read()
            await conn.close()
            [(info, err)] = rec.named("close")
            self.assertIsInstance(err, pfrelay.RemoteError)
            self.assertEqual(c.stats().failed, 1)

    async def test_fail_is_a_dropped_error(self):
        rec = Recorder()
        c = new_client(events=rec.events())
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            await conn.fail("no thanks")
            [(_, err)] = rec.named("close")
            self.assertIsInstance(err, pfrelay.DroppedError)
            self.assertEqual(err.reason, "no thanks")

    async def test_handler_errors_are_contained(self):
        def boom(*_):
            raise RuntimeError("the application's bug")

        c = new_client(events=pfrelay.Events(on_open=boom, on_close=boom))
        async with Pair() as p:
            with self.assertLogs("pfrelay", "ERROR"):
                conn = await c._new_conn(p.client, ID, pfrelay.Side.CONNECT)
            with self.assertLogs("pfrelay", "ERROR"):
                await conn.fail("x")
            self.assertEqual(c.stats().active, 0)


class Drop(unittest.IsolatedAsyncioTestCase):
    async def test_drop(self):
        rec = Recorder()
        c = new_client(events=rec.events())
        async with Pair() as p:
            await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            self.assertFalse(c.drop(pfrelay.ConnID("ffffffffffffffff"), "x"))
            self.assertTrue(c.drop(pfrelay.ConnID(str(ID)), "dropped by the test"))
            self.assertFalse(c.drop(ID, "twice"))
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_TEXT, True, b"err:dropped by the test"))
            self.assertEqual((await p.hub_recv_skip_pings())[0], OP_CLOSE)
            for _ in range(100):
                if rec.named("close"):
                    break
                await asyncio.sleep(0.01)
            [(info, err)] = rec.named("close")
            self.assertEqual(info.id, ID)
            self.assertIsInstance(err, pfrelay.DroppedError)
            self.assertEqual(c.conns(), [])
            self.assertFalse(c.drop(ID, "gone"))


class DroppedIsFailed(unittest.IsolatedAsyncioTestCase):
    async def test_drop_then_quiet_close(self):
        rec = Recorder()
        c = new_client(events=rec.events())
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            await p.hub.send(OP_TEXT, b"eof")
            self.assertEqual(await conn.read(), b"")
            self.assertTrue(c.drop(ID, "dropped by the test"))
            await conn.close()  # before the drop's own task has run
            for _ in range(100):
                if rec.named("close"):
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            [(_, err)] = rec.named("close")
            self.assertIsInstance(err, pfrelay.DroppedError)
            self.assertEqual(c.stats().failed, 1)


class Bookkeeping(unittest.IsolatedAsyncioTestCase):
    async def test_stats_and_conns(self):
        c = new_client()
        async with Pair() as p1, Pair() as p2:
            a = await c._new_conn(p1.client, pfrelay.ConnID("aaaaaaaaaaaaaaaa"), pfrelay.Side.CONNECT)
            await asyncio.sleep(0.01)
            b = await c._new_conn(p2.client, pfrelay.ConnID("bbbbbbbbbbbbbbbb"), pfrelay.Side.SERVE)
            await a.write(b"12345")
            await p2.hub.send(OP_BINARY, b"123")
            self.assertEqual(await b.read(), b"123")
            infos = c.conns()
            self.assertEqual([i.id for i in infos], [a.id, b.id])  # oldest first
            self.assertEqual([i.side for i in infos], [pfrelay.Side.CONNECT, pfrelay.Side.SERVE])
            self.assertEqual([(i.sent, i.received) for i in infos], [(5, 0), (0, 3)])
            self.assertEqual(c.stats(), pfrelay.Stats(opened=2, active=2, failed=0, sent=5, received=3))
            await a.fail("x")
            self.assertEqual(c.stats(), pfrelay.Stats(opened=2, active=1, failed=1, sent=5, received=3))
            self.assertEqual([i.id for i in c.conns()], [b.id])
            await b.close()
            self.assertEqual(c.stats().active, 0)


class Forwarders(unittest.IsolatedAsyncioTestCase):
    async def test_serve_refuses_an_unreachable_target(self):
        rec = Recorder()
        c = new_client(serve_token=SERVE_TOKEN, events=rec.events())
        gets = []

        async def fake_get(host, port, netloc, ctx, path, headers):
            gets.append((path, dict(headers)))
            return resp(204, x_pf_tunnel_proto="1")

        async with Pair() as p:
            async def fake_dial(host, port, netloc, ctx, path, headers):
                self.assertEqual(path, pfrelay.Endpoint.SERVE.path)
                return resp(101, x_pf_tunnel_proto="1"), p.client

            with mock.patch.object(_ws, "ws_dial", fake_dial), mock.patch.object(_ws, "http_get", fake_get):
                task = asyncio.ensure_future(c.serve(f"127.0.0.1:{closed_port()}"))
                for _ in range(200):
                    if rec.named("serving"):
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(rec.named("serving"), [(True,)])
                await p.hub.send(OP_TEXT, json.dumps({"open": str(ID)}).encode())
                await p.hub.send(OP_TEXT, b"not json")  # ignored
                for _ in range(300):
                    if gets:
                        break
                    await asyncio.sleep(0.01)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(rec.named("refuse"), [(ID, pfrelay.REASON_UNREACHABLE)])
        self.assertEqual(rec.named("open"), [])
        [(path, h)] = gets
        self.assertEqual(path, pfrelay.Endpoint.ACCEPT.path)
        self.assertEqual(h["X-PF-Tunnel-Conn"], str(ID))
        self.assertEqual(h["X-PF-Tunnel-Error"], pfrelay.REASON_UNREACHABLE)

    async def test_bridge_carries_both_ways(self):
        rec = Recorder()
        c = new_client(events=rec.events())
        got = asyncio.get_running_loop().create_future()

        async def app(reader, writer):  # the local end: sends, half-closes, reads all
            writer.write(b"ping")
            writer.write_eof()
            got.set_result(await reader.read())
            writer.close()

        server = await asyncio.start_server(app, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            carried = asyncio.ensure_future(_forward.bridge(conn, reader, writer, _forward.PARTY_SERVE))
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_BINARY, True, b"ping"))
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_TEXT, True, b"eof"))
            await p.hub.send(OP_BINARY, b"pong")
            await p.hub.send(OP_TEXT, b"eof")
            self.assertEqual(await asyncio.wait_for(got, 5), b"pong")
            self.assertEqual((await p.hub_recv_skip_pings())[0], OP_CLOSE)
            await p.hub.send(OP_CLOSE)
            ended = await asyncio.wait_for(carried, 5)
            self.assertIsNone(ended.err)
        server.close()
        [(info, err)] = rec.named("close")
        self.assertIsNone(err)
        self.assertEqual((info.sent, info.received), (4, 4))

    async def test_bridge_cancelled_while_closing_closes_the_local_end(self):
        c = new_client()

        async def app(reader, writer):
            writer.write_eof()
            await reader.read()
            writer.close()

        server = await asyncio.start_server(app, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            closing = asyncio.Event()

            async def stuck(err):
                closing.set()
                await asyncio.sleep(100)

            conn._close_with = stuck
            carried = asyncio.ensure_future(_forward.bridge(conn, reader, writer, _forward.PARTY_SERVE))
            await p.hub.send(OP_TEXT, b"eof")
            await asyncio.wait_for(closing.wait(), 5)
            carried.cancel()
            await asyncio.gather(carried, return_exceptions=True)
            self.assertTrue(writer.transport.is_closing())
        server.close()

    async def test_bridge_lets_a_slow_local_end_drain(self):
        # The far end's data, eof and close all arrive while the local end is
        # still reading slowly: nothing may be cut short.
        c = new_client()
        payload = os.urandom(900_000)
        got = asyncio.get_running_loop().create_future()

        async def app(reader, writer):
            writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            writer.write_eof()  # this end finishes first
            await asyncio.sleep(0.5)  # slow to start reading
            data = b""
            while chunk := await reader.read(65536):
                data += chunk
            got.set_result(data)
            writer.close()

        server = await asyncio.start_server(app, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            sock = writer.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            carried = asyncio.ensure_future(_forward.bridge(conn, reader, writer, _forward.PARTY_SERVE))
            self.assertEqual(await p.hub_recv_skip_pings(), (OP_TEXT, True, b"eof"))
            for off in range(0, len(payload), 65536):
                await p.hub.send(OP_BINARY, payload[off:off + 65536])
            await p.hub.send(OP_TEXT, b"eof")
            await p.hub.send(OP_CLOSE)  # the hub ends the stream at once
            ended = await asyncio.wait_for(carried, 30)
            self.assertEqual(len(await asyncio.wait_for(got, 30)), len(payload))
            self.assertIsNone(ended.err, ended.reason)
        server.close()

    async def test_bridge_tells_the_far_end_when_the_local_end_breaks(self):
        c = new_client()

        async def app(reader, writer):
            writer.transport.abort()  # a reset

        server = await asyncio.start_server(app, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await p.hub.send(OP_BINARY, b"x" * 100000)  # writing into a reset socket fails
            ended = await asyncio.wait_for(_forward.bridge(conn, reader, writer, _forward.PARTY_SERVE), 5)
            self.assertIsNotNone(ended.err)
            op, _, payload = await p.hub_recv_skip_pings()
            if payload == b"eof":
                op, _, payload = await p.hub_recv_skip_pings()
            self.assertEqual(op, OP_TEXT)
            self.assertTrue(payload.startswith(b"err:"), payload)
        server.close()


class Watch(unittest.IsolatedAsyncioTestCase):
    async def test_transitions(self):
        rec = Recorder()
        c = new_client(events=rec.events())
        answers = [403, 403, 204, 204, 204, 403, 403, 204]

        async def fake_get(host, port, netloc, ctx, path, headers):
            status = answers.pop(0) if answers else 204
            return resp(status, x_pf_tunnel_proto="1")

        with mock.patch.object(_ws, "http_get", fake_get):
            task = asyncio.ensure_future(c.watch())
            for _ in range(500):
                if not answers:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        seen = rec.named("tunnel")
        self.assertEqual([up for up, _ in seen], [False, True, False, True])
        self.assertIsInstance(seen[0][1], pfrelay.AccessDenied)
        self.assertIsNone(seen[1][1])

    async def test_pauses(self):
        c = new_client()
        c.retry_min, c.retry_max, c.recheck = 0.05, 0.2, 0.3
        times, answers = [], [403, 403, 403, 403, 204, 204]

        async def fake_get(*_):
            times.append(time.monotonic())
            return resp(answers.pop(0) if answers else 204, x_pf_tunnel_proto="1")

        with mock.patch.object(_ws, "http_get", fake_get):
            task = asyncio.ensure_future(c.watch())
            while len(times) < 6:
                await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        gaps = [b - a for a, b in zip(times, times[1:])]
        for gap, want in zip(gaps, [0.05, 0.1, 0.2, 0.2, 0.3]):  # down: doubling to the cap; up: recheck
            self.assertAlmostEqual(gap, want, delta=0.04)


class RetrySchedule(unittest.IsolatedAsyncioTestCase):
    async def test_pauses_double_up_to_the_cap(self):
        c = new_client(serve_token=SERVE_TOKEN)
        c.retry_min, c.retry_max = 0.05, 0.2
        times = []
        answers = [503] * 6 + [403]

        async def fake_dial(*_):
            times.append(time.monotonic())
            return resp(answers.pop(0), x_pf_tunnel_proto="1"), None

        with mock.patch.object(_ws, "ws_dial", fake_dial):
            with self.assertRaises(pfrelay.AccessDenied):  # final while never up
                await asyncio.wait_for(c.listen(), 10)
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertEqual(len(gaps), 6)
        for gap, want in zip(gaps, [0.05, 0.1, 0.2, 0.2, 0.2, 0.2]):
            self.assertAlmostEqual(gap, want, delta=0.04)

    async def test_once_up_refusals_are_retried_and_a_settled_link_resets(self):
        rec = Recorder()
        c = new_client(serve_token=SERVE_TOKEN, events=rec.events())
        c.retry_min, c.retry_max, c.settled = 0.05, 1.0, 0.1
        pairs = []
        times = []
        answers = ["up", 403, 403, "up"]

        async def fake_dial(*_):
            times.append(time.monotonic())
            a = answers.pop(0) if answers else 403
            if a == "up":
                pair = await Pair().__aenter__()
                pairs.append(pair)
                return resp(101, x_pf_tunnel_proto="1"), pair.client
            return resp(a, x_pf_tunnel_proto="1"), None

        with mock.patch.object(_ws, "ws_dial", fake_dial):
            listener = await c.listen()
            self.assertTrue(listener.up)
            await asyncio.sleep(0.15)  # longer than settled
            pairs[0].hub.abort()  # the hub is lost
            while len(pairs) < 2:
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.02)
            self.assertTrue(listener.up)
            await listener.close()
        for p in pairs:
            await p.__aexit__()
        gaps = [b - a for a, b in zip(times, times[1:])]
        # Lost after a settled link: 0.05, then 403s are retried at 0.1, 0.2.
        for gap, want in zip(gaps[1:], [0.1, 0.2]):
            self.assertAlmostEqual(gap, want, delta=0.04)
        self.assertEqual([a for a, in rec.named("serving")][:3], [True, False, True])


class Backlog(unittest.IsolatedAsyncioTestCase):
    async def test_full_backlog_refuses(self):
        rec = Recorder()
        c = new_client(serve_token=SERVE_TOKEN, events=rec.events())
        refusals = []

        async def fake_get(host, port, netloc, ctx, path, headers):
            refusals.append(dict(headers))
            return resp(204, x_pf_tunnel_proto="1")

        async with Pair() as control:
            accepts = []

            async def fake_dial(host, port, netloc, ctx, path, headers):
                if path == pfrelay.Endpoint.SERVE.path:
                    return resp(101, x_pf_tunnel_proto="1"), control.client
                pair = await Pair().__aenter__()
                accepts.append(pair)
                return resp(101, x_pf_tunnel_proto="1"), pair.client

            with mock.patch.object(_ws, "ws_dial", fake_dial), mock.patch.object(
                _ws, "http_get", fake_get
            ), mock.patch("pfrelay._client.LISTEN_BACKLOG", 3):
                listener = await c.listen()
                for i in range(5):
                    await control.hub.send(OP_TEXT, json.dumps({"open": f"{i:016x}"}).encode())
                while len(refusals) < 2:
                    await asyncio.sleep(0.01)
                await asyncio.sleep(0.05)
                self.assertEqual(len(accepts), 3)
                self.assertEqual(len(rec.named("open")), 3)
                self.assertEqual([str(cid) for cid, _ in rec.named("refuse")], [f"{3:016x}", f"{4:016x}"])
                self.assertTrue(all(h["X-PF-Tunnel-Error"] == pfrelay.REASON_BACKLOG for h in refusals))
                first = await listener.accept()
                self.assertEqual(str(first.id), f"{0:016x}")
                await listener.close()  # the two waiting are dropped
                await first.close()
            for pair in accepts:
                await pair.__aexit__()
        self.assertEqual(len(rec.named("close")), 3)


if __name__ == "__main__":
    unittest.main()
