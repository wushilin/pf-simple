"""No socket outlives cancellation, a stalled peer, or an async event
handler: each case counts what is left open."""

import asyncio
import json
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from support import Pair, new_client  # noqa: E402
from test_reuse import ScriptHub, echo_target  # noqa: E402

import pfrelay  # noqa: E402
from pfrelay import _ws  # noqa: E402
from pfrelay._client import Listener  # noqa: E402
from pfrelay._ws import OP_BINARY, OP_TEXT  # noqa: E402

ID = pfrelay.ConnID("0123456789abcdef")


def fds() -> int:
    return len(os.listdir("/proc/self/fd"))


async def hub_sees_end(ws, within=5.0) -> bool:
    """Whether the hub's end of a WebSocket sees it end (EOF, reset or a
    close) within the time, skipping anything else."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    try:
        while True:
            op, _, _ = await asyncio.wait_for(ws.recv(1 << 21, 1 << 21), max(0.01, deadline - loop.time()))
            if op == _ws.OP_CLOSE:
                return True
    except asyncio.TimeoutError:
        return False
    except Exception:
        return True


async def until(cond, within=5.0):
    for _ in range(int(within / 0.01)):
        if cond():
            return True
        await asyncio.sleep(0.01)
    return cond()


class FakeConnect:
    """ws_dial for connect: every dial is a Pair, kept for the test."""

    def __init__(self):
        self.pairs = []

    async def __call__(self, host, port, netloc, ctx, path, headers):
        pair = await Pair().__aenter__()
        self.pairs.append(pair)
        rh = _ws.Headers()
        dict.__setitem__(rh, "x-pf-tunnel-proto", "2")
        dict.__setitem__(rh, "x-pf-tunnel-conn", f"{len(self.pairs):016x}")
        pair.client.headers = rh
        return _ws.Response(101, "", rh), pair.client

    async def close(self):
        for p in self.pairs:
            await p.__aexit__()


class Leaks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.cleanups = []

    async def asyncTearDown(self):
        for f in reversed(self.cleanups):
            await f()

    # P1
    async def test_cancelled_connect_ends_its_open_connections(self):
        fake = FakeConnect()
        self.cleanups.append(fake.close)
        c = new_client()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.setblocking(False)
        port = sock.getsockname()[1]
        with mock.patch.object(_ws, "ws_dial", fake):
            task = asyncio.ensure_future(c.connect(sock))
            await asyncio.sleep(0.05)
            r, w = await asyncio.open_connection("127.0.0.1", port)
            self.assertTrue(await until(lambda: c.stats().active == 1))
            task.cancel()
            done, _ = await asyncio.wait({task}, timeout=3)
            self.assertTrue(done, "connect() did not stop while a forwarded connection was open")
        self.assertEqual(c.stats().active, 0)
        self.assertTrue(await hub_sees_end(fake.pairs[0].hub))
        self.assertEqual(await asyncio.wait_for(r.read(), 3), b"")  # the local end is closed too
        w.close()
        sock.close()

    # P2
    async def test_accept_cancelled_as_a_connection_arrives_keeps_it(self):
        lst = Listener(new_client())
        t = asyncio.ensure_future(lst.accept())
        await asyncio.sleep(0.02)
        marker = object()
        lst._slots += 1
        lst._queue.put_nowait(marker)  # what Listener._open does
        lst._wake.set()
        t.cancel()  # say, wait_for(listener.accept(), timeout) expiring
        with self.assertRaises(asyncio.CancelledError):
            await t
        self.assertIs(await asyncio.wait_for(lst.accept(), 1), marker)
        self.assertEqual(lst._slots, 0)

    # P3
    async def test_dial_cancelled_in_an_async_on_open(self):
        fake = FakeConnect()
        self.cleanups.append(fake.close)
        entered = asyncio.Event()

        async def on_open(info):
            entered.set()
            await asyncio.sleep(30)

        c = new_client(events=pfrelay.Events(on_open=on_open))
        with mock.patch.object(_ws, "ws_dial", fake):
            t = asyncio.ensure_future(c.dial())
            await asyncio.wait_for(entered.wait(), 5)
            t.cancel()
            await asyncio.gather(t, return_exceptions=True)
        self.assertTrue(await hub_sees_end(fake.pairs[0].hub))
        self.assertTrue(await until(lambda: c.stats().active == 0))

    async def scripted(self):
        hub = ScriptHub()
        patches = [mock.patch.object(_ws, "ws_dial", hub.ws_dial), mock.patch.object(_ws, "http_get", hub.http_get)]
        for p in patches:
            p.start()

        async def stop():
            for p in patches:
                p.stop()
            await hub.close()

        self.cleanups.append(stop)
        return hub

    async def test_serve_cancelled_in_an_async_on_open_closes_the_target(self):
        hub = await self.scripted()
        entered = asyncio.Event()

        async def on_open(info):
            entered.set()
            await asyncio.sleep(30)

        target_ends = []

        async def target(reader, writer):
            target_ends.append(await reader.read())
            writer.close()

        server = await asyncio.start_server(target, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        c = new_client(serve_token="s" * 40, events=pfrelay.Events(on_open=on_open))
        task = asyncio.ensure_future(c.serve(f"127.0.0.1:{port}"))
        ctl = await hub.next_ctl()
        await ctl.send(OP_TEXT, json.dumps({"open": str(ID)}).encode())
        _, _, leg = await hub.next_accept()
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(await until(lambda: target_ends == [b""]), "the target socket was left open")
        self.assertTrue(await hub_sees_end(leg))
        self.assertEqual(c.stats().active, 0)
        server.close()

    async def test_listener_open_cancelled_in_an_async_on_open_frees_its_slot(self):
        hub = await self.scripted()
        entered = asyncio.Event()

        async def on_open(info):
            entered.set()
            await asyncio.sleep(30)

        c = new_client(serve_token="s" * 40, events=pfrelay.Events(on_open=on_open))
        listener = await c.listen()
        ctl = await hub.next_ctl()
        await ctl.send(OP_TEXT, json.dumps({"open": str(ID)}).encode())
        _, _, leg = await hub.next_accept()
        await asyncio.wait_for(entered.wait(), 5)
        await listener.close()  # cancels the open in its handler
        self.assertEqual(listener._slots, 0)
        self.assertTrue(await hub_sees_end(leg))
        self.assertEqual(c.stats().active, 0)

    async def test_refuse_leg_cancelled_in_an_async_on_refuse(self):
        entered = asyncio.Event()

        async def on_refuse(cid, reason):
            entered.set()
            await asyncio.sleep(30)

        c = new_client(events=pfrelay.Events(on_refuse=on_refuse))
        async with Pair() as p:
            t = asyncio.ensure_future(c._refuse_leg(p.client, ID, "no"))
            await asyncio.wait_for(entered.wait(), 5)
            t.cancel()
            await asyncio.gather(t, return_exceptions=True)
            self.assertTrue(await hub_sees_end(p.hub))

    async def test_listen_cancelled_in_an_async_on_serving(self):
        hub = await self.scripted()
        entered = asyncio.Event()

        async def on_serving(up):
            entered.set()
            await asyncio.sleep(30)

        c = new_client(serve_token="s" * 40, events=pfrelay.Events(on_serving=on_serving))
        t = asyncio.ensure_future(c.listen())
        ctl = await hub.next_ctl()
        await asyncio.wait_for(entered.wait(), 5)
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)
        self.assertTrue(await hub_sees_end(ctl), "the control channel was left open")

    # P4
    async def test_fail_cancelled(self):
        c = new_client()
        async with Pair() as p:
            conn = await c._new_conn(p.client, ID, pfrelay.Side.SERVE)

            async def stuck(*a, **kw):
                await asyncio.sleep(30)

            conn._ws.send = stuck
            t = asyncio.ensure_future(conn.fail("bye"))
            await asyncio.sleep(0.05)
            t.cancel()
            await asyncio.gather(t, return_exceptions=True)
            self.assertTrue(await hub_sees_end(p.hub))
            self.assertEqual(c.stats().active, 0)

    async def test_listener_close_cancelled_cuts_the_waiting(self):
        c = new_client()
        lst = Listener(c)
        async with Pair() as p1, Pair() as p2:
            for p, cid in ((p1, "a" * 16), (p2, "b" * 16)):
                conn = await c._new_conn(p.client, pfrelay.ConnID(cid), pfrelay.Side.SERVE)

                async def stuck(*a, **kw):
                    await asyncio.sleep(30)

                conn._ws.send = stuck
                lst._slots += 1
                lst._queue.put_nowait(conn)
            t = asyncio.ensure_future(lst.close())
            await asyncio.sleep(0.05)
            t.cancel()
            await asyncio.gather(t, return_exceptions=True)
            self.assertTrue(await hub_sees_end(p1.hub))
            self.assertTrue(await hub_sees_end(p2.hub))
            self.assertTrue(await until(lambda: c.stats().active == 0))

    # P5
    async def test_close_transport_has_a_deadline(self):
        async with Pair() as p:
            p.client.writer.close = lambda: None  # a close that never finishes (TLS shutdown on 3.10)
            with mock.patch.object(_ws, "CLOSE_TIMEOUT", 0.1):
                p.client.close_transport()
                self.assertTrue(await until(lambda: p.client.writer.transport.is_closing(), 2))

    async def test_close_behind_a_stalled_write(self):
        c = new_client()
        async with Pair() as p:
            p.hub.writer.transport.pause_reading()  # a hub that stops reading
            p.client.writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            conn = await c._new_conn(p.client, ID, pfrelay.Side.CONNECT)

            async def flood():
                try:
                    while True:
                        await conn.write(b"x" * 65536)
                except Exception:
                    pass

            w = asyncio.ensure_future(flood())
            await asyncio.sleep(0.3)
            with mock.patch.object(_ws, "CLOSE_TIMEOUT", 0.3):
                await asyncio.wait_for(conn.close(), 3)
            await asyncio.wait_for(w, 3)
            self.assertEqual(c.stats().active, 0)

    async def test_no_fd_left_after_dial_and_close(self):
        fake = FakeConnect()
        c = new_client()
        before = fds()
        with mock.patch.object(_ws, "ws_dial", fake):
            for _ in range(5):
                conn = await c.dial()
                await conn.fail("done")
        await fake.close()
        await asyncio.sleep(0.1)
        self.assertLessEqual(fds(), before)


if __name__ == "__main__":
    unittest.main()
