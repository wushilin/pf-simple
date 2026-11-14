"""The serving side's half of reusing accept legs (protocol 2, PROTOCOL.md
12), against a hub whose every frame the test writes. Mirrors
pfrelay/reuse_test.go."""

import asyncio
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from support import Pair, new_client  # noqa: E402

import pfrelay  # noqa: E402
from pfrelay import _ws  # noqa: E402
from pfrelay._ws import OP_BINARY, OP_CLOSE, OP_TEXT  # noqa: E402

SESSION = "0123456789abcdef0123456789abcdef"
ID1, ID2 = "1111111111111111", "2222222222222222"


class ScriptHub:
    """Answers serve and accept as a protocol 2 hub would, and hands the
    hub's ends of the WebSockets to the test."""

    def __init__(self, offer: bool = True):
        self.offer = offer
        self.ctl: asyncio.Queue = asyncio.Queue()
        self.accepts: asyncio.Queue = asyncio.Queue()
        self.refusals = []
        # Held until the test ends, so nothing closes a hub-side socket early.
        self.pairs = []

    async def ws_dial(self, host, port, netloc, ctx, path, headers):
        h = dict(headers)
        pair = await Pair().__aenter__()
        self.pairs.append(pair)
        rh = _ws.Headers()
        dict.__setitem__(rh, "x-pf-tunnel-proto", "2")
        if path == pfrelay.Endpoint.SERVE.path:
            dict.__setitem__(rh, "x-pf-tunnel-session", SESSION)
            await self.ctl.put(pair.hub)
        elif path == pfrelay.Endpoint.ACCEPT.path:
            session = h.get("X-PF-Tunnel-Session", "")
            if self.offer and session == SESSION:
                dict.__setitem__(rh, "x-pf-tunnel-keep-alive", "60")
            await self.accepts.put((h["X-PF-Tunnel-Conn"], session, pair.hub))
        pair.client.headers = rh
        return _ws.Response(101, "", rh), pair.client

    async def http_get(self, host, port, netloc, ctx, path, headers):
        self.refusals.append(dict(headers))
        rh = _ws.Headers()
        dict.__setitem__(rh, "x-pf-tunnel-proto", "2")
        return _ws.Response(204, "", rh)

    async def close(self):
        for p in self.pairs:
            await p.__aexit__()

    async def next_ctl(self):
        return await asyncio.wait_for(self.ctl.get(), 10)

    async def next_accept(self):
        return await asyncio.wait_for(self.accepts.get(), 10)


async def send_open(ctl, cid):
    await ctl.send(OP_TEXT, json.dumps({"open": cid}).encode())


async def exchange(test, leg):
    """One connection from the hub's side against an echo: data, the hub's
    half-close, then the echo and the client's half-close."""
    await leg.send(OP_BINARY, b"hi")
    await leg.send(OP_TEXT, b"eof")
    got = b""
    while True:
        op, _, payload = await asyncio.wait_for(leg.recv(1 << 21, 1 << 21), 10)
        if op == OP_BINARY:
            got += payload
        elif op == OP_TEXT and payload == b"eof":
            break
        elif op == OP_CLOSE:
            test.fail(f"closed after {got!r}")
    test.assertEqual(got, b"hi")


async def expect_text(leg, within):
    """The leg's next text frame; raises if the leg closes or stays silent."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while True:
        op, _, payload = await asyncio.wait_for(leg.recv(1 << 21, 1 << 21), max(0.01, deadline - loop.time()))
        if op == OP_TEXT:
            return payload
        if op == OP_CLOSE:
            raise ConnectionError("closed")


class Recorder:
    def __init__(self):
        self.opened = []
        self.closed = {}

    def install(self, c):
        c.events = pfrelay.Events(on_open=self.on_open, on_close=self.on_close)

    def on_open(self, info):
        self.opened.append(info.id)

    def on_close(self, info, err):
        self.closed.setdefault(str(info.id), []).append(err)

    async def closed_with(self, cid, n=1):
        for _ in range(1000):
            if len(self.closed.get(cid, [])) >= n:
                return self.closed[cid]
            await asyncio.sleep(0.01)
        raise AssertionError(f"connection {cid} closed {len(self.closed.get(cid, []))} times, want {n}")


async def echo_conn(conn):
    try:
        while data := await conn.read():
            await conn.write(data)
        await conn.close_write()
    except pfrelay.PfRelayError:
        pass
    await conn.close()


async def listen_echo(c):
    listener = await c.listen()

    async def loop():
        async for conn in listener:
            asyncio.ensure_future(echo_conn(conn))

    task = asyncio.ensure_future(loop())
    return listener, task


async def echo_target():
    async def handle(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, f"127.0.0.1:{server.sockets[0].getsockname()[1]}"


class ReuseTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hub = ScriptHub()
        self.patches = [
            mock.patch.object(_ws, "ws_dial", self.hub.ws_dial),
            mock.patch.object(_ws, "http_get", self.hub.http_get),
        ]
        for p in self.patches:
            p.start()
        self.cleanups = []

    async def asyncTearDown(self):
        for f in reversed(self.cleanups):
            await f()
        for p in self.patches:
            p.stop()
        await self.hub.close()

    def client(self, **kw):
        c = new_client(serve_token="s" * 40, **kw)
        return c

    async def serve(self, c, mode):
        if mode == "listen":
            listener, task = await listen_echo(c)

            async def stop():
                task.cancel()
                await listener.close()

            self.cleanups.append(stop)
        else:
            server, target = await echo_target()
            task = asyncio.ensure_future(c.serve(target))

            async def stop():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                server.close()

            self.cleanups.append(stop)
        return await self.hub.next_ctl()

    async def keep_leg(self, ctl, cid):
        """Run connection cid on a fresh leg, give the hub's idle, and check
        that the client keeps the leg."""
        await send_open(ctl, cid)
        aid, session, leg = await self.hub.next_accept()
        self.assertEqual((aid, session), (cid, SESSION))
        await exchange(self, leg)
        await leg.send(OP_TEXT, b"idle")
        self.assertEqual(await expect_text(leg, 5), b"idle")
        return leg

    async def test_keeps_and_binds_legs(self):
        for mode in ("listen", "forward"):
            with self.subTest(mode=mode):
                c = self.client()
                ev = Recorder()
                ev.install(c)
                ctl = await self.serve(c, mode)
                leg = await self.keep_leg(ctl, ID1)
                self.assertEqual(await ev.closed_with(ID1), [None])

                # The hub binds the idle leg: answered at once, and carried.
                await leg.send(OP_TEXT, b"bind " + ID2.encode())
                self.assertEqual(await expect_text(leg, 5), b"bound " + ID2.encode())
                await exchange(self, leg)
                await leg.send(OP_TEXT, b"idle")
                self.assertEqual(await expect_text(leg, 5), b"idle")  # kept again
                self.assertEqual(await ev.closed_with(ID2), [None])
                st = c.stats()
                self.assertEqual((st.opened, st.failed, st.active), (2, 0, 0))
                self.assertEqual([str(i) for i in ev.opened], [ID1, ID2])

    async def test_verdict_timeout_and_err(self):
        c = self.client()
        c.verdict_wait = 0.2
        ev = Recorder()
        ev.install(c)
        ctl = await self.serve(c, "listen")

        await send_open(ctl, ID1)
        _, _, leg = await self.hub.next_accept()
        await exchange(self, leg)
        start = time.monotonic()
        with self.assertRaises((ConnectionError, pfrelay.LinkError, asyncio.TimeoutError)):
            await expect_text(leg, 5)  # no text: a close, as protocol 1
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(await ev.closed_with(ID1), [None])

        await send_open(ctl, ID2)
        _, _, leg = await self.hub.next_accept()
        await exchange(self, leg)
        await leg.send(OP_TEXT, b"err:the application side failed")
        await leg.send(OP_CLOSE)
        [err] = await ev.closed_with(ID2)
        self.assertIsInstance(err, pfrelay.RemoteError)
        self.assertEqual(err.reason, "the application side failed")
        self.assertEqual(c.stats().failed, 1)

    async def test_without_offer_nothing_waits(self):
        self.hub.offer = False
        c = self.client()
        ctl = await self.serve(c, "listen")
        await send_open(ctl, ID1)
        _, _, leg = await self.hub.next_accept()
        await exchange(self, leg)
        start = time.monotonic()
        with self.assertRaises((ConnectionError, pfrelay.LinkError, asyncio.TimeoutError)):
            await expect_text(leg, 5)
        self.assertLess(time.monotonic() - start, 1)

    async def test_no_reuse_sends_no_session(self):
        c = self.client(no_reuse=True)
        ctl = await self.serve(c, "listen")
        await send_open(ctl, ID1)
        _, session, _ = await self.hub.next_accept()
        self.assertEqual(session, "")

    async def test_idle_cap_and_registration_loss(self):
        c = self.client(max_idle_legs=1)
        ctl = await self.serve(c, "listen")
        kept = await self.keep_leg(ctl, ID1)

        await send_open(ctl, ID2)
        _, _, leg = await self.hub.next_accept()
        await exchange(self, leg)
        await leg.send(OP_TEXT, b"idle")
        with self.assertRaises((ConnectionError, pfrelay.LinkError, asyncio.TimeoutError)):
            await expect_text(leg, 5)  # over the cap: answered with a close

        ctl.abort()  # the registration ends
        with self.assertRaises((ConnectionError, pfrelay.LinkError, asyncio.TimeoutError)):
            await expect_text(kept, 5)

    async def test_reopened_id_is_a_new_attempt(self):
        c = self.client()
        ev = Recorder()
        ev.install(c)
        ctl = await self.serve(c, "listen")
        leg = await self.keep_leg(ctl, ID1)
        await leg.send(OP_TEXT, b"bind " + ID2.encode())
        self.assertEqual(await expect_text(leg, 5), b"bound " + ID2.encode())
        # The hub never heard bound, and asks again.
        await send_open(ctl, ID2)
        aid, _, leg2 = await self.hub.next_accept()
        self.assertEqual(aid, ID2)
        await exchange(self, leg2)
        await leg2.send(OP_TEXT, b"idle")
        await expect_text(leg2, 5)
        errs = await ev.closed_with(ID2, 2)
        dropped = [e for e in errs if isinstance(e, pfrelay.DroppedError) and e.reason == pfrelay.REASON_LEG_LOST]
        self.assertEqual(len(dropped), 1, errs)
        self.assertEqual(errs.count(None), 1, errs)

    async def test_forwarder_unreachable_after_bound(self):
        c = self.client()
        refused = []
        c.events = pfrelay.Events(on_refuse=lambda cid, reason: refused.append((str(cid), reason)))
        server, target = await echo_target()
        task = asyncio.ensure_future(c.serve(target))

        async def stop():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        self.cleanups.append(stop)
        ctl = await self.hub.next_ctl()
        leg = await self.keep_leg(ctl, ID1)
        server.close()
        await server.wait_closed()
        await leg.send(OP_TEXT, b"bind " + ID2.encode())
        self.assertEqual(await expect_text(leg, 5), b"bound " + ID2.encode())
        msg = await expect_text(leg, 10)
        self.assertTrue(msg.startswith(b"err:"), msg)
        self.assertEqual(refused, [(ID2, pfrelay.REASON_UNREACHABLE)])
        self.assertEqual(self.hub.refusals, [])  # not through accept: the leg is bound

    async def test_idle_in_the_wrong_state_closes_the_leg(self):
        c = self.client()
        ev = Recorder()
        ev.install(c)
        ctl = await self.serve(c, "listen")
        await send_open(ctl, ID1)
        _, _, leg = await self.hub.next_accept()
        await leg.send(OP_TEXT, b"idle")  # while carrying: a violation
        with self.assertRaises((ConnectionError, pfrelay.LinkError, asyncio.TimeoutError)):
            while True:
                await expect_text(leg, 5)
        [err] = await ev.closed_with(ID1)
        self.assertIsNotNone(err)

    async def test_idle_leg_frames(self):
        c = self.client()
        ctl = await self.serve(c, "listen")
        leg = await self.keep_leg(ctl, ID1)
        await leg.send(OP_TEXT, b"something from a later protocol")  # unknown: ignored
        await leg.send(OP_TEXT, b"bind " + ID2.encode())
        self.assertEqual(await expect_text(leg, 5), b"bound " + ID2.encode())
        await exchange(self, leg)
        await leg.send(OP_TEXT, b"idle")
        self.assertEqual(await expect_text(leg, 5), b"idle")  # kept again
        await leg.send(OP_TEXT, b"eof")  # a stream frame on an idle leg: a violation
        with self.assertRaises((ConnectionError, pfrelay.LinkError, asyncio.TimeoutError)):
            await expect_text(leg, 5)

    async def test_idle_leg_gives_its_place_back(self):
        c = self.client(max_idle_legs=1)
        ctl = await self.serve(c, "listen")
        kept = await self.keep_leg(ctl, ID1)
        await kept.send(OP_CLOSE)  # the hub's idle limit closes the leg
        kept.close_transport()
        await asyncio.sleep(0.1)
        await self.keep_leg(ctl, ID2)  # its place is free again

    def test_known_leg_frames(self):
        from pfrelay._client import known_leg_frame

        for known in (b"eof", b"err:x", b"err:", b"idle", b"bind", b"bind ", b"bind 1", b"bound", b"bound 1"):
            self.assertTrue(known_leg_frame(known), known)
        for unknown in (b"binder", b"boundary", b"idler", b"eofs", b"error", b"", b"hello"):
            self.assertFalse(known_leg_frame(unknown), unknown)

    def test_offered(self):
        from pfrelay._client import offered

        def h(**kw):
            rh = _ws.Headers()
            for k, v in kw.items():
                dict.__setitem__(rh, k.replace("_", "-"), v)
            return rh

        self.assertTrue(offered(h(x_pf_tunnel_proto="2", x_pf_tunnel_keep_alive="60")))
        self.assertTrue(offered(h(x_pf_tunnel_proto="2", x_pf_tunnel_keep_alive="3600")))
        for bad in ("0", "3601", "+5", " 5", "5s", "", "٣"):
            self.assertFalse(offered(h(x_pf_tunnel_proto="2", x_pf_tunnel_keep_alive=bad)), bad)
        self.assertFalse(offered(h(x_pf_tunnel_proto="1", x_pf_tunnel_keep_alive="60")))


if __name__ == "__main__":
    unittest.main()
