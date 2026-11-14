"""Shared helpers: a fake hub over plain TCP, and a client that goes nowhere."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pfrelay  # noqa: E402
from pfrelay._ws import OP_PING, WebSocket  # noqa: E402

WORD = "k3f9-x2mq-7hpa"
SERVE_TOKEN = "s" * 40


def new_client(**kw) -> pfrelay.Client:
    kw.setdefault("name", "Test")
    c = pfrelay.Client("https://127.0.0.1:1", WORD, **kw)
    c.retry_min, c.retry_max, c.recheck = 0.01, 0.02, 0.02
    return c


class Pair:
    """A client WebSocket and the fake hub's end of the same TCP connection."""

    async def __aenter__(self):
        got = asyncio.get_running_loop().create_future()

        async def on(reader, writer):
            got.set_result((reader, writer))

        self.server = await asyncio.start_server(on, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        self.client = WebSocket(r, w)
        sr, sw = await got
        self.hub = WebSocket(sr, sw, client=False)
        return self

    async def __aexit__(self, *exc):
        self.client.abort()
        self.hub.abort()
        self.server.close()

    async def hub_recv(self, timeout=5):
        return await asyncio.wait_for(self.hub.recv(1 << 21, 1 << 21), timeout)

    async def hub_recv_skip_pings(self, timeout=5):
        while True:
            op, fin, p = await self.hub_recv(timeout)
            if op != OP_PING:
                return op, fin, p


