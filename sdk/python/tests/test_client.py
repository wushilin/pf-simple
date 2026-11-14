"""Client behavior over a faked handshake layer: refusals, protocol checks,
retries (PROTOCOL.md 5.3, 6, 9)."""

import asyncio
import hashlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pfrelay  # noqa: E402
from pfrelay import _ws  # noqa: E402

SERVE_TOKEN = "s" * 40


def resp(status, body=b"", **headers):
    h = _ws.Headers()
    for k, v in headers.items():
        dict.__setitem__(h, k.replace("_", "-").lower(), v)
    return _ws.Response(status, "", h, body)


class Fake:
    """Answers handshakes from a list; records the requests."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []

    async def __call__(self, host, port, netloc, ctx, path, headers):
        self.requests.append((path, dict(headers)))
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, BaseException):
            raise a
        return a


def client(**kw):
    c = pfrelay.Client("https://127.0.0.1:1/pf", "K3F9-x2mq-7hpa", name="Test", **kw)
    c.retry_min, c.retry_max = 0.01, 0.02
    return c


class Requests(unittest.IsolatedAsyncioTestCase):
    async def test_dial_headers_and_403(self):
        fake = Fake([(resp(403, b'{"error":"denied"}', x_pf_tunnel_proto="1"), None)])
        c = client(client_token="open-sesame")
        with mock.patch.object(_ws, "ws_dial", fake):
            with self.assertRaises(pfrelay.AccessDenied):
                await c.dial()
        path, h = fake.requests[0]
        self.assertEqual(path, "/pf/api/tunnel/connect")
        self.assertEqual(h["X-PF-Tunnel-Word"], "k3f9-x2mq-7hpa")
        self.assertEqual(h["X-PF-Tunnel-Proto"], "1-2")
        self.assertEqual(h["X-PF-Client-Token"], "open-sesame")
        self.assertTrue(h["X-PF-Version"].startswith("pfrelay-py"))

    async def test_protocol_0_refusal_is_a_proto_error(self):
        # A protocol 0 hub ignores the client token, and may refuse for it.
        fake = Fake([(resp(403), None)])
        with mock.patch.object(_ws, "ws_dial", fake):
            with self.assertRaises(pfrelay.ProtoError):
                await client(client_token="open-sesame").dial()

    async def test_404_is_not_checked(self):
        fake = Fake([(resp(404), None)])
        with mock.patch.object(_ws, "ws_dial", fake):
            with self.assertRaises(pfrelay.StatusError) as cm:
                await client(client_token="open-sesame").dial()
        self.assertEqual(cm.exception.code, 404)
        self.assertIn("does not accept tunnels", str(cm.exception))

    async def test_check(self):
        fake = Fake([resp(204, x_pf_tunnel_proto="1")])
        with mock.patch.object(_ws, "http_get", fake):
            await client().check()
        fake = Fake([resp(204)])  # protocol 0 hub, client token needed
        with mock.patch.object(_ws, "http_get", fake):
            with self.assertRaises(pfrelay.ProtoError):
                await client(client_token="open-sesame").check()
        fake = Fake([resp(403, x_pf_tunnel_proto="1")])
        with mock.patch.object(_ws, "http_get", fake):
            with self.assertRaises(pfrelay.AccessDenied):
                await client().check()

    async def test_probe(self):
        body = b'{"version":"0.14.0","protoMin":0,"protoMax":1,"token":"alice","new":true}'
        fake = Fake([resp(200, body, x_pf_tunnel_proto="1")])
        with mock.patch.object(_ws, "http_get", fake):
            info = await client(serve_token=SERVE_TOKEN).probe()
        self.assertEqual(info, pfrelay.ServerInfo("0.14.0", 0, 1, "alice"))
        self.assertEqual(fake.requests[0][1]["X-PF-Serve-Token"], SERVE_TOKEN)
        self.assertNotIn("X-PF-Tunnel-Word", fake.requests[0][1])
        fake = Fake([resp(403, x_pf_tunnel_proto="1")])
        with mock.patch.object(_ws, "http_get", fake):
            with self.assertRaises(pfrelay.AccessDenied):
                await client(serve_token=SERVE_TOKEN).probe()


class Listening(unittest.IsolatedAsyncioTestCase):
    async def test_first_refusal_is_final(self):
        for status, exc in ((403, pfrelay.AccessDenied), (409, pfrelay.StatusError), (426, pfrelay.StatusError)):
            fake = Fake([(resp(status, b'{"error":"why"}', x_pf_tunnel_proto="1"), None)])
            with mock.patch.object(_ws, "ws_dial", fake):
                with self.assertRaises(exc):
                    await client(serve_token=SERVE_TOKEN).listen()
            self.assertEqual(len(fake.requests), 1)

    async def test_anonymous_on_protocol_0(self):
        fake = Fake([(resp(403), None)])
        with mock.patch.object(_ws, "ws_dial", fake):
            with self.assertRaises(pfrelay.ProtoError):
                await client().listen()
        self.assertEqual(fake.requests[0][1]["X-PF-Tunnel-Proto"], "1-2")
        self.assertNotIn("X-PF-Serve-Token", fake.requests[0][1])

    async def test_transient_failures_are_retried(self):
        fake = Fake(
            [
                OSError("connection refused"),
                (resp(503, b'{"error":"busy"}', x_pf_tunnel_proto="1"), None),
                (resp(429, x_pf_tunnel_proto="1"), None),
                (resp(403, x_pf_tunnel_proto="1"), None),
            ]
        )
        with mock.patch.object(_ws, "ws_dial", fake):
            with self.assertRaises(pfrelay.AccessDenied):
                await asyncio.wait_for(client(serve_token=SERVE_TOKEN).listen(), 5)
        self.assertEqual(len(fake.requests), 4)
        _, h = fake.requests[0]
        self.assertEqual(h["X-PF-Tunnel-Name"], "Test")
        self.assertEqual(h["X-PF-Tunnel-Target"], "listener")
        self.assertEqual(h["X-PF-Tunnel-Proto"], "0-2")

    async def test_client_token_hash(self):
        fake = Fake([(resp(409, x_pf_tunnel_proto="1"), None)])
        with mock.patch.object(_ws, "ws_dial", fake):
            with self.assertRaises(pfrelay.StatusError):
                await client(serve_token=SERVE_TOKEN, client_token="open-sesame").listen()
        h = fake.requests[0][1]
        self.assertEqual(h["X-PF-Client-Token-SHA256"], hashlib.sha256(b"open-sesame").hexdigest())
        self.assertNotIn("X-PF-Client-Token", h)

    async def test_name_required(self):
        c = pfrelay.Client("https://127.0.0.1:1", "k3f9-x2mq-7hpa", serve_token=SERVE_TOKEN)
        with self.assertRaises(ValueError):
            await c.listen()


if __name__ == "__main__":
    unittest.main()
