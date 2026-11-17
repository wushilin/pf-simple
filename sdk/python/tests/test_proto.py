import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pfrelay  # noqa: E402
from pfrelay import _proto  # noqa: E402

SERVE_TOKEN = "s" * 40


class Values(unittest.TestCase):
    def test_normalize_word(self):
        self.assertEqual(pfrelay.normalize_word("  K3F9-x2mq-7HPA\n"), "k3f9-x2mq-7hpa")
        for bad in ["", "k3f9-x2mq", "k3f9x2mq7hpa", "k3f9-x2mq-7hp_", "k3f9-x2mq-7hpaa", "ｋ3f9-x2mq-7hpa"]:
            with self.assertRaises(ValueError, msg=bad):
                pfrelay.normalize_word(bad)

    def test_new_word(self):
        for _ in range(200):
            w = pfrelay.new_word()
            self.assertEqual(pfrelay.normalize_word(w), w)
            self.assertTrue(set(w.replace("-", "")) <= set(_proto.WORD_ALPHABET))

    def test_tokens(self):
        pfrelay.check_serve_token("a" * 32)
        pfrelay.check_serve_token("~" * 128)
        for bad in ["a" * 31, "a" * 129, "a" * 31 + " ", "a" * 31 + "é"]:
            with self.assertRaises(ValueError):
                pfrelay.check_serve_token(bad)
        pfrelay.check_client_token("open-sesame")
        for bad in ["short", "a" * 129, "open sesame"]:
            with self.assertRaises(ValueError):
                pfrelay.check_client_token(bad)

    def test_name(self):
        self.assertEqual(_proto.check_name("  Office SSH "), "Office SSH")
        for bad in ["", "   ", "x" * 65, "a\tb"]:
            with self.assertRaises(ValueError):
                _proto.check_name(bad)

    def test_base(self):
        for raw, prefix in [
            ("https://h", "/pf"),
            ("https://h/", "/pf"),
            ("https://h/pf", "/pf"),
            ("https://h/pf/", "/pf"),
            (" https://h ", "/pf"),
            ("https://h:8443/xzfe-aeeg-e2da/", "/xzfe-aeeg-e2da"),
            ("https://h/a/b.c_d~e-f", "/a/b.c_d~e-f"),
            ("https://h/Hub", "/Hub"),  # case-sensitive
            ("https://h/" + "x" * 64, "/" + "x" * 64),
            ("https://h" + "/abcd" * 40, "/abcd" * 40),  # exactly 200
        ]:
            with self.subTest(raw=raw):
                b = _proto.parse_base(raw)
                self.assertEqual(b.host, "h")
                self.assertIn(b.port, (443, 8443))
                self.assertEqual(b.prefix, prefix)
                self.assertEqual(b.url, "https://" + b.netloc + prefix)
        self.assertEqual(_proto.parse_base("https://h:8443/xzfe-aeeg-e2da/").port, 8443)
        for bad in [
            "http://h",
            "http://h/pf",
            "https://",
            "https:///pf",
            "h:443",
            "https://h/pf?x=1",
            "https://h/?",
            "https://h/pf#top",
            "https://h#",
            "https://u:p@h/",
            "https://u@h/pf",
            "https://h//",
            "https://h//pf",
            "https://h/a//b",
            "https://h/pf//",
            "https://h/.",
            "https://h/..",
            "https://h/a/../b",
            "https://h/a%2Fb",
            "https://h/%70f",
            "https://h/a b",
            "https://h/a\tb",
            "https://h/caf\u00e9",
            "https://h/a+b",
            "https://h/" + "x" * 65,
            "https://h" + "/abcd" * 40 + "/x",  # 202 characters
            "https://h:99999/",
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError) as cm:
                _proto.parse_base(bad)
            self.assertIn("https://host[:port]", str(cm.exception), bad)
        b = _proto.parse_base("https://[::1]:9/")
        self.assertEqual((b.host, b.port, b.netloc, b.prefix), ("::1", 9, "[::1]:9", "/pf"))

    def test_base_paths(self):
        self.assertEqual(_proto.parse_base("https://h").path("serve"), "/pf/api/tunnel/serve")
        b = _proto.parse_base("https://h:8443/xzfe-aeeg-e2da/")
        self.assertEqual(b.path("connect"), "/xzfe-aeeg-e2da/api/tunnel/connect")
        self.assertEqual(b.path("quic"), "/xzfe-aeeg-e2da/api/tunnel/quic")
        self.assertEqual(b.url, "https://h:8443/xzfe-aeeg-e2da")
        self.assertEqual(_proto.Endpoint.ACCEPT.path, "/pf/api/tunnel/accept")

    def test_clean_reason(self):
        self.assertEqual(_proto.clean_reason("a\x00b\nc"), "abc")
        self.assertEqual(len(_proto.clean_reason("x" * 500)), 200)

    def test_error_text(self):
        self.assertEqual(_proto.error_text(b'{"error":"nope"}'), "nope")
        self.assertEqual(_proto.error_text(b"plain words\n"), "plain words")
        self.assertEqual(_proto.error_text(b"<html>proxy</html>"), "")
        self.assertEqual(_proto.error_text(b"x" * 300), "")


class Negotiation(unittest.TestCase):
    def test_ranges(self):
        self.assertEqual(pfrelay.proto_range(0, 1), "0-1")
        self.assertEqual(pfrelay.parse_proto_range(""), (0, 0))
        self.assertEqual(pfrelay.parse_proto_range("1"), (1, 1))
        self.assertEqual(pfrelay.parse_proto_range(" 0-1 "), (0, 1))
        for bad in ["1-0", "a", "-1", "1-", "1_0", "0-99999999"]:
            with self.assertRaises(ValueError, msg=bad):
                pfrelay.parse_proto_range(bad)

    def test_server_proto(self):
        self.assertEqual(_proto.server_proto({}), 0)
        self.assertEqual(_proto.server_proto({"x-pf-tunnel-proto": "1"}), 1)
        self.assertEqual(_proto.server_proto({"X-Pf-Tunnel-Proto": " 2 "}), 2)
        self.assertEqual(_proto.server_proto({"x-pf-tunnel-proto": "one"}), 0)
        self.assertEqual(_proto.server_proto({"x-pf-tunnel-proto": "-3"}), 0)

    def client(self, **kw):
        return pfrelay.Client("https://127.0.0.1:1", "k3f9-x2mq-7hpa", **kw)

    def test_offer(self):
        plain = self.client(serve_token=SERVE_TOKEN)
        self.assertEqual(plain.offer("serve"), "0-2")
        self.assertEqual(plain.offer("connect"), "0-2")
        self.assertEqual(plain.offer("check"), "0-2")
        self.assertEqual(plain.offer("accept"), "0-2")
        self.assertEqual(plain.offer("version"), "0-2")
        anon = self.client()
        self.assertEqual(anon.offer("serve"), "1-2")
        self.assertEqual(anon.offer("connect"), "0-2")
        tok = self.client(serve_token=SERVE_TOKEN, client_token="open-sesame")
        for ep in ("serve", "connect", "check"):
            self.assertEqual(tok.offer(ep), "1-2")
        self.assertEqual(tok.offer("accept"), "0-2")

    def test_max_proto(self):
        one = self.client(serve_token=SERVE_TOKEN, max_proto=1)
        self.assertEqual(one.offer("serve"), "0-1")
        tok = self.client(serve_token=SERVE_TOKEN, client_token="open-sesame", max_proto=1)
        self.assertEqual(tok.offer("connect"), "1-1")
        self.assertEqual(self.client(max_proto=0).offer("connect"), "0-2")
        self.assertEqual(self.client(max_proto=9).offer("connect"), "0-2")
        none = self.client(serve_token=SERVE_TOKEN, max_proto=-1)
        self.assertIsNone(none.offer("serve"))
        h = dict(none._headers(pfrelay.Endpoint.SERVE, []))
        self.assertNotIn("X-PF-Tunnel-Proto", h)
        self.assertNotIn("X-PF-Version", h)
        self.assertEqual(h["X-PF-Tunnel-Word"], "k3f9-x2mq-7hpa")

    def test_answered(self):
        tok = self.client(serve_token=SERVE_TOKEN, client_token="open-sesame")
        with self.assertRaises(pfrelay.ProtoError) as cm:
            tok.answered("check", {})
        self.assertEqual(cm.exception.server, 0)
        self.assertIs(cm.exception.need, pfrelay.Feature.CLIENT_TOKEN)
        self.assertIn("too old for a client token", str(cm.exception))
        tok.answered("check", {"X-PF-Tunnel-Proto": "1"})
        tok.answered("accept", {})
        anon = self.client()
        with self.assertRaises(pfrelay.ProtoError) as cm:
            anon.answered("serve", {"x-pf-tunnel-proto": "0"})
        self.assertIs(cm.exception.need, pfrelay.Feature.ANONYMOUS_SERVE)

    def test_status_final(self):
        self.assertTrue(pfrelay.StatusError(409).final)
        self.assertTrue(pfrelay.StatusError(426).final)
        self.assertFalse(pfrelay.StatusError(429).final)
        self.assertFalse(pfrelay.StatusError(408).final)
        self.assertFalse(pfrelay.StatusError(503).final)
        self.assertIsInstance(pfrelay.AccessDenied(), pfrelay.StatusError)
        self.assertEqual(pfrelay.AccessDenied().code, 403)


if __name__ == "__main__":
    unittest.main()
