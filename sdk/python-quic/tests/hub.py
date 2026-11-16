"""A fake hub's QUIC listener, on aioquic, for the tests: it answers requests
as a test tells it to, and discovery is skipped (TestQuic)."""

from __future__ import annotations

import asyncio
import datetime
import os
import struct
import sys
from typing import Awaitable, Callable, Optional

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_here))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_here)), "python"))

from aioquic.asyncio import serve  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import pfrelay  # noqa: E402
from pfrelay._framed import FRAME_DATA, FRAME_EOF, FRAME_ERR, encode  # noqa: E402
from pfrelay_quic import _quic, _transport, _wire  # noqa: E402
from pfrelay_quic._quic import QConn, QStream  # noqa: E402

WORD = "k3f9-x2mq-7hpa"


def self_signed() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A certificate as the hub makes its own: ECDSA P-256, self-signed."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hub.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=60))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("hub.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


Handler = Callable[["Hub", QConn, QStream, dict], Awaitable[None]]


class Hub:
    """Answers each request with the handler for its op."""

    def __init__(self) -> None:
        self.cert, self.key = self_signed()
        self.fingerprint = _quic.fingerprint(self.cert.public_bytes(Encoding.DER))
        self.conns: list[QConn] = []
        self.requests: list[dict] = []
        self.handlers: dict[str, Handler] = {"check": check_ok, "connect": connect_echo, "serve": serve_ok}
        self.server = None
        self.port = 0
        self.regs: list[tuple[QConn, QStream, str]] = []
        self.registered = asyncio.Event()
        self.transports: list[TestQuic] = []

    async def start(self) -> "Hub":
        cfg = QuicConfiguration(is_client=False, alpn_protocols=[_wire.ALPN], idle_timeout=30.0)
        cfg.certificate, cfg.private_key = self.cert, self.key
        self.server = await serve("127.0.0.1", 0, configuration=cfg, create_protocol=self._protocol)
        self.port = self.server._transport.get_extra_info("sockname")[1]
        return self

    def _protocol(self, quic, stream_handler=None):
        qc = QConn(quic)
        proto = _quic._Protocol(quic, qc)
        qc.proto = proto
        qc.on_open = lambda s: asyncio.ensure_future(self._stream(qc, s))
        self.conns.append(qc)
        return proto

    async def _stream(self, qc: QConn, s: QStream) -> None:
        try:
            req = await _transport.read_message(s)
        except Exception:
            s.cancel()
            return
        self.requests.append(req)
        await self.handlers[req["op"]](self, qc, s, req)

    def close(self) -> None:
        for t in self.transports:
            t.close()
        for qc in self.conns:
            qc.close()
        if self.server is not None:
            self.server.close()


class TestQuic(_transport.Quic):
    """The QUIC transport with discovery answered by the test."""

    def __init__(self, hub: Hub):
        super().__init__()
        self.hub = hub
        self.discoveries = 0
        self.wrong_first = 0  # discoveries that announce another certificate

    async def _discover(self, p, op):
        self.discoveries += 1
        fp = self.hub.fingerprint
        if self.wrong_first > 0:
            self.wrong_first -= 1
            fp = "00" * 32
        return _wire.Discovery("127.0.0.1", self.hub.port, [fp])


def client(hub: Hub, **kw) -> tuple[pfrelay.Client, TestQuic]:
    t = TestQuic(hub)
    hub.transports.append(t)
    kw.setdefault("name", "Test")
    c = pfrelay.Client("https://127.0.0.1:1", WORD, transport=t, **kw)
    c.retry_min, c.retry_max, c.recheck = 0.05, 0.1, 0.05
    return c, t


# ------------------------------------------------------------- answers


async def answer(s: QStream, **m) -> None:
    m.setdefault("proto", 3)
    await s.write(_wire.encode_message(m))


async def check_ok(hub: Hub, qc: QConn, s: QStream, req: dict) -> None:
    await answer(s, status=204)
    s.finish()
    s.close()


async def refuse(s: QStream, status: int, error: str, **extra) -> None:
    await answer(s, status=status, error=error, **extra)
    s.finish()
    s.stop_read(_wire.Code.REFUSED)
    s.close()


async def read_frame(s: QStream) -> Optional[tuple[int, bytes]]:
    head = await _transport._read_exactly(s, 3)
    if not head:
        return None
    typ, n = struct.unpack("!BH", head)
    return typ, await _transport._read_exactly(s, n)


async def echo(s: QStream) -> None:
    """Echo frames back until eof, then eof and FIN."""
    while True:
        f = await read_frame(s)
        if f is None:
            return
        typ, payload = f
        if typ == FRAME_DATA:
            await s.write(encode(FRAME_DATA, payload))
        elif typ == FRAME_EOF:
            await s.write(encode(FRAME_EOF))
            s.finish()
        elif typ == FRAME_ERR:
            s.finish()
            return


async def connect_echo(hub: Hub, qc: QConn, s: QStream, req: dict) -> None:
    await answer(s, status=200, conn="8f14e45fceea167a")
    try:
        await echo(s)
        await read_frame(s)  # the client's FIN
    except ConnectionError:
        pass
    s.close()


async def serve_ok(hub: Hub, qc: QConn, s: QStream, req: dict) -> None:
    reg = f"{len(hub.regs) + 1:016x}"
    await answer(s, status=200, reg=reg)
    hub.regs.append((qc, s, reg))
    hub.registered.set()


async def open_to(qc: QConn, reg: str, oid: str, *, delay_answer: Optional[asyncio.Event] = None) -> tuple[QStream, dict]:
    """Open a stream to the serving side, and read its answer."""
    s = qc.open_stream()
    await s.write(_wire.encode_message({"open": oid, "reg": reg}))
    m = await asyncio.wait_for(_transport.read_message(s), 15)
    return s, m


__all__ = [
    "Hub",
    "TestQuic",
    "client",
    "answer",
    "refuse",
    "read_frame",
    "echo",
    "open_to",
    "WORD",
    "FRAME_DATA",
    "FRAME_EOF",
    "FRAME_ERR",
    "encode",
]
