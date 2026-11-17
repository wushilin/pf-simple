"""What travels on protocol 3's streams before the frames: the messages
(PROTOCOL.md 13.4), the discovery answer (13.2), and the error codes (13.7)."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

ALPN = "pf-tunnel"  # the one ALPN protocol of the hub's QUIC listener (13.3)
MAX_MESSAGE = 4096  # the longest message, in bytes, after its 2-byte length
END_TAKEOVER = "takeover"  # the end of a registration another serve took over


class Code:
    """Error codes on RESET_STREAM, STOP_SENDING and CONNECTION_CLOSE (13.7).
    They are for logs: nothing is decided from them."""

    NONE = 0x0
    BROKEN = 0x1
    REFUSED = 0x2
    PROTOCOL = 0x3
    REQUEST_TIMEOUT = 0x4
    CANCELLED = 0x5
    GOING_AWAY = 0x6
    LIMIT = 0x7


class MessageFin(Exception):
    """The stream's FIN came before a message began."""


class Malformed(Exception):
    """Too long, cut short, or not a JSON object: the peer broke the
    protocol."""


def encode_message(value: dict) -> bytes:
    """One message: a 2-byte big-endian length, then JSON (plain UTF-8, not
    escaped)."""
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        raise ValueError("a message over 4096 bytes")
    return struct.pack("!H", len(body)) + body


def request(op: str, proto: int, version: str, word: str, **fields: Optional[str]) -> dict:
    """A client's request; fields left None or empty are left out."""
    out: dict[str, Any] = {"op": op, "proto": str(proto)}
    if version:
        out["version"] = version
    if word:
        out["word"] = word
    for k, v in fields.items():
        if v:
            out[k] = v
    return out


def parse_message(body: bytes) -> dict:
    """A message's JSON object."""
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Malformed("a malformed message") from None
    if not isinstance(value, dict):
        raise Malformed("a message that is not a JSON object")
    return value


@dataclass
class Answer:
    """The hub's answer to a request."""

    status: int = 0
    proto: int = 0
    error: str = ""
    reg: str = ""
    conn: str = ""
    scope: str = ""
    retry_after: int = 0

    @classmethod
    def of(cls, m: dict) -> "Answer":
        def s(k: str) -> str:
            v = m.get(k)
            return v if isinstance(v, str) else ""

        def n(k: str) -> int:
            v = m.get(k)
            return v if isinstance(v, int) and not isinstance(v, bool) else 0

        return cls(n("status"), n("proto"), s("error"), s("reg"), s("conn"), s("scope"), n("retryAfter"))


@dataclass
class Discovery:
    """The answer of GET <prefix>/api/tunnel/quic (13.2)."""

    host: str = ""
    port: int = 0
    fingerprints: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, body: bytes) -> "Discovery":
        """Raises ValueError for an answer that is not understood or not
        usable."""
        m = json.loads(body.decode("utf-8"))
        if not isinstance(m, dict):
            raise ValueError("the hub's answer to QUIC discovery is not understood")
        host, port, fps = m.get("host"), m.get("port"), m.get("fingerprints")
        d = cls(
            host if isinstance(host, str) else "",
            port if isinstance(port, int) and not isinstance(port, bool) else 0,
            [f for f in fps if isinstance(f, str)] if isinstance(fps, list) else [],
        )
        d.check()
        return d

    def check(self) -> None:
        if not self.host or any(c in self.host for c in "[]/ "):
            raise ValueError(f"the hub advertised a bad QUIC host {self.host!r}")
        if not 1 <= self.port <= 65535:
            raise ValueError(f"the hub advertised a bad QUIC port {self.port}")
        if not 1 <= len(self.fingerprints) <= 4:
            raise ValueError("the hub advertised no usable certificate fingerprints")
        for f in self.fingerprints:
            if len(f) != 64 or any(c not in "0123456789abcdefABCDEF" for c in f):
                raise ValueError(f"the hub advertised a bad certificate fingerprint {f!r}")

    def pins(self) -> set[bytes]:
        return {bytes.fromhex(f) for f in self.fingerprints}


def clean_text(s: str, limit: int) -> str:
    """Keep printable ASCII, cut to limit, as reasons travel (6.6)."""
    return "".join(c for c in s if " " <= c <= "~")[:limit]


def end_reason(end: str, error: str) -> str:
    """The hub's end of a registration, as the user should read it. Nothing
    is decided from it: every end is followed by registering again."""
    why = clean_text(error, 200) or "the server ended the registration"
    if end == END_TAKEOVER:
        why += " (another serving side registered the same word)"
    return why
