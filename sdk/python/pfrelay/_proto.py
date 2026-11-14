"""Values, protocol negotiation and errors of the tunnel protocol.

See docs/PROTOCOL.md sections 3 to 5.
"""

from __future__ import annotations

import enum
import json
import re
import secrets
import unicodedata
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlsplit

__all__ = [
    "PROTO_MIN",
    "PROTO_MAX",
    "Feature",
    "PfRelayError",
    "StatusError",
    "AccessDenied",
    "ProtoError",
    "RemoteError",
    "LinkError",
    "ClosedError",
    "DroppedError",
    "ConnID",
    "Side",
    "ServerInfo",
    "new_word",
    "normalize_word",
    "check_serve_token",
    "check_client_token",
    "check_name",
    "proto_range",
    "parse_proto_range",
    "server_proto",
    "error_text",
    "clean_reason",
]

# The protocol versions this SDK speaks. Protocol 1 is sealed; protocol 2
# adds reusing the serving side's accept legs (PROTOCOL.md 12).
PROTO_MIN = 0
PROTO_MAX = 2

# The first pf-simple release that speaks each protocol.
_PROTO_RELEASE = {0: "0.11.0", 1: "0.14.0", 2: "0.15.0"}

API_PATH = "/pf/api/tunnel"

HEADER_PROTO = "X-PF-Tunnel-Proto"
HEADER_VERSION = "X-PF-Version"
HEADER_WORD = "X-PF-Tunnel-Word"
HEADER_SERVE = "X-PF-Serve-Token"
HEADER_NAME = "X-PF-Tunnel-Name"
HEADER_TARGET = "X-PF-Tunnel-Target"
HEADER_CLIENT_HASH = "X-PF-Client-Token-SHA256"
HEADER_CLIENT_TOKEN = "X-PF-Client-Token"
HEADER_CONN = "X-PF-Tunnel-Conn"
HEADER_ERROR = "X-PF-Tunnel-Error"
# Protocol 2: the registration's secret, and the offer to reuse a leg.
HEADER_SESSION = "X-PF-Tunnel-Session"
HEADER_KEEP_ALIVE = "X-PF-Tunnel-Keep-Alive"


class Feature(enum.Enum):
    """Something a request may depend on that not every protocol has."""

    CLIENT_TOKEN = (1, "a client token")
    ANONYMOUS_SERVE = (1, "serving without a serve token")
    # Nothing ever depends on reuse, so no request names it; for the record.
    REUSE = (2, "reusing accept legs")

    @property
    def proto(self) -> int:
        return self.value[0]

    @property
    def label(self) -> str:
        return self.value[1]


# ---------------------------------------------------------------- errors


class PfRelayError(Exception):
    """Base class of the errors this SDK raises."""


class StatusError(PfRelayError):
    """The hub (or a proxy in front of it) refused a request."""

    def __init__(self, code: int, message: str = "", headers: Optional[Mapping[str, str]] = None):
        self.code = code
        self.message = message
        self.headers = dict(headers or {})
        super().__init__(code, message)

    def __str__(self) -> str:
        if self.message:
            return f"{self.message} ({self.code})"
        return f"the server answered {self.code}"

    @property
    def final(self) -> bool:
        """Whether trying again cannot help (PROTOCOL.md section 9)."""
        return 400 <= self.code < 500 and self.code not in (408, 429)


class AccessDenied(StatusError):
    """The hub refused a token or word (403)."""

    def __init__(self, message: str = "", headers: Optional[Mapping[str, str]] = None):
        super().__init__(403, message, headers)

    def __str__(self) -> str:
        return "access denied"


class ProtoError(PfRelayError):
    """The hub is too old for a feature this request depends on.

    Waiting or retrying cannot help: the hub must be upgraded.
    """

    def __init__(self, server: int, need: Feature):
        self.server = server
        self.need = need
        super().__init__(server, need)

    def __str__(self) -> str:
        speaks = f"it speaks tunnel protocol {self.server}"
        if self.server == 0:
            speaks = "it announces no tunnel protocol"
        return (
            f"this server is too old for {self.need.label}: {speaks}, and that needs "
            f"protocol {self.need.proto} (pf-simple {_release_of(self.need.proto)} or later). "
            "Upgrade the server, or do without it"
        )


class RemoteError(PfRelayError):
    """The far end or the hub dropped the stream, and said why."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)

    def __str__(self) -> str:
        return self.reason


class LinkError(PfRelayError, ConnectionError):
    """The link to the hub broke: a lost or silent connection, or the hub
    closing a stream that had not finished."""


class ClosedError(PfRelayError):
    """The connection or listener was closed by this side."""


class DroppedError(PfRelayError):
    """How a connection ended that this side dropped, with Conn.fail or
    Client.drop."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)

    def __str__(self) -> str:
        return f"dropped by this side: {self.reason}"


class ConnID:
    """Names one connection through the tunnel: the id the hub gave it, the
    same on both ends. It is opaque: compare it, hash it, print it with
    str(). ConnID("") names nothing and is falsy."""

    __slots__ = ("_value",)

    def __init__(self, value: str = ""):
        object.__setattr__(self, "_value", str(value))

    def __setattr__(self, name, value):
        raise AttributeError("ConnID is immutable")

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"ConnID({self._value!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ConnID) and other._value == self._value

    def __hash__(self) -> int:
        return hash((ConnID, self._value))

    def __bool__(self) -> bool:
        return bool(self._value)

    @property
    def short(self) -> str:
        """The start of the id, enough to tell connections apart in a log."""
        return self._value[:8]


class Side(str, enum.Enum):
    """Which end of the tunnel a connection belongs to."""

    CONNECT = "connect"  # opened by dial or the connect forwarder
    SERVE = "serve"  # brought in by listen or the serve forwarder

    def __str__(self) -> str:
        return self.value


def _release_of(proto: int) -> str:
    return _PROTO_RELEASE.get(proto, "of a newer release")


# ---------------------------------------------------------------- values

WORD_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_WORD_EXAMPLE = "k3f9-x2mq-7hpa"
_WORD_RE = re.compile(r"[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")


def normalize_word(word: str) -> str:
    """Trim and lower-case a word, and check its form (PROTOCOL.md 3.1)."""
    w = word.strip().lower()
    if not _WORD_RE.fullmatch(w) or not w.isascii():
        raise ValueError(
            "the word must be three groups of four letters or digits, like "
            f"{_WORD_EXAMPLE} (case does not matter)"
        )
    return w


def new_word() -> str:
    """A random word that is easy to read out."""
    groups = ["".join(secrets.choice(WORD_ALPHABET) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)


def _printable_ascii(s: str) -> bool:
    return all(0x21 <= ord(c) <= 0x7E for c in s)


def check_serve_token(token: str) -> None:
    """32 to 128 printable ASCII characters (PROTOCOL.md 3.2)."""
    if len(token) < 32:
        raise ValueError(f"the serve token must be at least 32 characters long (got {len(token)})")
    if len(token) > 128:
        raise ValueError("the serve token must be at most 128 characters long")
    if not _printable_ascii(token):
        raise ValueError("the serve token may only use printable ASCII characters, without spaces")


def check_client_token(token: str) -> None:
    """8 to 128 printable ASCII characters (PROTOCOL.md 3.3)."""
    if len(token) < 8:
        raise ValueError(f"the client token must be at least 8 characters long (got {len(token)})")
    if len(token) > 128:
        raise ValueError("the client token must be at most 128 characters long")
    if not _printable_ascii(token):
        raise ValueError("the client token may only use printable ASCII characters, without spaces")


def check_name(name: str) -> str:
    """1 to 64 characters after trimming, no control characters (3.4)."""
    n = name.strip()
    if not n:
        raise ValueError("give the tunnel a name")
    if len(n) > 64:
        raise ValueError("the tunnel name is longer than 64 characters")
    if any(unicodedata.category(c) == "Cc" for c in n):
        raise ValueError("the tunnel name may not contain control characters")
    return n


def normalize_base(raw: str) -> tuple[str, str, int, str]:
    """Check the hub's base URL. Returns (base, host, port, netloc)."""
    try:
        u = urlsplit(raw.strip())
        host = u.hostname
        port = u.port
    except ValueError:
        raise ValueError(f"invalid server URL {raw!r}: use https://host[:port]/") from None
    if not host or not u.netloc:
        raise ValueError(f"invalid server URL {raw!r}: use https://host[:port]/")
    if u.scheme.lower() != "https":
        raise ValueError(f"invalid server URL {raw!r}: only https:// is supported")
    if u.username is not None or u.password is not None:
        raise ValueError(f"invalid server URL {raw!r}: give the server's address only")
    path = u.path[:-1] if u.path.endswith("/") else u.path
    if path not in ("", "/pf"):
        raise ValueError(
            f"invalid server URL {raw!r}: give the server's address only, like https://{u.netloc}/"
        )
    netloc = u.netloc
    return "https://" + netloc, host, port or 443, netloc


# ---------------------------------------------------------------- negotiation


def proto_range(lo: int, hi: int) -> str:
    """Format a range for X-PF-Tunnel-Proto."""
    return f"{lo}-{hi}"


_RANGE_PART = re.compile(r"[0-9]+")


def parse_proto_range(s: str) -> tuple[int, int]:
    """Read a range as a peer sent it; empty means protocol 0."""
    s = s.strip()
    if not s:
        return 0, 0
    lo, sep, hi = s.partition("-")
    if not sep:
        hi = lo
    if not _RANGE_PART.fullmatch(lo) or not _RANGE_PART.fullmatch(hi):
        raise ValueError(f"invalid tunnel protocol range {s!r}")
    a, b = int(lo), int(hi)
    if b < a or b > 1 << 20:
        raise ValueError(f"invalid tunnel protocol range {s!r}")
    return a, b


_SERVER_PROTO = re.compile(r"[+-]?[0-9]+")


def server_proto(headers: Mapping[str, str]) -> int:
    """The protocol the hub chose, from its answer. None or junk is 0."""
    raw = None
    for k, v in headers.items():
        if k.lower() == HEADER_PROTO.lower():
            raw = v
            break
    if raw is None:
        return 0
    raw = raw.strip()
    if not _SERVER_PROTO.fullmatch(raw):
        return 0
    n = int(raw)
    return n if n >= 0 else 0


def error_text(body: bytes) -> str:
    """The message of a refusal: pf-simple sends {"error": "..."}, a proxy
    in front of it may send anything."""
    body = body[:2048]
    try:
        parsed = json.loads(body.decode("utf-8"))
        if isinstance(parsed, dict) and isinstance(parsed.get(ERROR_FIELD), str) and parsed[ERROR_FIELD]:
            return parsed[ERROR_FIELD]
    except (ValueError, UnicodeDecodeError):
        pass
    text = body.decode("utf-8", "replace").strip()
    if len(text) < 200 and "<" not in text:
        return text
    return ""


def clean_reason(s: str) -> str:
    """Make a reason from the wire safe to show: printable only, at most 200
    characters."""
    out = []
    for c in s:
        if len(out) >= 200:
            break
        if c.isprintable():
            out.append(c)
    return "".join(out)


class Endpoint(str, enum.Enum):
    """The hub's endpoints, under API_PATH (PROTOCOL.md 6)."""

    SERVE = "serve"
    CONNECT = "connect"
    ACCEPT = "accept"
    CHECK = "check"
    VERSION = "version"

    def __str__(self) -> str:
        return self.value

    @property
    def path(self) -> str:
        return f"{API_PATH}/{self.value}"


# The control channel's message (PROTOCOL.md 7): {"open": "<id>"}.
CONTROL_OPEN = "open"
# A refusal's body (PROTOCOL.md 6): {"error": "<message>"}.
ERROR_FIELD = "error"


@dataclass(frozen=True)
class ServerInfo:
    """The answer to a version probe."""

    version: str
    proto_min: int
    proto_max: int
    token: str

    # The answer's field names on the wire.
    FIELD_VERSION = "version"
    FIELD_PROTO_MIN = "protoMin"
    FIELD_PROTO_MAX = "protoMax"
    FIELD_TOKEN = "token"

    def to_dict(self) -> dict:
        """The answer with the wire's field names."""
        return {
            self.FIELD_VERSION: self.version,
            self.FIELD_PROTO_MIN: self.proto_min,
            self.FIELD_PROTO_MAX: self.proto_max,
            self.FIELD_TOKEN: self.token,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ServerInfo":
        """Read the hub's answer; fields this SDK does not know are ignored."""
        return cls(
            version=str(d[cls.FIELD_VERSION]),
            proto_min=int(d.get(cls.FIELD_PROTO_MIN, 0)),
            proto_max=int(d.get(cls.FIELD_PROTO_MAX, 0)),
            token=str(d.get(cls.FIELD_TOKEN, "")),
        )
