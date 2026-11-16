"""A way to reach the hub other than WebSocket, for SDKs built on this one.

pfrelay-quic plugs its QUIC transport (tunnel protocol 3, PROTOCOL.md 13) in
here, with Client(transport=...). The Client keeps everything else:
listeners, the serve forwarder and its retries, reasons, events, stats,
drop and watch, so a program behaves the same on either transport. Only
listen, serve, dial, connect and check go through the transport; probe
stays an HTTPS request (PROTOCOL.md 6.5).

Applications do not implement this. It is a service-provider interface: it
may change with the transports that use it.

A transport hands over each connection as a Stream: a QUIC stream that has
passed its request and answer, carrying protocol 3's frames (PROTOCOL.md
13.5). The client reads and writes the frames itself.

Refusals come back as this package's errors, as over WebSocket: 403 as
AccessDenied, others as StatusError (see refused).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Mapping, Optional, Protocol, runtime_checkable

from . import _ws
from ._proto import AccessDenied, StatusError, error_text

if TYPE_CHECKING:  # pragma: no cover
    from ._client import Client

__all__ = ["Stream", "Open", "Registration", "Transport", "Params", "HttpAnswer", "refused"]


@runtime_checkable
class Stream(Protocol):
    """One stream of the transport after its request and answer, in protocol
    3's frame encoding: what the Client turns into a Conn."""

    async def read(self, n: int) -> bytes:
        """Up to n bytes; b"" once the peer has ended its direction cleanly
        (QUIC's FIN). Raises ConnectionError when the stream or its
        connection was lost or reset."""
        ...

    async def write(self, data: bytes) -> None:
        """Send data, waiting while the transport's flow control holds it
        back. Raises ConnectionError when the stream can take no more."""
        ...

    def finish(self) -> None:
        """End this side's direction cleanly: QUIC's FIN."""
        ...

    def cancel(self) -> None:
        """End both directions at once, giving up on the stream (QUIC: reset,
        "cancelled")."""
        ...

    def broken(self) -> None:
        """End both directions at once because the peer broke the protocol
        (QUIC: reset, "protocol")."""
        ...

    def close(self) -> None:
        """End what is left. After finish, the peer has a short while to end
        its own direction, so that what was sent last is not lost;
        otherwise this is cancel."""
        ...


class Open(Protocol):
    """The hub asking for one connection."""

    @property
    def id(self) -> str:
        """The hub's id for the connection."""
        ...

    async def accept(self) -> Stream:
        """Take the connection: its stream."""
        ...

    async def refuse(self, reason: str) -> None:
        """Tell the hub why this side cannot carry it."""
        ...


class Registration(Protocol):
    """One registration, until it ends."""

    async def next(self) -> Open:
        """Wait for the hub's next request for a connection. Raises why the
        registration ended (a ConnectionError, such as LinkError)."""
        ...

    def close(self) -> None:
        """End the registration; a next() that waits raises."""
        ...


class Transport(Protocol):
    """A way to reach the hub."""

    name: str  # what the transport is called in the log, such as "QUIC"

    async def register(self, p: "Params", target: str) -> Registration:
        """Register the tunnel, returning once it is registered."""
        ...

    async def connect(self, p: "Params") -> tuple[Stream, str]:
        """Open one connection: its stream, and the hub's id for it."""
        ...

    async def check(self, p: "Params") -> None:
        """Ask whether the tunnel can be reached; returns if so."""
        ...

    def close(self) -> None:
        """Release what the transport keeps between requests, such as a QUIC
        connection."""
        ...


class HttpAnswer:
    """An answer of the hub's HTTPS endpoint."""

    def __init__(self, status: int, headers: Mapping[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def error_text(self) -> str:
        """The error of a JSON body, or the body itself, cut short."""
        return error_text(self.body)

    def refusal(self) -> StatusError:
        """The answer as a refusal, as the client words them (PROTOCOL.md 9)."""
        return refused(self.status, self.error_text(), self.headers)


def refused(status: int, message: str, headers: Optional[Mapping[str, str]] = None) -> StatusError:
    """The error of a refused request with this status and the hub's
    message: 403 is AccessDenied, anything else StatusError."""
    if status == 403:
        return AccessDenied(message, headers)
    return StatusError(status, message, headers)


class Params:
    """What a transport needs of the Client, taken at each request."""

    def __init__(self, client: "Client"):
        self._c = client

    @property
    def server(self) -> str:
        """The hub's address, as https://host[:port]."""
        return self._c.base

    @property
    def word(self) -> str:
        """The word, normalized."""
        return self._c.word

    @property
    def serve_token(self) -> str:
        """The serve token; empty to serve anonymously."""
        return self._c.serve_token

    @property
    def client_token(self) -> str:
        """The client token; empty if the tunnel has none."""
        return self._c.client_token

    @property
    def client_token_sha256(self) -> str:
        """The client token's SHA-256 in hex, as serve registers it; empty
        without one."""
        t = self._c.client_token
        return hashlib.sha256(t.encode("ascii")).hexdigest() if t else ""

    @property
    def name(self) -> str:
        """The tunnel's name, as plain UTF-8."""
        return self._c.name

    @property
    def agent(self) -> str:
        """What this program calls itself, for the hub's log."""
        return self._c.agent

    async def get(self, path: str, headers: list[tuple[str, str]]) -> HttpAnswer:
        """A GET of path on the hub's HTTPS endpoint, verified as the
        Client's own requests are. Any answer comes back; only a failure to
        get one raises."""
        c = self._c
        resp = await _ws.http_get(c._host, c._port, c._netloc, c._ssl, path, headers)
        return HttpAnswer(resp.status, resp.headers, resp.body)
