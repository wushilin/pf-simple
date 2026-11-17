"""pfrelay-quic: the Python SDK for the pf-simple relay hub over QUIC, tunnel
protocol 3 (docs/PROTOCOL.md section 13 of the pf-simple repository).

It is pfrelay with another way to the hub. The client discovers the hub's
QUIC listener over the hub's HTTPS endpoint, pins its certificate by the
fingerprint that endpoint announced, and carries each request on a stream of
one QUIC connection. Everything else is pfrelay's: the same Conn, Listener,
Events, errors, retries and forwarders. A QUIC side works with a WebSocket
side through the same hub, in either role.

Moving a program from WebSocket to QUIC means making the client here:

    client = pfrelay_quic.Client("https://hub.example.com", "k3f9-x2mq-7hpa")
    conn = await client.dial()

There is no fallback: where UDP is blocked this fails to connect, and
pfrelay (WebSocket) is the one to use.
"""

from __future__ import annotations

import ssl
from typing import Optional

import pfrelay
from pfrelay import (
    LISTEN_BACKLOG,
    REASON_BACKLOG,
    REASON_STOPPED,
    REASON_UNREACHABLE,
    STDIO_TARGET,
    AccessDenied,
    ClosedError,
    Conn,
    ConnID,
    ConnInfo,
    DroppedError,
    Events,
    LinkError,
    Listener,
    PfRelayError,
    ProtoError,
    RemoteError,
    ServerInfo,
    Side,
    Stats,
    StatusError,
    new_word,
    normalize_word,
    split_host_port,
)

from ._quic import IDLE_TIMEOUT, KEEP_ALIVE, fingerprint
from ._transport import ANSWER_WAIT, NO_QUIC, PIN_MISMATCH, PROTO, REQUEST_WAIT, Quic

__version__ = "0.16.2"
DEFAULT_AGENT = f"pfrelay-quic-py {__version__}"


class Client(pfrelay.Client):
    """Talks to one relay hub about one tunnel (one word), over QUIC.

    It is a pfrelay.Client, so it has the same methods: listen, serve, dial,
    connect, connect_one, check, watch, stats, conns, drop. probe asks the
    hub's HTTPS endpoint, as version probes always do. ca_file and
    ssl_context are for that HTTPS endpoint, where the QUIC listener is
    discovered; the listener's own certificate is pinned instead
    (PROTOCOL.md 13.3).

    The settings of the WebSocket protocols (max_proto, leg reuse) do not
    apply. The client keeps one QUIC connection to the hub, made again
    when it is lost; close() closes it.
    """

    def __init__(
        self,
        server: str,
        word: str,
        *,
        ca_file: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        serve_token: str = "",
        client_token: str = "",
        name: str = "",
        target: str = "",
        agent: str = DEFAULT_AGENT,
        events: Optional[Events] = None,
    ):
        self._quic = Quic()
        super().__init__(
            server,
            word,
            ca_file=ca_file,
            ssl_context=ssl_context,
            serve_token=serve_token,
            client_token=client_token,
            name=name,
            target=target,
            agent=agent or DEFAULT_AGENT,
            events=events,
            no_reuse=True,
            transport=self._quic,
        )

    def __repr__(self) -> str:
        return f"<pfrelay_quic.Client {self.base} {self.word[:4]}-…>"

    def close(self) -> None:
        """Close the QUIC connection to the hub (code none), ending what it
        carries. The next request opens a new one."""
        self._quic.close()


__all__ = [
    "__version__",
    "DEFAULT_AGENT",
    "PROTO",
    "IDLE_TIMEOUT",
    "KEEP_ALIVE",
    "ANSWER_WAIT",
    "REQUEST_WAIT",
    "NO_QUIC",
    "PIN_MISMATCH",
    "LISTEN_BACKLOG",
    "REASON_BACKLOG",
    "REASON_STOPPED",
    "REASON_UNREACHABLE",
    "STDIO_TARGET",
    "Client",
    "Events",
    "Listener",
    "Conn",
    "ConnID",
    "ConnInfo",
    "Side",
    "Stats",
    "ServerInfo",
    "PfRelayError",
    "StatusError",
    "AccessDenied",
    "ProtoError",
    "RemoteError",
    "LinkError",
    "ClosedError",
    "DroppedError",
    "fingerprint",
    "new_word",
    "normalize_word",
    "split_host_port",
]
