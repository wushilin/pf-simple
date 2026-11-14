"""pfrelay: the Python SDK for the pf-simple relay hub.

Serve a tunnel or connect through one from your own asyncio program. The
protocol is described in docs/PROTOCOL.md of the pf-simple repository.

    client = pfrelay.Client("https://hub.example.com", "k3f9-x2mq-7hpa",
                            serve_token=TOKEN, name="Office SSH")
    listener = await client.listen()
    conn = await listener.accept()
"""

from ._client import DEFAULT_AGENT, LISTEN_BACKLOG, Client, Listener, __version__
from ._conn import ConnInfo, Conn, Stats
from ._proto import (
    PROTO_MAX,
    PROTO_MIN,
    AccessDenied,
    ClosedError,
    Feature,
    LinkError,
    PfRelayError,
    ProtoError,
    RemoteError,
    ServerInfo,
    StatusError,
    check_client_token,
    check_serve_token,
    new_word,
    normalize_word,
    parse_proto_range,
    proto_range,
)

STDIO_TARGET = "stdio"

import logging as _logging

_logging.getLogger("pfrelay").addHandler(_logging.NullHandler())

__all__ = [
    "__version__",
    "DEFAULT_AGENT",
    "LISTEN_BACKLOG",
    "PROTO_MIN",
    "PROTO_MAX",
    "STDIO_TARGET",
    "Client",
    "Listener",
    "Conn",
    "ConnInfo",
    "Stats",
    "ServerInfo",
    "Feature",
    "PfRelayError",
    "StatusError",
    "AccessDenied",
    "ProtoError",
    "RemoteError",
    "LinkError",
    "ClosedError",
    "new_word",
    "normalize_word",
    "check_serve_token",
    "check_client_token",
    "proto_range",
    "parse_proto_range",
]
