"""The client of the relay hub: serve a tunnel (listen/accept, or the serve
forwarder) or connect through one (dial, or the connect forwarder), plus
check, watch and probe. Mirrors the Go SDK, pfrelay."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Union
from urllib.parse import quote_plus

from . import _ws
from ._conn import Conn, ConnInfo, Stats, _Registry, emit
from ._forward import PARTY_CONNECT, PARTY_SERVE, bridge
from ._proto import (
    CONTROL_OPEN,
    HEADER_CLIENT_HASH,
    HEADER_CLIENT_TOKEN,
    HEADER_CONN,
    HEADER_ERROR,
    HEADER_NAME,
    HEADER_PROTO,
    HEADER_SERVE,
    HEADER_TARGET,
    HEADER_VERSION,
    HEADER_WORD,
    PROTO_MAX,
    PROTO_MIN,
    AccessDenied,
    ClosedError,
    ConnID,
    Endpoint,
    Feature,
    LinkError,
    ProtoError,
    ServerInfo,
    Side,
    StatusError,
    check_client_token,
    check_name,
    check_serve_token,
    error_text,
    normalize_base,
    normalize_word,
    proto_range,
    server_proto,
)
from ._ws import OP_CLOSE, OP_PING, OP_PONG, OP_TEXT, WebSocket

__version__ = "0.1.0"
DEFAULT_AGENT = f"pfrelay-py {__version__}"

log = logging.getLogger("pfrelay")

CONTROL_PING = 20.0
CONTROL_SILENCE = 60.0
MAX_CONTROL_FRAME = 4096
LISTEN_BACKLOG = 128
TARGET_DIAL_TIMEOUT = 5.0
LISTENER_TARGET = "listener"  # what listen() tells the console without a target

# Reasons this side gives the far end when it refuses a connection.
REASON_BACKLOG = "the serving side is not accepting connections fast enough"
REASON_UNREACHABLE = "the serving side could not reach its target"
REASON_STOPPED = "the serving side stopped listening"

_NO_RELAY = "this server does not accept tunnels (it needs --tunnel or a [tunnel] table)"
_NO_PROBE = (
    "this server does not answer a version probe: it is older than pf-simple 0.14.0, or its relay hub is off"
)

_TRANSIENT = (OSError, ConnectionError, ssl.SSLError, LinkError, asyncio.TimeoutError)

Handler = Optional[Callable[..., Union[Any, Awaitable[Any]]]]


def _clean_header(s: str, limit: int = 200) -> str:
    return "".join(c for c in s if " " <= c <= "~")[:limit]


def split_host_port(addr: str) -> tuple[str, int]:
    """'host:port' or '[v6]:port' as (host, port)."""
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit() or not host:
        raise ValueError(f"invalid address {addr!r}: use host:port")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def explain(err: BaseException) -> BaseException:
    """Turn the hub's refusals into something to act on (PROTOCOL.md 9)."""
    if not isinstance(err, StatusError) or isinstance(err, AccessDenied):
        return err
    if err.code == 403:
        return AccessDenied(err.message, err.headers)
    if err.code == 404 and not err.message:
        return StatusError(404, _NO_RELAY, err.headers)
    return err


@dataclass
class Events:
    """Handlers a Client calls as things happen. Each one left None (the
    default) is not called. They are called in the task where the event
    happened; a plain function is called, a coroutine function is awaited,
    so a handler should return quickly. One that raises is logged.

    on_serving(up): listen or serve registered with the hub (True), or lost
        that registration (False).
    on_tunnel(up, err): watch found the tunnel reachable (True, None) or not
        (False, why); called with the first result and on every change.
    on_open(info): a connection was opened: dialed, brought in for listen,
        or carried by a forwarder.
    on_close(info, err): a connection ended, exactly once for each on_open,
        with its final figures; err is None after a clean finish.
    on_refuse(id, reason): this side refused a connection the hub offered
        (backlog full, target unreachable). A refused one is never opened.
    """

    on_serving: Handler = None
    on_tunnel: Handler = None
    on_open: Handler = None
    on_close: Handler = None
    on_refuse: Handler = None


class Client:
    """Talks to one relay hub about one tunnel (one word).

    It can serve the tunnel (listen, serve) or connect through it (dial,
    connect, check, watch).
    """

    # Timing (PROTOCOL.md 9); class attributes, so tests can shorten them.
    retry_min = 1.0  # a failed attempt is retried after this, doubling...
    retry_max = 30.0  # ...up to this
    settled = 60.0  # a control channel this old starts the pause again
    recheck = 30.0  # watch checks a tunnel that is up this often

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
        self.base, self._host, self._port, self._netloc = normalize_base(server)
        self.word = normalize_word(word)
        if serve_token:
            check_serve_token(serve_token)
        if client_token:
            check_client_token(client_token)
        if name:
            name = check_name(name)
        self.serve_token = serve_token
        self.client_token = client_token
        self.name = name
        self.target = target
        self.agent = _clean_header(agent or DEFAULT_AGENT, 128) or DEFAULT_AGENT
        self.events = events if events is not None else Events()
        if ssl_context is None:
            ssl_context = ssl.create_default_context(cafile=ca_file)
        elif ca_file:
            ssl_context.load_verify_locations(cafile=ca_file)
        ssl_context.set_alpn_protocols(["http/1.1"])
        self._ssl = ssl_context
        self._reg = _Registry()
        self._drops: set[asyncio.Task] = set()

    def __repr__(self) -> str:
        return f"<pfrelay.Client {self.base} {self.word[:4]}-…>"

    # ---------------------------------------------------------- negotiation

    def needs(self, endpoint: Union[Endpoint, str]) -> list[Feature]:
        """What a request to endpoint depends on beyond protocol 0."""
        endpoint = Endpoint(endpoint)
        out: list[Feature] = []
        if endpoint is Endpoint.SERVE:
            if self.client_token:
                out.append(Feature.CLIENT_TOKEN)
            if not self.serve_token:
                out.append(Feature.ANONYMOUS_SERVE)
        elif endpoint in (Endpoint.CONNECT, Endpoint.CHECK):
            if self.client_token:
                out.append(Feature.CLIENT_TOKEN)
        return out

    def offer(self, endpoint: Union[Endpoint, str]) -> str:
        """The protocol range a request to endpoint offers."""
        lo = PROTO_MIN
        for f in self.needs(endpoint):
            lo = max(lo, f.proto)
        return proto_range(lo, PROTO_MAX)

    def answered(self, endpoint: Union[Endpoint, str], headers) -> None:
        """Raise ProtoError when the hub's answer shows it is too old for
        something the request depends on."""
        proto = server_proto(headers)
        for f in self.needs(endpoint):
            if proto < f.proto:
                raise ProtoError(proto, f)

    def _headers(self, endpoint: Endpoint, extra: list[tuple[str, str]]) -> list[tuple[str, str]]:
        h = [(HEADER_PROTO, self.offer(endpoint)), (HEADER_VERSION, self.agent)]
        if endpoint is not Endpoint.VERSION:
            h.append((HEADER_WORD, self.word))
        return h + extra

    def _connect_extra(self) -> list[tuple[str, str]]:
        if self.client_token:
            return [(HEADER_CLIENT_TOKEN, self.client_token)]
        return []

    # ---------------------------------------------------------- requests

    async def _dial(self, endpoint: Endpoint, extra: list[tuple[str, str]]) -> WebSocket:
        resp, ws = await _ws.ws_dial(
            self._host, self._port, self._netloc, self._ssl, endpoint.path, self._headers(endpoint, extra)
        )
        if ws is not None:
            try:
                self.answered(endpoint, resp.headers)
            except ProtoError:
                ws.abort()
                raise
            return ws
        if resp.status != 404:  # 404: no hub there to be old
            self.answered(endpoint, resp.headers)
        raise StatusError(resp.status, error_text(resp.body), resp.headers)

    async def _get(self, endpoint: Endpoint, extra: list[tuple[str, str]]) -> _ws.Response:
        resp = await _ws.http_get(
            self._host, self._port, self._netloc, self._ssl, endpoint.path, self._headers(endpoint, extra)
        )
        if resp.status != 404:
            self.answered(endpoint, resp.headers)
        if resp.status // 100 != 2:
            raise StatusError(resp.status, error_text(resp.body), resp.headers)
        return resp

    async def check(self) -> None:
        """Ask the hub whether someone serves this word (and the client
        token, if one is needed, is right). Raises AccessDenied if not."""
        try:
            await self._get(Endpoint.CHECK, self._connect_extra())
        except StatusError as e:
            raise explain(e) from None

    async def probe(self) -> ServerInfo:
        """The hub's version and the protocols it speaks. Needs a valid
        serve token."""
        resp = await _ws.http_get(
            self._host,
            self._port,
            self._netloc,
            self._ssl,
            Endpoint.VERSION.path,
            self._headers(Endpoint.VERSION, [(HEADER_SERVE, self.serve_token)]),
        )
        if resp.status == 404:
            raise StatusError(404, _NO_PROBE, resp.headers)
        if resp.status // 100 != 2:
            raise explain(StatusError(resp.status, error_text(resp.body), resp.headers))
        try:
            info = ServerInfo.from_dict(json.loads(resp.body.decode("utf-8")))
            if not info.version:
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
            raise LinkError("the server's answer to the version probe is not understood") from None
        return info

    async def watch(self) -> None:
        """Check, until cancelled, whether the tunnel can be reached.

        events.on_tunnel hears the first result and then every change. A
        tunnel that is up is checked every 30 seconds; one that is down
        sooner, from 1 second doubling to 30. It is for the connecting side,
        which keeps going either way: connections are refused while the
        tunnel is away."""
        backoff, up, first = self.retry_min, False, True
        while True:
            err: Optional[BaseException] = None
            try:
                await self.check()
            except (StatusError, ProtoError, *_TRANSIENT) as e:
                err = e
            now_up = err is None
            if first or now_up != up:
                if now_up:
                    log.info("the tunnel is up")
                else:
                    log.info("the tunnel is not available (%s)", err)
                await emit(self.events.on_tunnel, now_up, err)
            if now_up:
                wait, backoff = self.recheck, self.retry_min
            else:
                wait, backoff = backoff, min(backoff * 2, self.retry_max)
            up, first = now_up, False
            await asyncio.sleep(wait)

    # ---------------------------------------------------------- connecting

    async def dial(self) -> Conn:
        """Open one connection through the tunnel.

        The hub answers before the serving side has: if the serving side
        cannot be reached, or cannot reach its target, the first read raises
        a RemoteError saying so."""
        try:
            ws = await self._dial(Endpoint.CONNECT, self._connect_extra())
        except StatusError as e:
            raise explain(e) from None
        return await self._new_conn(ws, ConnID(ws.headers.get(HEADER_CONN, "")), Side.CONNECT)

    async def connect_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Forward one local connection through the tunnel, both ways, until
        both directions finish. Raises why it ended badly: the dial's error,
        or what broke the connection. Its signature fits
        asyncio.start_server, but connect() is usually what you want."""
        try:
            conn = await self.dial()
        except BaseException:
            writer.transport.abort()
            raise
        ended = await bridge(conn, reader, writer, PARTY_CONNECT)
        log.info("connection %s closed: %s", conn.id.short, ended.reason)
        if ended.err is not None:
            raise ended.err

    async def connect(self, sock: socket.socket) -> None:
        """Forward every connection accepted on sock, a listening TCP socket,
        through the tunnel, until cancelled. Each one opens its own
        connection through the tunnel; a refused one is closed at once."""
        handlers: set[asyncio.Task] = set()

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:
                handlers.add(task)
            try:
                await self.connect_one(reader, writer)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.info("connection from %s: %s", writer.get_extra_info("peername"), explain(e))
            finally:
                if task is not None:
                    handlers.discard(task)

        server = await asyncio.start_server(handle, sock=sock)
        try:
            await server.serve_forever()
        finally:
            server.close()
            for t in list(handlers):
                t.cancel()
            if handlers:
                await asyncio.gather(*handlers, return_exceptions=True)

    # ---------------------------------------------------------- serving

    async def listen(self) -> "Listener":
        """Register the tunnel and return once it is registered.

        A refusal that waiting cannot cure (403 AccessDenied, another final
        4xx as StatusError, a hub too old for what was asked as ProtoError)
        is raised; anything else is retried with a growing pause. Bound the
        wait with asyncio.wait_for if needed."""
        if not self.name:
            raise ValueError("give the tunnel a name")
        lst = Listener(self)
        try:
            await lst._start()
        except BaseException:
            await lst.close()
            raise
        return lst

    async def serve(self, target: str) -> None:
        """Offer target, a TCP host:port, to whoever connects, until
        cancelled. It raises only when the hub refuses the first
        registration for a reason that waiting cannot cure, or is too old;
        everything else is retried with a growing pause.

        For each connection it dials the target first; if that fails it
        refuses the connection with a reason (events.on_refuse), so the
        connecting side hears it on its first read."""
        if not self.name:
            raise ValueError("give the tunnel a name")
        host, port = split_host_port(target)

        async def open_one(cid: ConnID) -> None:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TARGET_DIAL_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                log.warning("connection %s refused: cannot reach the target %s: %s", cid.short, target, e)
                await self._refuse(cid, REASON_UNREACHABLE)
                return
            try:
                ws = await self._dial(Endpoint.ACCEPT, [(HEADER_CONN, str(cid))])
            except Exception as e:
                log.warning("connection %s failed: cannot bring it to the server: %s", cid.short, explain(e))
                writer.transport.abort()
                return
            except BaseException:
                writer.transport.abort()
                raise
            conn = await self._new_conn(ws, cid, Side.SERVE)
            ended = await bridge(conn, reader, writer, PARTY_SERVE)
            log.info("connection %s closed: %s", cid.short, ended.reason)

        reg = _Registration(self, target, open_one, lambda up: None)
        await reg.run()

    # ---------------------------------------------------------- bookkeeping

    def stats(self) -> Stats:
        """This client's totals, open connections included."""
        return self._reg.stats()

    def conns(self) -> list[ConnInfo]:
        """This client's open connections, oldest first."""
        return self._reg.conns()

    def drop(self, conn_id: ConnID, reason: str) -> bool:
        """End the open connection conn_id and tell the far end reason, as
        Conn.fail does; it ends with a DroppedError. Returns whether such a
        connection was open. It is a plain function, so that a sync event
        handler may call it: the failure is sent in a task of its own, and
        on_close follows once it has gone out."""
        conn = self._reg.find(conn_id)
        if conn is None or conn._done or conn._dropping:
            return False
        conn._dropping = True
        task = asyncio.ensure_future(conn.fail(reason))
        self._drops.add(task)
        task.add_done_callback(self._drops.discard)
        return True

    async def _new_conn(self, ws: WebSocket, cid: ConnID, side: Side) -> Conn:
        conn = Conn(ws, cid, side, self)
        self._reg.add(conn)
        await emit(self.events.on_open, conn.info())
        return conn

    async def _conn_closed(self, conn: Conn, err: Optional[BaseException]) -> None:
        if self._reg.finish(conn, err is not None):
            await emit(self.events.on_close, conn.info(), err)

    async def _refuse(self, cid: ConnID, reason: str) -> None:
        await emit(self.events.on_refuse, cid, reason)
        try:
            await self._get(Endpoint.ACCEPT, [(HEADER_CONN, str(cid)), (HEADER_ERROR, _clean_header(reason, 128))])
        except Exception as e:
            log.info("connection %s: could not tell the server: %s", cid.short, explain(e))


class _Registration:
    """Keeps a tunnel registered and calls open_one, in a task of its own,
    for each connection the hub asks for."""

    def __init__(
        self,
        client: Client,
        target: str,
        open_one: Callable[[ConnID], Awaitable[None]],
        on_up: Callable[[bool], None],
    ):
        self._c = client
        self._target = target
        self._open_one = open_one
        self._on_up = on_up
        self._opens: set[asyncio.Task] = set()
        self.control: Optional[WebSocket] = None

    async def run(self) -> None:
        try:
            await self._loop()
        finally:
            for t in list(self._opens):
                t.cancel()
            if self._opens:
                await asyncio.gather(*self._opens, return_exceptions=True)

    async def _loop(self) -> None:
        c = self._c
        extra = [(HEADER_TARGET, _clean_header(self._target)), (HEADER_NAME, quote_plus(c.name))]
        if c.serve_token:
            extra.append((HEADER_SERVE, c.serve_token))
        if c.client_token:
            extra.append((HEADER_CLIENT_HASH, hashlib.sha256(c.client_token.encode("ascii")).hexdigest()))
        backoff, served, attempt = c.retry_min, False, 0
        while True:
            attempt += 1
            try:
                ws = await c._dial(Endpoint.SERVE, extra)
            except ProtoError:
                raise  # the hub cannot do what was asked: waiting will not change it
            except StatusError as e:
                if not served and e.final:
                    raise explain(e) from None
                log.warning(
                    "cannot register with %s (%s); attempt %d, trying again in %gs",
                    c.base, explain(e), attempt, backoff,
                )
            except _TRANSIENT as e:
                log.warning(
                    "cannot register with %s (%s); attempt %d, trying again in %gs", c.base, e, attempt, backoff
                )
            else:
                if served:
                    log.info("registered again with %s after %d attempt(s)", c.base, attempt)
                else:
                    log.info("registered with %s: serving %r", c.base, c.name)
                served, attempt = True, 0
                started = time.monotonic()
                self._on_up(True)
                await emit(c.events.on_serving, True)
                try:
                    err = await self._control(ws)
                finally:
                    self._on_up(False)
                await emit(c.events.on_serving, False)
                if time.monotonic() - started >= c.settled:
                    backoff = c.retry_min
                log.warning("lost the server (%s); its connections are closed; registering again in %gs", err, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, c.retry_max)

    async def _control(self, ws: WebSocket) -> BaseException:
        """Run one control channel until it fails; returns why."""
        self.control = ws
        ws.start_keepalive(CONTROL_PING, CONTROL_SILENCE)
        try:
            while True:
                op, _fin, payload = await ws.recv(MAX_CONTROL_FRAME, MAX_CONTROL_FRAME)
                if op == OP_TEXT:
                    cid = _open_message(payload)
                    if cid:
                        t = asyncio.ensure_future(self._open_one(cid))
                        self._opens.add(t)
                        t.add_done_callback(self._opens.discard)
                elif op == OP_PING:
                    try:
                        await ws.send(OP_PONG, payload, timeout=_ws.WRITE_TIMEOUT)
                    except (ConnectionError, OSError) as e:
                        return e
                elif op == OP_CLOSE:
                    try:
                        await ws.send(OP_CLOSE, payload[:2], timeout=_ws.CLOSE_TIMEOUT)
                    except (ConnectionError, OSError):
                        pass
                    return LinkError("the server closed the control channel")
        except (ConnectionError, OSError, LinkError) as e:
            return e
        except asyncio.CancelledError:
            try:  # say goodbye, briefly
                await ws.send(OP_CLOSE, b"", timeout=1.0)
            except (ConnectionError, OSError):
                pass
            raise
        finally:
            ws.stop_keepalive()
            ws.abort()
            self.control = None


def _open_message(payload: bytes) -> Optional[ConnID]:
    """The connection an open message names; None for anything else, which
    is ignored (PROTOCOL.md 7)."""
    try:
        msg = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    value = msg.get(CONTROL_OPEN) if isinstance(msg, dict) else None
    if isinstance(value, str) and value and len(value) <= 128 and all("!" <= ch <= "~" for ch in value):
        return ConnID(value)
    return None


class Listener:
    """Serves the tunnel and hands each connection to accept(). It keeps
    itself registered: a lost hub is registered with again, with a growing
    pause, until close(). Connections that were open end with the hub.

    At most LISTEN_BACKLOG connections wait for accept(); the rest are
    refused at once with a reason (events.on_refuse)."""

    def __init__(self, client: Client):
        self._c = client
        self._queue: asyncio.Queue[Conn] = asyncio.Queue()
        self._slots = 0  # connections waiting for accept, or on their way
        self._up = False
        self._closed = False
        self._registered = asyncio.Event()
        self._done = asyncio.Event()
        self._error: Optional[BaseException] = None
        self._task: Optional[asyncio.Task] = None
        self._reg = _Registration(client, client.target or LISTENER_TARGET, self._open, self._set_up)

    @property
    def up(self) -> bool:
        """Whether the tunnel is registered with the hub right now."""
        return self._up

    @property
    def error(self) -> Optional[BaseException]:
        """Why serving stopped for good, if it did."""
        return self._error

    def _set_up(self, up: bool) -> None:
        self._up = up
        if up:
            self._registered.set()

    async def _start(self) -> None:
        self._task = asyncio.ensure_future(self._serve())
        waiter = asyncio.ensure_future(self._registered.wait())
        try:
            await asyncio.wait({self._task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            waiter.cancel()
        if self._registered.is_set():
            return
        if self._error is not None:
            raise self._error
        raise ClosedError("the listener is closed")

    async def _serve(self) -> None:
        try:
            await self._reg.run()
        except asyncio.CancelledError:
            pass
        except BaseException as e:
            self._error = e
        finally:
            self._up = False
            self._done.set()

    async def _open(self, cid: ConnID) -> None:
        c = self._c
        if self._slots >= LISTEN_BACKLOG:
            log.warning("connection %s refused: %d connections are waiting to be accepted", cid.short, LISTEN_BACKLOG)
            await c._refuse(cid, REASON_BACKLOG)
            return
        self._slots += 1
        try:
            ws = await c._dial(Endpoint.ACCEPT, [(HEADER_CONN, str(cid))])
        except asyncio.CancelledError:
            self._slots -= 1
            raise
        except Exception as e:
            self._slots -= 1
            log.warning("connection %s failed: cannot bring it to the server: %s", cid.short, explain(e))
            return
        conn = await c._new_conn(ws, cid, Side.SERVE)
        if self._closed:
            self._slots -= 1
            await conn.fail(REASON_STOPPED)
            return
        self._queue.put_nowait(conn)

    async def accept(self) -> Conn:
        """The next connection. Raises ClosedError after close(), or the
        error that stopped serving for good."""
        while True:
            if not self._queue.empty():
                self._slots -= 1
                return self._queue.get_nowait()
            if self._closed or self._done.is_set():
                if self._error is not None and not self._closed:
                    raise self._error
                raise ClosedError("the listener is closed")
            getter = asyncio.ensure_future(self._queue.get())
            done_waiter = asyncio.ensure_future(self._done.wait())
            try:
                await asyncio.wait({getter, done_waiter}, return_when=asyncio.FIRST_COMPLETED)
            except BaseException:
                getter.cancel()
                done_waiter.cancel()
                raise
            done_waiter.cancel()
            if getter.done() and not getter.cancelled():
                self._slots -= 1
                return getter.result()
            getter.cancel()

    async def close(self) -> None:
        """Stop serving: the registration ends, and connections not yet
        accepted are dropped. Accepted connections stay open until the link
        they use ends or they are closed."""
        if self._closed:
            return
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except BaseException:
                pass
        self._done.set()
        while not self._queue.empty():
            conn = self._queue.get_nowait()
            self._slots -= 1
            await conn.fail(REASON_STOPPED)

    async def __aenter__(self) -> "Listener":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def __aiter__(self):
        return self

    async def __anext__(self) -> Conn:
        try:
            return await self.accept()
        except ClosedError:
            raise StopAsyncIteration from None
