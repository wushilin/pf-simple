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
from ._conn import _EOF as _EOF_FRAME
from ._conn import _ERR as _ERR_FRAME
from ._conn import MSG_BIND, MSG_BOUND, MSG_IDLE, Conn, ConnInfo, Stats, _Registry, emit
from ._forward import PARTY_CONNECT, PARTY_SERVE, bridge
from ._framed import Framed
from ._proto import (
    CONTROL_OPEN,
    HEADER_CLIENT_HASH,
    HEADER_CLIENT_TOKEN,
    HEADER_CONN,
    HEADER_ERROR,
    HEADER_KEEP_ALIVE,
    HEADER_NAME,
    HEADER_PROTO,
    HEADER_SERVE,
    HEADER_SESSION,
    HEADER_TARGET,
    HEADER_VERSION,
    HEADER_WORD,
    PROTO_MAX,
    PROTO_MIN,
    AccessDenied,
    ClosedError,
    ConnID,
    DroppedError,
    Endpoint,
    Feature,
    LinkError,
    ProtoError,
    RemoteError,
    ServerInfo,
    Side,
    StatusError,
    clean_reason,
    check_client_token,
    check_name,
    check_serve_token,
    error_text,
    normalize_base,
    normalize_word,
    proto_range,
    server_proto,
)
from ._ws import OP_BINARY, OP_CLOSE, OP_CONT, OP_PING, OP_PONG, OP_TEXT, FrameError, WebSocket
from .transport import Open, Params, Registration, Transport

__version__ = "0.16.1"
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
# How an attempt ends whose leg died before the hub heard "bound": the hub
# asks again with an open message (PROTOCOL.md 12.7).
REASON_LEG_LOST = "the leg was lost before the server took the connection"

DEFAULT_MAX_IDLE_LEGS = 16
SESSION_LENGTH = 32  # hex digits of X-PF-Tunnel-Session
KEEP_ALIVE_MAX = 3600  # the largest valid X-PF-Tunnel-Keep-Alive

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
    verdict_wait = 3.0  # how long a clean finish waits for the hub's verdict (12.5)

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
        max_proto: Optional[int] = None,
        no_reuse: bool = False,
        max_idle_legs: int = DEFAULT_MAX_IDLE_LEGS,
        transport: Optional[Transport] = None,
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
        # The newest protocol to offer: None or 0 the newest this SDK
        # speaks, 1 like pf-client 0.14, -1 none at all, like a client from
        # before 0.14 (for testing against old peers).
        self.max_proto = max_proto
        # Protocol 2: keep the serving side's legs for reuse, at most this many.
        self.no_reuse = no_reuse
        self.max_idle_legs = max_idle_legs if max_idle_legs > 0 else DEFAULT_MAX_IDLE_LEGS
        # Another way to the hub than WebSocket, for SDKs built on this one,
        # such as pfrelay-quic (see pfrelay.transport). Reuse of accept legs,
        # which is WebSocket only, is then off.
        self.transport = transport
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

    def proto_max(self) -> int:
        """The newest protocol this client offers."""
        m = self.max_proto
        if m is not None and m < 0:
            return 0
        if not m or m > PROTO_MAX:
            return PROTO_MAX
        return m

    def offer(self, endpoint: Union[Endpoint, str]) -> Optional[str]:
        """The protocol range a request to endpoint offers; None when this
        client announces none (max_proto -1)."""
        if self.max_proto is not None and self.max_proto < 0:
            return None
        hi = self.proto_max()
        lo = PROTO_MIN
        for f in self.needs(endpoint):
            lo = max(lo, f.proto)
        return proto_range(min(lo, hi), hi)

    def answered(self, endpoint: Union[Endpoint, str], headers) -> None:
        """Raise ProtoError when the hub's answer shows it is too old for
        something the request depends on."""
        proto = server_proto(headers)
        for f in self.needs(endpoint):
            if proto < f.proto:
                raise ProtoError(proto, f)

    def _headers(self, endpoint: Endpoint, extra: list[tuple[str, str]]) -> list[tuple[str, str]]:
        h: list[tuple[str, str]] = []
        offer = self.offer(endpoint)
        if offer is not None:  # a client from before 0.14 announced nothing
            h += [(HEADER_PROTO, offer), (HEADER_VERSION, self.agent)]
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
            if self.transport is not None:
                await self.transport.check(Params(self))
                return
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
        if self.transport is not None:
            try:
                stream, cid = await self.transport.connect(Params(self))
            except StatusError as e:
                raise explain(e) from None
            return await self._new_conn(Framed(stream), ConnID(cid), Side.CONNECT)
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
        stopping = False

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await self.connect_one(reader, writer)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.info("connection from %s: %s", writer.get_extra_info("peername"), explain(e))

        def accepted(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            # A plain callback: the task is known from the moment the
            # connection is, so a stop cancels it even before it has run.
            if stopping:
                writer.transport.abort()
                return
            t = asyncio.ensure_future(handle(reader, writer))
            handlers.add(t)
            t.add_done_callback(handlers.discard)

        server = await asyncio.start_server(accepted, sock=sock)
        try:
            # Not serve_forever(): cancelled, it waits in wait_closed() for
            # the open connections, which only the finally below ends.
            await asyncio.get_running_loop().create_future()
        finally:
            stopping = True
            server.close()
            for t in list(handlers):
                t.cancel()
            if handlers:
                await asyncio.gather(*handlers, return_exceptions=True)
            try:
                await asyncio.wait_for(server.wait_closed(), _ws.CLOSE_TIMEOUT)
            except asyncio.TimeoutError:
                pass

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

        async def open_one(cid: ConnID, sess: "_Session", leg: Optional[WebSocket]) -> None:
            was_bound = leg is not None  # it came on a reused leg, after "bound"
            # On a reused leg the hub already has "bound": a refusal from
            # here on is an err: on that leg (12.7).
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TARGET_DIAL_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                log.warning("connection %s refused: cannot reach the target %s: %s", cid.short, target, e)
                if leg is not None:
                    await self._refuse_leg(leg, cid, REASON_UNREACHABLE)
                else:
                    await self._refuse(cid, REASON_UNREACHABLE, sess)
                return
            except BaseException:
                if leg is not None:
                    leg.abort()  # cancelled while dialing: the bound leg goes too
                raise
            if leg is not None and sess.abandoned(str(cid)):
                # Asked for again while this side was dialing: the new attempt
                # carries it, and this one never opened.
                writer.transport.abort()
                await _fail_leg(leg, REASON_LEG_LOST)
                return
            reusable = True
            if leg is None:
                try:
                    leg, reusable = await self._accept(cid, sess)
                except Exception as e:
                    log.warning("connection %s failed: cannot bring it to the server: %s", cid.short, explain(e))
                    writer.transport.abort()
                    return
                except BaseException:
                    writer.transport.abort()
                    raise
            try:
                conn = await self._new_conn(leg, cid, Side.SERVE, reusable=reusable, finisher=sess.finisher)
            except BaseException:
                writer.transport.abort()
                raise
            if was_bound and sess.abandoned(str(cid)):
                self._drop(conn, REASON_LEG_LOST)  # asked for again just as it opened
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
        return self._drop(self._reg.find(conn_id), reason)

    def _drop(self, conn: Optional[Conn], reason: str) -> bool:
        if conn is None or conn._done or conn._dropping:
            return False
        conn._dropping = True
        conn._drop_reason = reason
        task = asyncio.ensure_future(conn.fail(reason))
        self._drops.add(task)
        task.add_done_callback(self._drops.discard)
        return True

    async def _new_conn(
        self,
        ws: WebSocket,
        cid: ConnID,
        side: Side,
        *,
        reusable: bool = False,
        finisher: Optional[Callable[[Conn], Awaitable[Optional[BaseException]]]] = None,
    ) -> Conn:
        conn = Conn(ws, cid, side, self, reusable=reusable, finisher=finisher if reusable else None)  # type: ignore[arg-type]
        self._reg.add(conn)
        try:
            await emit(self.events.on_open, conn.info())
        except BaseException:  # cancelled in an async handler: nobody owns the leg yet
            conn._kill(ClosedError("cancelled while the connection opened"))
            raise
        return conn

    async def _accept(self, cid: ConnID, sess: "_Session") -> tuple[WebSocket, bool]:
        """Bring this side's leg of connection cid to the hub. With the
        registration's session it may be offered reuse (12.3); returns the
        leg and whether it was."""
        if isinstance(sess, _AltSession):
            stream = await sess.take(cid).accept()
            return Framed(stream), False  # type: ignore[return-value]
        extra = [(HEADER_CONN, str(cid))]
        if sess.secret:
            extra.append((HEADER_SESSION, sess.secret))
        ws = await self._dial(Endpoint.ACCEPT, extra)
        return ws, bool(sess.secret) and offered(ws.headers)

    def _abandon(self, cid: ConnID) -> None:
        """The hub asks again for an id only when the leg it was bound to
        was lost before it heard "bound" (12.7): the old attempt fails, and
        the new one goes on under the same id."""
        # Only the serving side's: the same client may also be connecting
        # through the tunnel, and its connection carries the same id.
        self._drop(self._reg.find(cid, Side.SERVE), REASON_LEG_LOST)

    async def _refuse_leg(self, ws: WebSocket, cid: ConnID, reason: str) -> None:
        """Refuse a connection that arrived on a reused leg, after "bound":
        err:<reason> and a close on that leg (12.7)."""
        try:
            await emit(self.events.on_refuse, cid, reason)
        finally:
            await _fail_leg(ws, reason)

    async def _conn_closed(self, conn: Conn, err: Optional[BaseException]) -> None:
        if self._reg.finish(conn, err is not None):
            await emit(self.events.on_close, conn.info(), err)

    async def _refuse(self, cid: ConnID, reason: str, sess: Optional["_Session"] = None) -> None:
        await emit(self.events.on_refuse, cid, reason)
        if isinstance(sess, _AltSession):
            try:
                await sess.take(cid).refuse(_clean_header(reason, 128))
            except Exception as e:
                log.info("connection %s: could not tell the server: %s", cid.short, e)
            return
        try:
            await self._get(Endpoint.ACCEPT, [(HEADER_CONN, str(cid)), (HEADER_ERROR, _clean_header(reason, 128))])
        except Exception as e:
            log.info("connection %s: could not tell the server: %s", cid.short, explain(e))


def _cancels() -> int:
    """How many times this task has been asked to stop (0 where Python
    cannot tell, before 3.11).

    On Python 3.10 and 3.11, asyncio.wait_for returns a result that arrives
    together with the cancellation, and the cancellation is lost. A
    registration that comes back while the count went up must not be kept.
    The count is compared, not tested for zero: a task that once caught a
    cancellation keeps its count, and must still be able to serve."""
    t = asyncio.current_task()
    cancelling = getattr(t, "cancelling", None)
    return cancelling() if cancelling else 0


class _Registration:
    """Keeps a tunnel registered and calls open_one, in a task of its own,
    for each connection the hub asks for."""

    def __init__(
        self,
        client: Client,
        target: str,
        open_one: Callable[[ConnID, "_Session", Optional[WebSocket]], Awaitable[None]],
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
            if self._c.transport is not None:
                await self._alt_loop(self._c.transport)
            else:
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
            cancels = _cancels()
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
                if _cancels() > cancels:
                    ws.abort()
                    raise asyncio.CancelledError()
                if served:
                    log.info("registered again with %s after %d attempt(s)", c.base, attempt)
                else:
                    log.info("registered with %s: serving %r", c.base, c.name)
                served, attempt = True, 0
                started = time.monotonic()
                sess = _Session(self, ws.headers)
                self._on_up(True)
                try:
                    await emit(c.events.on_serving, True)
                    err = await self._control(ws, sess)
                finally:
                    ws.abort()  # also when cancelled in an async handler
                    sess.end()  # its legs go with it (12.6)
                    self._on_up(False)
                await emit(c.events.on_serving, False)
                if time.monotonic() - started >= c.settled:
                    backoff = c.retry_min
                log.warning("lost the server (%s); its connections are closed; registering again in %gs", err, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, c.retry_max)

    async def _alt_loop(self, t: Transport) -> None:
        """The same loop as _loop, over an attached transport: its
        registrations and opens in place of the control channel and accept."""
        c = self._c
        backoff, served, attempt = c.retry_min, False, 0
        while True:
            attempt += 1
            cancels = _cancels()
            try:
                reg = await t.register(Params(c), self._target)
            except ProtoError:
                raise
            except StatusError as e:
                if not served and e.final:
                    raise explain(e) from None
                log.warning(
                    "cannot register with %s over %s (%s); attempt %d, trying again in %gs",
                    c.base, t.name, explain(e), attempt, backoff,
                )
            except _TRANSIENT as e:
                log.warning(
                    "cannot register with %s over %s (%s); attempt %d, trying again in %gs",
                    c.base, t.name, e, attempt, backoff,
                )
            else:
                if _cancels() > cancels:
                    reg.close()
                    raise asyncio.CancelledError()
                if served:
                    log.info("registered again with %s over %s after %d attempt(s)", c.base, t.name, attempt)
                else:
                    log.info("registered with %s over %s: serving %r", c.base, t.name, c.name)
                served, attempt = True, 0
                started = time.monotonic()
                sess = _AltSession()
                self._on_up(True)
                try:
                    await emit(c.events.on_serving, True)
                    err = await self._alt_opens(reg, sess)
                finally:
                    reg.close()  # also when cancelled in an async handler
                    sess.end()
                    self._on_up(False)
                await emit(c.events.on_serving, False)
                if time.monotonic() - started >= c.settled:
                    backoff = c.retry_min
                log.warning("lost the server (%s); its connections are closed; registering again in %gs", err, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, c.retry_max)

    async def _alt_opens(self, reg: Registration, sess: "_AltSession") -> BaseException:
        """Carry each connection a registration asks for, until it ends;
        returns why it did."""
        while True:
            try:
                o = await reg.next()
            except (ConnectionError, OSError, LinkError) as e:
                return e
            cid = ConnID(clean_reason(o.id))
            sess.put(cid, o)
            self.spawn(self._open_one(cid, sess, None))  # type: ignore[arg-type]

    def spawn(self, coro) -> None:
        t = asyncio.ensure_future(coro)
        self._opens.add(t)
        t.add_done_callback(self._opens.discard)

    async def _control(self, ws: WebSocket, sess: "_Session") -> BaseException:
        """Run one control channel until it fails; returns why."""
        self.control = ws
        ws.start_keepalive(CONTROL_PING, CONTROL_SILENCE)
        try:
            while True:
                op, _fin, payload = await ws.recv(MAX_CONTROL_FRAME, MAX_CONTROL_FRAME)
                if op == OP_TEXT:
                    cid = _open_message(payload)
                    if cid:
                        if sess.took_open(str(cid)):
                            self._c._abandon(cid)  # a bound id asked for again: a new attempt (12.7)
                        self.spawn(self._open_one(cid, sess, None))
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


async def _fail_leg(ws: WebSocket, reason: str) -> None:
    """End a leg the protocol 1 way: err:<reason> and a close."""
    sent = False
    try:
        await ws.send(OP_TEXT, _ERR_FRAME + _clean_header(reason, 128).encode("ascii"), timeout=_ws.CLOSE_TIMEOUT)
        await ws.send(OP_CLOSE, b"", timeout=_ws.CLOSE_TIMEOUT)
        sent = True
    except (ConnectionError, OSError):
        pass
    finally:
        if sent:
            ws.close_transport()
        else:
            ws.abort()


def known_leg_frame(msg: bytes) -> bool:
    """Whether msg is one of the text frames of streams and reused legs
    (8.1, 12): such a frame where it does not belong is a violation, while
    any other text is ignored."""
    return (
        msg in (_EOF_FRAME, MSG_IDLE, MSG_BIND, MSG_BOUND)
        or msg.startswith((_ERR_FRAME, MSG_BIND + b" ", MSG_BOUND + b" "))
    )


def offered(headers) -> bool:
    """Whether the hub's answer to an accept offered reuse: a protocol 2
    answer with a keep-alive of 1 to 3600 seconds (12.3)."""
    if server_proto(headers) < 2:
        return False
    v = headers.get(HEADER_KEEP_ALIVE)
    if not v or not v.isascii() or not v.isdigit():
        return False
    return 1 <= int(v) <= KEEP_ALIVE_MAX


RECALL = 30.0  # how long a session remembers ids: well past the hub's 10 s


@dataclass
class _Attempt:
    """A connection taken on a reused leg, until the hub has seen "bound"."""

    at: float
    abandoned: bool = False


class _Session:
    """One control channel's life (protocol 2): its secret, and the legs
    kept for reuse that belong to it."""

    def __init__(self, reg: "_Registration", headers):
        c = reg._c
        self._reg = reg
        self._c = c
        self.secret = ""
        if server_proto(headers) >= 2 and not c.no_reuse and c.proto_max() >= 2:
            v = headers.get(HEADER_SESSION) or ""
            if len(v) == SESSION_LENGTH:
                self.secret = v
        self.idle = 0  # legs kept, idle or offered
        self.legs: set[WebSocket] = set()
        self.ended = False
        # The ids answered "bound" (with whether that attempt was abandoned)
        # and the ids that came with an open message, remembered for a
        # while: an id that came both ways is the case of 12.7.
        self._bound: dict[str, _Attempt] = {}
        self._opened: dict[str, float] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        for k in [k for k, a in self._bound.items() if now - a.at > RECALL]:
            del self._bound[k]
        for k in [k for k, at in self._opened.items() if now - at > RECALL]:
            del self._opened[k]

    def take_bind(self, cid: str) -> bool:
        """Record a bind of cid; refuse one for an id that already came
        with an open message (a bind that arrived after the hub fell back)."""
        self._prune()
        if cid in self._opened:
            return False
        self._bound[cid] = _Attempt(time.monotonic())
        return True

    def took_open(self, cid: str) -> bool:
        """Record an open message for cid; True when cid was bound here: a
        new attempt, the old one being abandoned."""
        self._prune()
        self._opened[cid] = time.monotonic()
        a = self._bound.get(cid)
        if a is not None:
            a.abandoned = True
            return True
        return False

    def abandoned(self, cid: str) -> bool:
        """Whether the attempt at cid on a reused leg was given up because
        the hub asked for it again."""
        a = self._bound.get(cid)
        return a is not None and a.abandoned

    def keep(self) -> bool:
        """Reserve room for one more idle leg."""
        if self.ended or self.idle >= self._c.max_idle_legs:
            return False
        self.idle += 1
        return True

    def release(self) -> None:
        self.idle -= 1

    def end(self) -> None:
        """The control channel ended: the hub has dropped every leg."""
        self.ended = True
        for ws in list(self.legs):
            ws.abort()

    async def finisher(self, conn: Conn) -> Optional[BaseException]:
        """End a cleanly finished connection on a reusable leg: wait for the
        hub's verdict, keep the leg if there is room, and return what the
        verdict reports went wrong, if anything (12.5)."""
        idle, reason = await conn._await_verdict(self._c.verdict_wait)
        if idle:
            if self.keep():
                ws = conn._ws
                try:
                    await ws.send(OP_TEXT, MSG_IDLE, timeout=_ws.WRITE_TIMEOUT)  # bounded
                except (ConnectionError, OSError):
                    self.release()
                    await conn._close_stream()
                    return None
                except BaseException:  # cancelled: the place goes back
                    self.release()
                    raise
                self._reg.spawn(self._idle_leg(conn._detach()))
                return None
            await conn._close_stream()  # the hub's "idle" answered with a close: not kept
            return None
        await conn._close_stream()
        if reason:
            return RemoteError(reason)
        return None  # the hub closed, or said nothing in time: protocol 1 rules

    async def _idle_leg(self, ws: WebSocket) -> None:
        """Wait on an idle leg for the hub's "bind <id>", until the leg or
        the registration ends."""
        self.legs.add(ws)
        bound = False
        try:
            if self.ended:
                return
            ws.start_keepalive(Conn._PING_EVERY, Conn._SILENCE)
            while True:
                op, fin, payload = await ws.recv(MAX_CONTROL_FRAME, MAX_CONTROL_FRAME)
                if op in (OP_PING, OP_PONG):
                    continue
                if op == OP_CLOSE or op in (OP_BINARY, OP_CONT) or not fin:
                    return  # closed, or a violation (12.4)
                prefix = MSG_BIND + b" "
                if payload.startswith(prefix) and len(payload) > len(prefix):
                    break
                if known_leg_frame(payload):
                    return  # a known frame in the wrong state: a violation (12.4)
                # unknown text is ignored
            ws.stop_keepalive()
            if self.ended:
                return
            raw = payload[len(MSG_BIND) + 1:]
            if not self.take_bind(raw.decode("utf-8", "replace")):
                return  # already asked for with an open message: the hub gave this leg up
            await ws.send(OP_TEXT, MSG_BOUND + b" " + raw, timeout=_ws.WRITE_TIMEOUT)
            bound = True
        except (ConnectionError, OSError, LinkError, FrameError):
            return
        finally:
            self.legs.discard(ws)
            self.release()
            if not bound:
                ws.stop_keepalive()
                ws.abort()
        cid = ConnID(clean_reason(raw.decode("utf-8", "replace")))
        await self._reg._open_one(cid, self, ws)


_tasks: set[asyncio.Future] = set()


def _background(coro) -> None:
    """Run coro in a task of its own, kept until it is done."""
    t = asyncio.ensure_future(coro)
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


class _AltSession:
    """One registration's life over an attached transport: the opens not
    yet taken. There is no leg reuse."""

    secret = ""
    finisher = None

    def __init__(self) -> None:
        self._opens: dict[ConnID, Open] = {}
        self.ended = False

    def put(self, cid: ConnID, o: Open) -> None:
        old = self._opens.pop(cid, None)
        if old is not None:  # an id asked for twice: the old one is refused
            _background(old.refuse(REASON_LEG_LOST))
        self._opens[cid] = o

    def take(self, cid: ConnID) -> Open:
        o = self._opens.pop(cid, None)
        if o is None:
            raise LinkError("the registration ended before the connection was taken")
        return o

    def abandoned(self, cid: str) -> bool:
        return False

    def end(self) -> None:
        """The registration ended: the opens not taken are refused."""
        self.ended = True
        opens, self._opens = list(self._opens.values()), {}
        for o in opens:
            _background(o.refuse(REASON_STOPPED))


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
        self._wake = asyncio.Event()  # a connection arrived, or serving ended
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
            self._wake.set()

    async def _open(self, cid: ConnID, sess: _Session, leg: Optional[WebSocket]) -> None:
        c = self._c
        was_bound = leg is not None  # it came on a reused leg, after "bound"
        if self._slots >= LISTEN_BACKLOG:
            log.warning("connection %s refused: %d connections are waiting to be accepted", cid.short, LISTEN_BACKLOG)
            if leg is not None:
                await c._refuse_leg(leg, cid, REASON_BACKLOG)  # after "bound", an err: (12.7)
            else:
                await c._refuse(cid, REASON_BACKLOG, sess)
            return
        self._slots += 1
        if leg is not None and sess.abandoned(str(cid)):
            self._slots -= 1
            await _fail_leg(leg, REASON_LEG_LOST)  # asked for again: the new attempt carries it
            return
        reusable = True
        if leg is None:
            try:
                leg, reusable = await c._accept(cid, sess)
            except asyncio.CancelledError:
                self._slots -= 1
                raise
            except Exception as e:
                self._slots -= 1
                log.warning("connection %s failed: cannot bring it to the server: %s", cid.short, explain(e))
                return
        try:
            conn = await c._new_conn(leg, cid, Side.SERVE, reusable=reusable, finisher=sess.finisher)
        except BaseException:
            self._slots -= 1
            raise
        if was_bound and sess.abandoned(str(cid)):
            c._drop(conn, REASON_LEG_LOST)  # asked for again just as it opened
        if self._closed:
            self._slots -= 1
            await conn.fail(REASON_STOPPED)
            return
        self._queue.put_nowait(conn)
        self._wake.set()

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
            # One Event, set by an arrival and by the end: a cancelled wait
            # takes nothing from the queue, so nothing is lost.
            self._wake.clear()
            await self._wake.wait()

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
        self._wake.set()
        waiting = []
        while not self._queue.empty():
            waiting.append(self._queue.get_nowait())
            self._slots -= 1
        try:
            for conn in waiting:
                await conn.fail(REASON_STOPPED)
        finally:  # cancelled on the way: the rest are cut at once
            for conn in waiting:
                conn._kill(DroppedError(REASON_STOPPED))

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
