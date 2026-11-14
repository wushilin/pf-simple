"""The client of the relay hub: serve a tunnel (listen/accept) or connect
through one (dial), plus check and probe. Mirrors the Go SDK, pfrelay."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
import time
from typing import Optional
from urllib.parse import quote_plus

from . import _ws
from ._conn import SIDE_CONNECT, SIDE_SERVE, Conn, ConnInfo, Stats, _Registry
from ._proto import (
    API_PATH,
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
    Feature,
    LinkError,
    ProtoError,
    ServerInfo,
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

_NO_RELAY = "this server does not accept tunnels (it needs --tunnel or a [tunnel] table)"


def _short(conn_id: str) -> str:
    return conn_id[:8]


def _clean_header(s: str, limit: int = 200) -> str:
    return "".join(c for c in s if " " <= c <= "~")[:limit]


def explain(err: BaseException) -> BaseException:
    """Turn the hub's refusals into something to act on (PROTOCOL.md 9)."""
    if not isinstance(err, StatusError) or isinstance(err, AccessDenied):
        return err
    if err.code == 403:
        return AccessDenied(err.message, err.headers)
    if err.code == 404 and not err.message:
        return StatusError(404, _NO_RELAY, err.headers)
    return err


class Client:
    """Talks to one relay hub about one tunnel (one word).

    It can serve the tunnel (listen) or connect through it (dial, check).
    """

    # Retry timing (PROTOCOL.md 9); class attributes so tests can shorten them.
    retry_min = 1.0
    retry_max = 30.0
    settled = 60.0  # a control channel this old resets the pause

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
        if ssl_context is None:
            ssl_context = ssl.create_default_context(cafile=ca_file)
        elif ca_file:
            ssl_context.load_verify_locations(cafile=ca_file)
        ssl_context.set_alpn_protocols(["http/1.1"])
        self._ssl = ssl_context
        self._reg = _Registry()

    def __repr__(self) -> str:
        return f"<pfrelay.Client {self.base} {self.word[:4]}-…>"

    # ---------------------------------------------------------- negotiation

    def needs(self, endpoint: str) -> list[Feature]:
        """What a request to endpoint depends on beyond protocol 0."""
        out: list[Feature] = []
        if endpoint == "serve":
            if self.client_token:
                out.append(Feature.CLIENT_TOKEN)
            if not self.serve_token:
                out.append(Feature.ANONYMOUS_SERVE)
        elif endpoint in ("connect", "check"):
            if self.client_token:
                out.append(Feature.CLIENT_TOKEN)
        return out

    def offer(self, endpoint: str) -> str:
        """The protocol range a request to endpoint offers."""
        lo = PROTO_MIN
        for f in self.needs(endpoint):
            lo = max(lo, f.proto)
        return proto_range(lo, PROTO_MAX)

    def answered(self, endpoint: str, headers) -> None:
        """Raise ProtoError when the hub's answer shows it is too old for
        something the request depends on."""
        proto = server_proto(headers)
        for f in self.needs(endpoint):
            if proto < f.proto:
                raise ProtoError(proto, f)

    def _headers(self, endpoint: str, extra: list[tuple[str, str]]) -> list[tuple[str, str]]:
        h = [(HEADER_PROTO, self.offer(endpoint)), (HEADER_VERSION, self.agent)]
        if endpoint != "version":
            h.append((HEADER_WORD, self.word))
        return h + extra

    def _connect_extra(self) -> list[tuple[str, str]]:
        if self.client_token:
            return [(HEADER_CLIENT_TOKEN, self.client_token)]
        return []

    # ---------------------------------------------------------- requests

    async def _dial(self, endpoint: str, extra: list[tuple[str, str]]) -> WebSocket:
        resp, ws = await _ws.ws_dial(
            self._host, self._port, self._netloc, self._ssl, f"{API_PATH}/{endpoint}", self._headers(endpoint, extra)
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

    async def _get(self, endpoint: str, extra: list[tuple[str, str]]) -> _ws.Response:
        resp = await _ws.http_get(
            self._host, self._port, self._netloc, self._ssl, f"{API_PATH}/{endpoint}", self._headers(endpoint, extra)
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
            await self._get("check", self._connect_extra())
        except StatusError as e:
            raise explain(e) from None

    async def probe(self) -> ServerInfo:
        """The hub's version and the protocols it speaks. Needs a valid
        serve token."""
        try:
            resp = await _ws.http_get(
                self._host,
                self._port,
                self._netloc,
                self._ssl,
                f"{API_PATH}/version",
                self._headers("version", [(HEADER_SERVE, self.serve_token)]),
            )
        except StatusError as e:  # pragma: no cover
            raise explain(e) from None
        if resp.status == 404:
            raise StatusError(
                404,
                "this server does not answer a version probe: it is older than pf-simple 0.14.0, "
                "or its relay hub is off",
                resp.headers,
            )
        if resp.status // 100 != 2:
            raise explain(StatusError(resp.status, error_text(resp.body), resp.headers))
        try:
            d = json.loads(resp.body.decode("utf-8"))
            info = ServerInfo(
                version=str(d["version"]),
                proto_min=int(d.get("protoMin", 0)),
                proto_max=int(d.get("protoMax", 0)),
                token=str(d.get("token", "")),
            )
            if not info.version:
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
            raise LinkError("the server's answer to the version probe is not understood") from None
        return info

    async def dial(self) -> Conn:
        """Open one connection through the tunnel.

        The hub answers before the serving side has: if the serving side
        cannot be reached, or cannot reach its target, the first read raises
        a RemoteError saying so."""
        try:
            ws = await self._dial("connect", self._connect_extra())
        except StatusError as e:
            raise explain(e) from None
        return Conn(ws, ws.headers.get(HEADER_CONN, ""), SIDE_CONNECT, self._reg)

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

    # ---------------------------------------------------------- bookkeeping

    def stats(self) -> Stats:
        """This client's totals, open connections included."""
        return self._reg.stats()

    def conns(self) -> list[ConnInfo]:
        """This client's open connections, oldest first."""
        return self._reg.conns()

    async def _refuse(self, conn_id: str, reason: str) -> None:
        try:
            await self._get("accept", [(HEADER_CONN, conn_id), (HEADER_ERROR, _clean_header(reason, 128))])
        except Exception as e:
            log.info("connection %s: could not tell the server: %s", _short(conn_id), explain(e))


class Listener:
    """Serves the tunnel and hands each connection to accept(). It keeps
    itself registered: a lost hub is registered with again, with a growing
    pause, until close(). Connections that were open end with the hub."""

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
        self._opens: set[asyncio.Task] = set()
        self._control: Optional[WebSocket] = None

    @property
    def up(self) -> bool:
        """Whether the tunnel is registered with the hub right now."""
        return self._up

    @property
    def error(self) -> Optional[BaseException]:
        """Why serving stopped for good, if it did."""
        return self._error

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
            await self._serve_loop()
        except asyncio.CancelledError:
            pass
        except BaseException as e:
            self._error = e
        finally:
            self._up = False
            self._done.set()

    async def _serve_loop(self) -> None:
        c = self._c
        extra = [(HEADER_TARGET, _clean_header(c.target or "listener")), (HEADER_NAME, quote_plus(c.name))]
        if c.serve_token:
            extra.append((HEADER_SERVE, c.serve_token))
        if c.client_token:
            extra.append((HEADER_CLIENT_HASH, hashlib.sha256(c.client_token.encode("ascii")).hexdigest()))
        backoff, served, attempt = c.retry_min, False, 0
        while True:
            attempt += 1
            try:
                ws = await c._dial("serve", extra)
            except ProtoError:
                raise  # the hub cannot do what was asked: waiting will not change it
            except StatusError as e:
                if not served and e.final:
                    raise explain(e) from None
                log.warning(
                    "cannot register with %s (%s); attempt %d, trying again in %gs",
                    c.base, explain(e), attempt, backoff,
                )
            except (OSError, ConnectionError, ssl.SSLError, LinkError, asyncio.TimeoutError) as e:
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
                self._up = True
                self._registered.set()
                try:
                    err = await self._run_control(ws)
                finally:
                    self._up = False
                if time.monotonic() - started >= c.settled:
                    backoff = c.retry_min
                log.warning("lost the server (%s); its connections are closed; registering again in %gs", err, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, c.retry_max)

    async def _run_control(self, ws: WebSocket) -> BaseException:
        """Run one control channel until it fails; returns why."""
        self._control = ws
        ws.start_keepalive(CONTROL_PING, CONTROL_SILENCE)
        try:
            while True:
                op, _fin, payload = await ws.recv(MAX_CONTROL_FRAME, MAX_CONTROL_FRAME)
                if op == OP_TEXT:
                    try:
                        msg = json.loads(payload.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    conn_id = msg.get("open") if isinstance(msg, dict) else None
                    if isinstance(conn_id, str) and conn_id and len(conn_id) <= 128 and all(
                        "!" <= ch <= "~" for ch in conn_id
                    ):
                        t = asyncio.ensure_future(self._open(conn_id))
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
        finally:
            ws.stop_keepalive()
            ws.abort()
            self._control = None

    async def _open(self, conn_id: str) -> None:
        c = self._c
        if self._slots >= LISTEN_BACKLOG:
            log.warning("connection %s refused: %d connections are waiting to be accepted", _short(conn_id), LISTEN_BACKLOG)
            await c._refuse(conn_id, "the serving side is not accepting connections fast enough")
            return
        self._slots += 1
        try:
            ws = await c._dial("accept", [(HEADER_CONN, conn_id)])
        except asyncio.CancelledError:
            self._slots -= 1
            raise
        except Exception as e:
            self._slots -= 1
            log.warning("connection %s failed: cannot bring it to the server: %s", _short(conn_id), explain(e))
            return
        conn = Conn(ws, conn_id, SIDE_SERVE, c._reg)
        if self._closed:
            self._slots -= 1
            await conn.fail("the serving side stopped listening")
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
        ws = self._control
        if ws is not None:
            try:
                await ws.send(OP_CLOSE, b"", timeout=1.0)
            except (ConnectionError, OSError):
                pass
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except BaseException:
                pass
        for t in list(self._opens):
            t.cancel()
        self._done.set()
        while not self._queue.empty():
            conn = self._queue.get_nowait()
            self._slots -= 1
            await conn.fail("the serving side stopped listening")

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
