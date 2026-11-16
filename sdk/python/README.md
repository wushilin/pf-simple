# pfrelay for Python

The Python SDK for the relay hub of [pf-simple](../../README.md): serve a
tunnel, or connect through one, from your own asyncio program. It speaks the
tunnel protocol described in [docs/PROTOCOL.md](../../docs/PROTOCOL.md)
(protocols 0, 1 and 2) and mirrors the Go SDK, [`pfrelay`](../../pfrelay).

- Python 3.10 or later, standard library only (asyncio and ssl).
- Its own minimal RFC 6455 WebSocket client over TLS, HTTP/1.1 only.

## Install

```sh
pip install ./sdk/python        # from a checkout of pf-simple
```

Or copy `sdk/python/pfrelay/` next to your program: it has no dependencies.

## Serve a tunnel

```python
import asyncio, pfrelay

async def main():
    client = pfrelay.Client(
        "https://hub.example.com", "k3f9-x2mq-7hpa",
        serve_token=SERVE_TOKEN,       # or none, where the hub allows it
        name="Echo service",           # what the hub's console calls it
        client_token="open-sesame",    # optional: what connectors must give
    )
    listener = await client.listen()   # returns once registered
    async with listener:
        async for conn in listener:    # or: conn = await listener.accept()
            asyncio.ensure_future(echo(conn))

async def echo(conn: pfrelay.Conn):
    async with conn:                   # close() on the way out
        while data := await conn.read():
            await conn.write(data)
        await conn.close_write()       # pass the half-close on

asyncio.run(main())
```

The listener keeps itself registered: when the hub is lost it registers
again, pausing 1 s, doubling up to 30 s. Refusals that waiting cannot cure
on the first registration are raised from `listen()`. At most 128
connections wait for `accept()`; the rest are refused at once with a
reason (PROTOCOL.md §9).

## Connect through a tunnel

```python
async def main():
    client = pfrelay.Client("https://hub.example.com", "k3f9-x2mq-7hpa",
                            client_token="open-sesame")
    await client.check()               # optional: raises AccessDenied if not up
    conn = await client.dial()
    await conn.write(b"hello\n")
    await conn.close_write()
    try:
        while data := await conn.read():
            print(data)
    except pfrelay.RemoteError as e:   # the far end failed, and said why
        print("failed:", e.reason)
    await conn.close()
    if conn.err:                       # a failure may follow a half-close
        print("failed:", conn.err)
```

The hub answers `dial()` before the serving side has: if the serving side
cannot reach its target, the first `read()` says so.

## Forwarders

To carry TCP connections, let the SDK do the copying, both ways, with
half-close and failure reasons:

```python
# Serving side: offer a TCP target. Runs until cancelled; raises only on a
# refusal waiting cannot cure.
await client.serve("localhost:22")

# Connecting side: forward every connection accepted on a listening socket.
sock = socket.create_server(("127.0.0.1", 2222))
await client.connect(sock)

# Or one stream pair, e.g. as an asyncio.start_server callback:
await asyncio.start_server(client.connect_one, "127.0.0.1", 2222)
```

`serve()` dials the target before it answers the hub. If the target cannot
be reached it refuses the connection with a reason (`events.on_refuse`), so
the connecting side hears it on its first read.

## Events, stats and drop

```python
def opened(info: pfrelay.ConnInfo):
    print("opened", info.id, info.side)

async def closed(info: pfrelay.ConnInfo, err):
    print("closed", info.id, info.sent, info.received, err or "ok")

client.events = pfrelay.Events(
    on_serving=lambda up: print("registered" if up else "lost the hub"),
    on_tunnel=lambda up, err: print("tunnel", "up" if up else f"down ({err})"),
    on_open=opened,
    on_close=closed,            # exactly once for each on_open
    on_refuse=lambda cid, reason: print("refused", cid, reason),
)
```

Every handler is optional (`None` by default) and called in the task
where the event happened: a plain function is called, a coroutine
function awaited. A handler that raises is logged, never passed on.
Connections from `dial`, `listen` and both forwarders all appear in the
events, in `client.stats()` and in `client.conns()`.

`client.drop(conn_id, reason)` ends an open connection by its id and tells
the far end why; it returns whether such a connection was open. It is a
plain function, so a sync handler may call it; the connection ends with a
`DroppedError` and `on_close` follows. Connection ids are `ConnID`: opaque,
hashable, equal by value, printed with `str()`.

## Watch

`await client.watch()` (until cancelled) checks whether the tunnel can be
reached and reports through `events.on_tunnel`: the first result, then
every change. A tunnel that is up is checked every 30 s; one that is down
from 1 s, doubling to 30 s.

## Protocol 2: reused legs

Against a hub that speaks protocol 2 (pf-simple 0.15.0 or later), the
serving side reuses its connections to the hub ("accept legs") instead of
opening a new TLS WebSocket for every connection (PROTOCOL.md §12):

- The client offers `0-2` by default. The minimum is still that of the
  features a request depends on (`1` with a client token, or when serving
  without a serve token).
- After a connection on an offered leg finishes cleanly, the client waits
  up to 3 seconds (`Client.verdict_wait`) for the hub's verdict. Only then
  does it report the connection closed: `idle` is a clean finish, and
  `err:` a failure. A close, or silence, is judged by the protocol 1 rules.
  It keeps the leg idle if it has room.
- The hub hands an idle leg the next connection with `bind <id>`. The client
  answers `bound <id>` at once, and the connection arrives like any other,
  through `listener.accept()` or the `serve()` forwarder, with its own
  events. A connection that cannot be carried after `bound` (unreachable
  target, full backlog) is refused with `err:<reason>` on that leg.
- When the registration's control channel ends, its idle legs are closed.

It needs no code from the application. The options are:

| Option | Default | |
|---|---|---|
| `no_reuse=True` | `False` | never keep legs: every connection gets a new one |
| `max_idle_legs=N` | 16 | the most idle legs kept; the hub's further offers are answered with a close |
| `max_proto=N` | `None` | offer no protocol newer than N: `1` behaves like pf-client 0.14, `-1` announces none, like a client from before 0.14; `None` or `0` means the newest |

**Older hubs.** Against a protocol 1 hub (pf-simple 0.14) the client falls
back to protocol 1, and against a hub from before 0.14 to protocol 0. Each
connection then gets its own leg, as before. Reuse is an optimization,
never a requirement, so not getting it is never an error.

## Other transports: QUIC

[pfrelay-quic](../python-quic) reaches the hub over QUIC (tunnel protocol 3,
PROTOCOL.md §13). Its `Client` is this package's `Client` with a QUIC
transport attached through `pfrelay.transport`, so listeners, `dial`,
forwarders, events, stats, `drop`, `watch` and the retry loop are the ones
described here. Over an attached transport:

- `listen`, `serve`, `dial`, `connect` and `check` go through the
  transport; `probe` stays an HTTPS request.
- Each connection's stream carries protocol 3's frames, which a `Conn`
  reads and writes as it does a WebSocket's: data, `eof`, `err`, and the
  stream's end in place of the close.
- Leg reuse (protocol 2) is WebSocket only, so it is off.

`pfrelay.transport` is a service-provider interface for SDKs built on this
one; applications do not implement it.

## TLS

The hub's certificate is verified normally. Pass `ca_file=` to trust a
particular CA, or a ready `ssl_context=` (its ALPN is set to `http/1.1`).

## Timing

The retry and watch timing are class attributes of `Client`, which an
instance may override (tests do): `retry_min = 1.0`, `retry_max = 30.0`,
`settled = 60.0` (a control channel this old starts the pause again),
`recheck = 30.0` and `verdict_wait = 3.0` (protocol 2).

## API overview

| | |
|---|---|
| `Client(server, word, *, ca_file, ssl_context, serve_token, client_token, name, target, agent, events, max_proto, no_reuse, max_idle_legs, transport)` | one hub, one tunnel; checks the URL, word and tokens; `transport` is for SDKs such as pfrelay-quic |
| `await client.listen()` → `Listener` | register and serve |
| `await listener.accept()` → `Conn` | the next connection; `ClosedError` after `close()` |
| `listener.up`, `listener.error`, `await listener.close()` | registered right now; why serving stopped for good |
| `await client.serve(target)` | the serve forwarder, to a TCP `host:port` |
| `await client.dial()` → `Conn` | open one connection |
| `await client.connect(sock)`, `await client.connect_one(reader, writer)` | the connect forwarder |
| `await client.watch()` | report the tunnel coming and going, through `events.on_tunnel` |
| `client.drop(conn_id, reason)` → `bool` | drop an open connection by its id |
| `await client.check()` | is someone serving this word? |
| `await client.probe()` → `ServerInfo` | the hub's version and protocols (needs a serve token) |
| `client.stats()` → `Stats(opened, active, failed, sent, received)` | this client's totals |
| `client.conns()` → `[ConnInfo(id, side, opened, sent, received, wrote_eof, read_eof)]` | open connections, oldest first; `id` is a `ConnID`, `side` a `Side` |
| `await conn.read(n)` | up to `n` bytes; `b""` after the far end's half-close |
| `await conn.readexactly(n)`, `async for chunk in conn` | conveniences |
| `await conn.write(data)` | send, in frames of at most 64 KiB |
| `await conn.close_write()` | half-close (sends `eof`) |
| `await conn.fail(reason)` | drop it, telling the far end why |
| `await conn.close()` | half-close if not yet done, then end; clean when both sides half-closed |
| `conn.err`, `conn.id`, `conn.info()` | why it failed (also an `err:` after `eof`), the hub's id, a snapshot |
| `new_word()`, `normalize_word(w)` | words (PROTOCOL.md §3.1) |

Errors:

| | |
|---|---|
| `AccessDenied` | the hub answered 403 (a subclass of `StatusError`) |
| `StatusError(code, message)` | any other refusal; `.final` says whether retrying can help |
| `ProtoError` | the hub is too old for a feature this request depends on (§5.3) |
| `RemoteError(reason)` | the far end or the hub dropped the stream, and why |
| `LinkError` | the link to the hub broke or went silent |
| `ClosedError` | used after this side closed it |
| `DroppedError(reason)` | how a connection ended that this side dropped (`fail`, `drop`) |

All derive from `PfRelayError`. Logs go to the `pfrelay` logger.

## Tests

From the repository root:

```sh
python3 -I -m unittest discover -s sdk/python/tests
PF_CONFORMANCE_DRIVER="python3 -I sdk/python/driver.py" go test -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="python3 -I sdk/python/driver.py" go test -run 'TestConformance/idle' .
```

`driver.py` is the conformance driver described in
[conformance/README.md](../../conformance/README.md).

## License

Apache License 2.0; see [LICENSE](LICENSE).
