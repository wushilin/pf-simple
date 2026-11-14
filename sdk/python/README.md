# pfrelay for Python

The Python SDK for the relay hub of [pf-simple](../../README.md): serve a
tunnel, or connect through one, from your own asyncio program. It speaks the
tunnel protocol described in [docs/PROTOCOL.md](../../docs/PROTOCOL.md)
(protocols 0 and 1) and mirrors the Go SDK, [`pfrelay`](../../pfrelay).

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
on the first registration are raised from `listen()`.

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

## TLS

The hub's certificate is verified normally. Pass `ca_file=` to trust a
particular CA or self-signed certificate, or a ready `ssl_context=` (its
ALPN is set to `http/1.1`).

## API overview

| | |
|---|---|
| `Client(server, word, *, ca_file, ssl_context, serve_token, client_token, name, target, agent)` | one hub, one tunnel; checks the URL, word and tokens |
| `await client.listen()` → `Listener` | register and serve |
| `await listener.accept()` → `Conn` | the next connection; `ClosedError` after `close()` |
| `listener.up`, `listener.error`, `await listener.close()` | registered right now; why serving stopped for good |
| `await client.dial()` → `Conn` | open one connection |
| `await client.check()` | is someone serving this word? |
| `await client.probe()` → `ServerInfo` | the hub's version and protocols (needs a serve token) |
| `client.stats()` → `Stats(opened, active, failed, sent, received)` | this client's totals |
| `client.conns()` → `[ConnInfo(id, side, opened, sent, received, wrote_eof, read_eof)]` | open connections, oldest first |
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
