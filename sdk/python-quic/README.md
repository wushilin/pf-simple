# pfrelay-quic for Python

The Python SDK for the [pf-simple](../../README.md) relay hub over **QUIC**:
tunnel protocol 3, as defined in [`docs/PROTOCOL.md`](../../docs/PROTOCOL.md)
§13. It runs on asyncio, with [aioquic](https://github.com/aiortc/aioquic).

It is [`pfrelay`](../python) with another way to the hub. The `Client` it
makes is a `pfrelay.Client`, with a QUIC transport attached, so listeners,
`dial`, forwarders, events, stats, `drop`, `watch` and the retry loop are
pfrelay's, and behave the same. A QUIC side works with a WebSocket side
through the same hub, in either role.

- Python 3.11 or later (aioquic 1.8 needs it).
- Depends on `pfrelay` 0.16 and `aioquic` 1.8 or later.

```sh
pip install pfrelay-quic
```

## Moving from WebSocket

Make the client from `pfrelay_quic` instead of `pfrelay`; the rest of the
program stays as it is.

```python
import asyncio, pfrelay, pfrelay_quic

async def main():
    # was: pfrelay.Client(...)
    client = pfrelay_quic.Client(
        "https://hub.example.com", "k3f9-x2mq-7hpa",
        serve_token=SERVE_TOKEN,
        name="Echo service",
    )
    listener = await client.listen()
    async for conn in listener:          # pfrelay.Conn, as over WebSocket
        asyncio.ensure_future(echo(conn))

async def echo(conn: pfrelay.Conn):
    async with conn:
        while data := await conn.read():
            await conn.write(data)
        await conn.close_write()

asyncio.run(main())
```

`pfrelay_quic.Client` takes pfrelay's settings except those of the
WebSocket protocols (`max_proto`, leg reuse). `ca_file` and `ssl_context`
are for the hub's HTTPS endpoint, where the QUIC listener is discovered.
`client.close()` closes the QUIC connection; the next request opens a new
one.

## How it reaches the hub

- **Discovery.** `GET /pf/api/tunnel/quic` on the hub's HTTPS endpoint,
  with the run's credentials, tells where the QUIC listener is and the
  SHA-256 fingerprints of its certificate. A 404 means the hub offers no
  QUIC (this is final); a 501 means its listener is off (retried).
- **Pinning.** The listener's certificate is accepted if and only if the
  SHA-256 of its DER is one of the fingerprints. The chain, name and dates
  are not checked; the TLS 1.3 handshake signature is. aioquic offers no
  verification hook, so the pin is checked right after the handshake,
  before any stream is opened. On a mismatch the client discovers once
  more, then fails.
- **One QUIC connection** per client, made again (after discovering again)
  when it is lost. QUIC version 1 only, ALPN `pf-tunnel`, no 0-RTT, no
  session resumption, idle timeout 30 s, no unidirectional streams.
  aioquic has no keepalive of its own, so the client sends a PING after
  10 s in which nothing arrived.
- **Flow control.** A stream's receive credit follows what the
  application has read, so a connection whose reader stalls holds up only
  itself. A write waits while too much of its stream is unacknowledged.
- **Each request is a stream.** `connect` is one stream per connection;
  `serve` keeps one stream open as the registration, and the hub opens a
  stream to the serving side for each connection.
- **No fallback.** Where UDP is blocked this fails to connect; use
  `pfrelay` (WebSocket) there.

## Tests

From the repository root, with aioquic installed:

```sh
python3 -I -m unittest discover -s sdk/python-quic/tests
PF_CONFORMANCE_DRIVER="python3 -I sdk/python-quic/driver.py" go test -count=1 -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="python3 -I sdk/python-quic/driver.py" go test -count=1 -run 'TestConformance/quic/idle' .
```

The unit tests run the client against a fake hub's QUIC listener, also on
aioquic (`tests/hub.py`). `driver.py` is the conformance driver
([`conformance/README.md`](../../conformance/README.md)); it answers
`protocols` with `3-3`, so the suite runs every case with the hub's QUIC
listener on and the Go SDK on WebSocket on the other side.

## License

Apache License 2.0; see [LICENSE](LICENSE).
