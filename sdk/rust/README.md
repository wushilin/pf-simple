# pfrelay (Rust)

The Rust SDK for the [pf-simple](../../README.md) relay hub. With it, your
program can serve a tunnel or connect through one, with no `pf-client` in
between. It is async and runs on tokio, uses rustls for TLS, and speaks
tunnel protocols 0 to 2 as defined in
[`docs/PROTOCOL.md`](../../docs/PROTOCOL.md).

```toml
[dependencies]
pfrelay = "0.16"
tokio = { version = "1", features = ["full"] }
```

## The hub's address

`Client::builder(server, word)` takes the hub as `https://host[:port]`,
optionally followed by the hub's **prefix**, the path it is mounted at
(PROTOCOL.md §2). With no path, or `/`, the prefix is `/pf`, where every
hub is unless its admin chose another; one trailing `/` is ignored. So
`https://hub.example` and `https://hub.example/pf/` are the same hub, and
`https://hub.example/xzfe-aeeg-e2da/` is the hub mounted at
`/xzfe-aeeg-e2da`. Every request goes to
`https://host[:port]<prefix>/api/tunnel/<endpoint>`.

A prefix is one or more segments, each `/` followed by 1 to 64 of
`A-Z a-z 0-9 . _ ~ -` (not `.` or `..`), at most 200 characters in all;
it is case-sensitive. `build()` refuses any other path, `http://`, and a
URL with a query, a fragment or user information. A wrong prefix is not
detected up front: the hub answers 404 to every request. Versions before
0.16.2 of this crate accept only the default prefix.

## Serving a tunnel

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> pfrelay::Result<()> {
    let client = pfrelay::Client::builder("https://hub.example/", "k3f9-x2mq-7hpa")
        .serve_token(std::env::var("PF_SERVE_TOKEN").unwrap())
        .name("Echo service")
        .client_token("open-sesame")          // optional: whoever connects must give it
        .build()?;
    let listener = client.listen().await?;    // returns once registered
    loop {
        let mut conn = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = Vec::new();
            match conn.read_to_end(&mut buf).await {  // up to the far end's half-close
                Ok(_) => {
                    let _ = conn.write_all(&buf).await;
                    let _ = conn.close().await;      // half-closes, then a clean close
                }
                Err(e) => conn.fail(&format!("echo failed: {e}")).await,
            }
        });
    }
}
```

`listen` retries anything transient (a hub that cannot be reached, a 5xx,
a 429) with a pause of 1 second doubling up to 30. It fails at once on a
refusal that waiting cannot cure: `Error::AccessDenied` (403),
`Error::Status { code, message }` (another final 4xx, such as 409 for a word
of another tenant), `Error::NoRelay` (404, no hub there) or `Error::Proto`
(the hub is too old for a client token or for serving without a serve
token). Once registered, the listener keeps itself registered, also after
losing the hub, until it is closed or dropped.

## Connecting through a tunnel

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn demo() -> pfrelay::Result<()> {
    let client = pfrelay::Client::builder("https://hub.example/", "k3f9-x2mq-7hpa")
        .client_token("open-sesame")
        .build()?;
    client.check().await?;                 // is anyone serving it? (optional)

    let mut conn = client.dial().await?;
    conn.write_all(b"hello").await?;
    conn.shutdown().await?;                // half-close: the far end reads EOF
    let mut answer = Vec::new();
    conn.read_to_end(&mut answer).await?;  // fails with Error::Remote if the far end failed
    conn.close().await?;
    if let Some(err) = conn.err() {        // a failure can arrive after the EOF
        eprintln!("the connection failed: {err}");
    }
    Ok(())
}
```

The hub accepts a `connect` before the serving side has answered. If the
serving side cannot be reached, or cannot reach its target, the first read
fails with `Error::Remote` carrying its reason.

## Forwarders

For the common case of plain TCP on both ends, the SDK carries the bytes
itself, passing half-closes on and telling the far end why a connection
broke:

```rust
// Serve the tunnel to a local TCP service, for as long as the future runs.
// The target is dialed before the hub is answered: an unreachable target
// is refused at once, and the connecting side hears why on its first read.
client.serve_tcp("127.0.0.1:22").await?;

// Or forward every connection of a local TCP listener through the tunnel.
let ln = tokio::net::TcpListener::bind("127.0.0.1:2222").await?;
client.connect_tcp(ln).await?;
```

Both run until dropped (or until a refusal that waiting cannot cure);
connections they carry show in `stats()`, `conns()` and the events like
any other.

## Events, stats and dropping connections

```rust
use pfrelay::{Client, Events};

let events = Events::new()
    .on_serving(|up| eprintln!("registered: {up}"))
    .on_tunnel(|up, err| eprintln!("tunnel up: {up} {err:?}"))      // from watch()
    .on_open(|ci| eprintln!("opened {} ({})", ci.id, ci.side))
    .on_close(|ci, err| eprintln!("closed {}: {} B out, {} B in, {err:?}", ci.id, ci.sent, ci.received))
    .on_refuse(|id, reason| eprintln!("refused {id}: {reason}"));
let client = Client::builder("https://hub.example/", "k3f9-x2mq-7hpa").events(events).build()?;

tokio::spawn({ let c = client.clone(); async move { c.watch().await } });
for ci in client.conns() {
    if ci.received > 1 << 30 {
        client.drop_conn(&ci.id, "too much traffic");  // the far end hears the reason
    }
}
println!("{:?}", client.stats());
```

Handlers are none by default and are called **synchronously**, on the task
where the event happened: they must return quickly and must not block.
They may call `stats()`, `conns()` and `drop_conn()`. `on_close` comes
exactly once for each `on_open`, with the final byte counts; its error is
`None` after a clean finish, `Error::Remote` when the far end said why, and
`Error::Dropped` when this side dropped the connection.

## Protocol 2: reused accept legs

Against a hub that speaks protocol 2 (pf-simple 0.15.0 or later), a serving
client reuses its `accept` legs (PROTOCOL.md §12). Nothing changes for the
application: every connection still arrives through `accept` or the
forwarder, with its own id, events and figures.

- The registration's 101 carries a session secret, which each `accept`
  sends back. The hub may then offer reuse (`X-PF-Tunnel-Keep-Alive`).
- When a connection on an offered leg finishes cleanly, the client waits up
  to 3 seconds for the hub's verdict. On `idle` it keeps the leg (up to
  `max_idle_legs`, 16 by default) and reports the connection as finished
  cleanly; on `err:` the connection failed; on a close or no answer,
  protocol 1 rules apply. `on_close` comes only after the verdict.
- An idle leg pings every 10 seconds and is dead after 30 of silence. The
  hub's `bind <id>` is answered at once with `bound <id>`, and the
  connection is carried like any other. A forwarder answers `bound` before
  it dials its target; if the target cannot be reached, or a listener's
  backlog is full, it refuses with `err:<reason>` and calls `on_refuse`.
- If the hub asks again for an id still open here (its leg died before
  the hub heard `bound`), the old attempt ends as failed with
  `Error::Dropped` ("the leg was lost before the server took the
  connection"), and the new one is carried.
- When the registration's control channel ends, its idle legs are closed.
- On an idle leg, unknown text frames are ignored; binary data, or a known
  frame in the wrong state (`eof`, `err:`, `idle`, `bound`, ...), closes
  the leg.
- `drop_conn` on a connection whose writer is already waiting for the
  hub's verdict is ignored: by then all its data has been sent, so the
  verdict decides how it ends (and the leg may be kept).

**Older hubs, older clients.** The client offers `0-2` (raised to `1-2`
when a client token, or serving without a serve token, needs protocol 1).
A protocol 1 hub answers 1, and a hub from before 0.14 answers nothing
(protocol 0): legs are then simply never reused, and everything else works
as before. Reuse is an optimization, never a requirement, so its absence is
never an error.

```rust
use pfrelay::{Client, ProtoLimit};

let client = Client::builder("https://hub.example/", "k3f9-x2mq-7hpa")
    .serve_token(token)
    .max_idle_legs(4)                      // keep fewer idle legs (default 16)
    // .no_reuse()                         // never reuse legs
    // .max_proto(ProtoLimit::UpTo(1))     // behave like pf-client 0.14
    // .max_proto(ProtoLimit::Unannounced) // like a client from before 0.14
    .build()?;
```

## API overview

| Item | What it is |
|---|---|
| `Client::builder(server, word)` | `.serve_token()`, `.client_token()`, `.name()`, `.target()`, `.agent()`, `.ca_file()`, `.ca_pem()`, `.tls_config()`, `.logger()`, `.events(Events)`, `.timing(Timing)`, `.max_proto(ProtoLimit)`, `.no_reuse()`, `.max_idle_legs(n)`, `.build()` |
| `client.listen().await -> Listener` | registers the tunnel; `listener.accept().await -> Conn`, `.is_up()`, `.close()` |
| `client.dial().await -> Conn` | one connection through the tunnel |
| `client.check().await` | `Ok(())` when the word is served (and the client token is right) |
| `client.probe().await -> ServerInfo` | the hub's version and protocol range; needs a serve token |
| `client.serve_tcp(target).await`, `client.connect_tcp(listener).await` | the forwarders |
| `client.watch().await` | checks the tunnel every 30s while up, 1s doubling to 30s while down; reports through `on_tunnel` at the first result and on every change |
| `client.stats()`, `client.conns()` | this client's totals (`opened`, `active`, `failed`, `sent`, `received`) and open connections (`ConnInfo { id, side, opened, sent, received, wrote_eof, read_eof }`), forwarded ones included |
| `client.drop_conn(&id, reason) -> bool` | fails an open connection by id; it ends with `Error::Dropped` |
| `ConnId` | the hub's opaque connection id: `Clone + Eq + Hash + Ord + Display + Serialize`, `.short()` |
| `Side` | `Connect` or `Serve`; `Display`/`FromStr`/serde as `connect`/`serve` |
| `Events` | `on_serving`, `on_tunnel`, `on_open`, `on_close`, `on_refuse` |
| `Timing` | `retry_min` (1s), `retry_max` (30s), `settled` (60s), `recheck` (30s), `verdict_wait` (3s); change only to test |
| `ProtoLimit` | `Newest` (default, protocol 2), `UpTo(n)`, `Unannounced` (no `X-PF-Tunnel-Proto` or `X-PF-Version`) |
| `Conn` | `AsyncRead + AsyncWrite` (also `&Conn`, to read and write from two tasks); `shutdown` half-closes; `.close()`, `.fail(reason)`, `.err()`, `.finished()`, `.id()`, `.side()`, `.info()` |
| `Error` | `Config`, `AccessDenied`, `Status{code,message}`, `NoRelay`, `NoProbe`, `Proto(ProtoError)`, `Remote(RemoteError)`, `Dropped{reason}`, `Link`, `Protocol`, `Tls`, `Closed`, `Io`; `is_final()`; `Error::from_io(&io_err)` for errors from a `Conn`'s reads and writes |
| `new_word()`, `normalize_word()`, `check_serve_token()`, `check_client_token()`, `check_name()` | the values of PROTOCOL.md §3 |
| `PROTO_MIN` (0), `PROTO_MAX` (2), `Feature`, `negotiate()`, `proto_range()`, `parse_proto_range()`, `server_proto()` | protocol versions (§5) |

Notes:

- **TLS.** The hub's certificate is verified normally, against the system's
  roots unless `ca_file`/`ca_pem` or `tls_config` says otherwise. For a hub
  that runs with `--console-tls`, give the CA that pf-simple keeps in its
  `certs` directory. Only HTTP/1.1 is offered (ALPN `http/1.1`).
- **Writes** are handed to a task that puts them on the wire in order, at
  most 64 KiB per frame; `close` waits until they are sent. Dropping a
  `Conn` closes it the same way, in the background.
- **Keepalive.** Streams ping every 10 seconds and treat 30 seconds of
  silence as a dead link; the control channel pings every 20 seconds and
  allows 60. Pongs are never relied on.
- **Backlog.** At most 128 connections wait for `accept`; more are refused
  at once with a reason the connecting side hears, and reported to
  `on_refuse`.
- `X-PF-Version` is `pfrelay-rs <version>` unless `.agent()` says otherwise.
  It is for the hub's log and console only.

## Other transports

`pfrelay::transport` lets another crate reach the hub some other way while
the `Client` keeps everything else: listeners, retries, events, stats,
forwarders and `watch`. [`pfrelay-quic`](../rust-quic) plugs QUIC
(tunnel protocol 3, `docs/PROTOCOL.md` §13) in through
`ClientBuilder::transport`. Programs that use pfrelay over WebSocket need
none of it.

## Conformance

`src/bin/driver.rs` is the conformance driver
([`conformance/README.md`](../../conformance/README.md)): both modes
(`listen`, `forward`), the event lines, the stdin queries, `protocols` and
`--proto-max N`, so the suite runs it at every combination of hub and
client protocol. The unit
tests (`cargo test`) run the client against a fake hub over in-memory
pipes, with tokio's clock paused where timing matters. From the
repository root:

```sh
cargo build --release --manifest-path sdk/rust/Cargo.toml
cargo test --manifest-path sdk/rust/Cargo.toml
PF_CONFORMANCE_DRIVER="sdk/rust/target/release/driver" go test -count=1 -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="sdk/rust/target/release/driver" go test -count=1 -run 'TestConformance/hub_2,_client_2/idle' .
```

## License

Apache License 2.0; see [LICENSE](LICENSE).
