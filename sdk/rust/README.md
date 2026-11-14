# pfrelay (Rust)

The Rust SDK for the [pf-simple](../../README.md) relay hub. With it, your
program can serve a tunnel or connect through one, with no `pf-client` in
between. It is async and runs on tokio, uses rustls for TLS, and speaks
tunnel protocols 0 and 1 as defined in
[`docs/PROTOCOL.md`](../../docs/PROTOCOL.md).

```toml
[dependencies]
pfrelay = { path = "sdk/rust" }   # not on crates.io yet
tokio = { version = "1", features = ["full"] }
```

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

## API overview

| Item | What it is |
|---|---|
| `Client::builder(server, word)` | `.serve_token()`, `.client_token()`, `.name()`, `.target()`, `.agent()`, `.ca_file()`, `.ca_pem()`, `.tls_config()`, `.logger()`, `.build()` |
| `client.listen().await -> Listener` | registers the tunnel; `listener.accept().await -> Conn`, `.is_up()`, `.close()` |
| `client.dial().await -> Conn` | one connection through the tunnel |
| `client.check().await` | `Ok(())` when the word is served (and the client token is right) |
| `client.probe().await -> ServerInfo` | the hub's version and protocol range; needs a serve token |
| `client.stats()`, `client.conns()` | this client's totals (`opened`, `active`, `failed`, `sent`, `received`) and open connections (`ConnInfo`) |
| `Conn` | `AsyncRead + AsyncWrite` (also `&Conn`, to read and write from two tasks); `shutdown` half-closes; `.close()`, `.fail(reason)`, `.err()`, `.finished()`, `.id()`, `.side()`, `.info()` |
| `Error` | `Config`, `AccessDenied`, `Status{code,message}`, `NoRelay`, `NoProbe`, `Proto(ProtoError)`, `Remote(RemoteError)`, `Link`, `Protocol`, `Tls`, `Closed`, `Io`; `is_final()`; `Error::from_io(&io_err)` for errors from a `Conn`'s reads and writes |
| `new_word()`, `normalize_word()`, `check_serve_token()`, `check_client_token()`, `check_name()` | the values of PROTOCOL.md §3 |
| `PROTO_MIN`, `PROTO_MAX`, `negotiate()`, `proto_range()`, `parse_proto_range()`, `server_proto()` | protocol versions (§5) |

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
  with a reason the connecting side hears.
- `X-PF-Version` is `pfrelay-rs <version>` unless `.agent()` says otherwise.
  It is for the hub's log and console only.

## Conformance

`src/bin/driver.rs` is the conformance driver
([`conformance/README.md`](../../conformance/README.md)). From the
repository root:

```sh
cargo build --release --manifest-path sdk/rust/Cargo.toml
cargo test --manifest-path sdk/rust/Cargo.toml
PF_CONFORMANCE_DRIVER="sdk/rust/target/release/driver" go test -count=1 -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="sdk/rust/target/release/driver" go test -count=1 -run 'TestConformance/idle' .
```

## License

TODO: the repository has no LICENSE file yet. Set `license` in
`Cargo.toml` (and `repository`) before publishing to crates.io.
