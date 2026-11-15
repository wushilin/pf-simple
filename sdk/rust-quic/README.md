# pfrelay-quic (Rust)

The Rust SDK for the [pf-simple](../../README.md) relay hub over **QUIC**:
tunnel protocol 3, as defined in [`docs/PROTOCOL.md`](../../docs/PROTOCOL.md)
§13. It runs on tokio, with quinn and rustls.

It is [`pfrelay`](../rust) with another way to the hub. The `Client` it
builds is a `pfrelay::Client` (it dereferences to one), so listeners,
`dial`, forwarders, events, stats, `drop_conn`, `watch` and the retry loop
are pfrelay's, and behave the same. A QUIC side works with a WebSocket side
through the same hub, in either role.

```toml
[dependencies]
pfrelay-quic = "0.3"
tokio = { version = "1", features = ["full"] }
```

## Moving from WebSocket

Build the client from `pfrelay_quic` instead of `pfrelay`; the rest of the
program stays as it is.

```rust
// was: pfrelay::Client::builder(...)
let server = pfrelay_quic::Client::builder("https://hub.example/", "k3f9-x2mq-7hpa")
    .serve_token("0123456789abcdef0123456789abcdef")
    .name("My service")
    .build()?;
let listener = server.listen().await?;
while let Ok(conn) = listener.accept().await {
    // a pfrelay::Conn: AsyncRead + AsyncWrite, shutdown() half-closes
}
```

The builder takes pfrelay's settings except those of the WebSocket
protocols (`max_proto`, leg reuse). `ca_file`, `ca_pem` and `tls_config`
are for the hub's HTTPS endpoint, where the QUIC listener is discovered.

## How it reaches the hub

- **Discovery.** `GET /pf/api/tunnel/quic` on the hub's HTTPS endpoint,
  with the run's credentials, tells where the QUIC listener is and the
  SHA-256 fingerprints of its certificate. A 404 means the hub offers no
  QUIC (this is final); a 501 means its listener is off (retried).
- **Pinning.** The listener's certificate is accepted if and only if the
  SHA-256 of its DER is one of the fingerprints. The chain, name and dates
  are not checked; the TLS 1.3 handshake signature is. On a mismatch the
  client discovers once more, then fails.
- **One QUIC connection** per client, shared by clones, made again (after
  discovering again) when it is lost. QUIC version 1 only, ALPN
  `pf-tunnel`, no 0-RTT, no session resumption, keepalive every 10 s,
  idle timeout 30 s, no unidirectional streams.
- **Each request is a stream.** `connect` is one stream per connection;
  `serve` keeps one stream open as the registration, and the hub opens a
  stream to the serving side for each connection.
- **No fallback.** Where UDP is blocked this fails to connect; use
  `pfrelay` (WebSocket) there.

`Client::close` closes the QUIC connection; dropping the last clone of a
client does the same.

## Conformance

`src/bin/driver.rs` is the conformance driver
([`conformance/README.md`](../../conformance/README.md)). It answers
`protocols` with `3-3`, so the suite runs every case with the hub's QUIC
listener on and the Go SDK on WebSocket on the other side. From the
repository root:

```sh
cargo build --release --manifest-path sdk/rust-quic/Cargo.toml
cargo test --manifest-path sdk/rust-quic/Cargo.toml
PF_CONFORMANCE_DRIVER="sdk/rust-quic/target/release/driver" go test -count=1 -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="sdk/rust-quic/target/release/driver" go test -count=1 -run 'TestConformance/quic/idle' .
```

## License

Apache License 2.0; see [LICENSE](LICENSE).
