# pfrelay-quic for Java

The Java SDK for the [pf-simple](../../README.md) relay hub over **QUIC**:
tunnel protocol 3 ([docs/PROTOCOL.md §13](../../docs/PROTOCOL.md)). Serve a
tunnel from your own program, or connect through one, over UDP instead of
WebSockets. It passes the [conformance suite](../../conformance/README.md).

- Java 17 or later.
- Maven: `io.github.wushilin:pfrelay-quic:0.16.2`. It depends on
  [pfrelay](../java) (the WebSocket SDK, same version) and on
  [kwik](https://github.com/ptrd/kwik) (`tech.kwik:kwik`), a QUIC
  implementation in pure Java.
- Package `io.github.wushilin.pfrelayquic`.

## The same API as pfrelay

pfrelay-quic gives you pfrelay's own `Client`, with a QUIC transport plugged
in. Listeners, forwarders, `dial`, `check`, `watch`, events, stats and
`drop` are pfrelay's, so they behave the same on both transports. Moving a
program from WebSocket to QUIC means changing the builder:

```java
import io.github.wushilin.pfrelay.*;
import io.github.wushilin.pfrelayquic.QuicClient;

Client client = QuicClient.builder()           // instead of Client.builder()
        .server("https://hub.example.com")     // the hub's HTTPS address and prefix, as with pfrelay
        .word("k3f9-x2mq-7hpa")
        .build();

try (Conn conn = client.dial()) {
    conn.getOutputStream().write("hello\n".getBytes());
    conn.shutdownOutput();
    byte[] answer = conn.getInputStream().readAllBytes();
} finally {
    client.close();                            // closes the QUIC connection
}
```

Serving is the same too: `client.listen()` and `accept()`, or
`client.serve("localhost:22")`. See [pfrelay's README](../java/README.md)
for the whole API. What differs:

- **The server URL** is the same as pfrelay's
  ([its README](../java/README.md#the-server-url)): `https://host[:port]`,
  optionally followed by the hub's prefix, `/pf` when none is given, such
  as `https://hub.example.com/xzfe-aeeg-e2da/` for a hub mounted at
  `/xzfe-aeeg-e2da`. Discovery goes under that prefix.
- **Discovery.** The client asks the hub's HTTPS endpoint
  (`GET <prefix>/api/tunnel/quic`, `/pf/api/tunnel/quic` by default, with
  the run's own credentials) where its QUIC listener is and which
  certificate it uses. `caFile` and
  `sslContext` verify that HTTPS endpoint, as with pfrelay. It discovers
  again before each new QUIC connection.
- **Certificate pinning.** The QUIC listener's certificate is accepted if
  and only if the SHA-256 of its DER encoding is one that discovery
  announced. Its chain, name, subject and dates are not checked; the TLS 1.3
  handshake is, the CertificateVerify signature included, so a peer must
  hold the pinned certificate's key. On a mismatch the client discovers
  once more; a second mismatch is an error.
- **One QUIC connection** per `Client` carries every request: each
  registration and each connection is a stream of it. It is made again
  when it is lost, and `Client.close()` closes it at the end of the run.
  Streams that have just sent an err, a refusal or an unregister get up
  to 3 seconds for the hub to take it first, so `close()` may wait that
  long. Build one `Client` per builder.
- **Keepalive.** The client sends a PING every 5 seconds, and the
  connection's idle timeout is 30 seconds. Streams send nothing of their
  own: an idle connection stays up as long as the QUIC connection does.
- **No fallback.** A hub without QUIC (older than pf-simple 0.16.0, or with
  its relay off) is a final error that says so. Where UDP is blocked, the
  client cannot connect: use pfrelay (WebSocket) there.
- **Protocols.** It speaks protocol 3 only, over QUIC. It works with
  WebSocket clients of protocols 0 to 2 through the hub, which bridges
  them, in either role. `maxProto`, `noReuse` and `maxIdleLegs` do not
  apply. `probe()` still asks the hub's HTTPS endpoint.

## Notes on kwik

- QUIC version 1 only, ALPN `pf-tunnel`, no session tickets are kept, so
  there is no resumption and no 0-RTT.
- Use kwik on the class path, not the module path: the keepalive sends its
  PING through kwik's implementation class, as kwik's own keepalive (which
  pings only every half idle timeout) is too slow for §13.6.
- kwik sends the advertised host as SNI even when it is an IP address,
  where §13.3 asks for no SNI. The hub does not depend on it.
- kwik wakes threads blocked on a stream with interrupts. A thread
  blocked in a read of a kwik stream does not see its own interrupt (kwik
  clears it): interrupting a thread that waits for the hub's answer in
  `dial()` or `check()` does not stop it; the answer, or its 15-second
  limit, does. A writer that kwik wakes because its stream was reset gets
  a plain `IOException`, and the SDK clears the interrupt kwik left.

## Building

```sh
sdk/java-quic/build.sh   # fetches kwik into lib/, builds pfrelay from ../java and this SDK, runs the tests
sdk/java-quic/driver.sh  # the conformance driver, after build.sh
```

`build.sh` needs `javac`, `jar` and `curl`: it fetches kwik and its three
dependencies from Maven Central once, into `lib/`, and checks each jar's
SHA-256. `pom.xml` is for publishing; it names the same versions.

## Conformance

```sh
sdk/java-quic/build.sh
PF_CONFORMANCE_DRIVER="sdk/java-quic/driver.sh" go test -run TestConformance .
```

The driver answers `protocols` with `3-3`, so the suite runs every case
with the hub's QUIC listener on, this SDK on QUIC, and the Go SDK on
WebSocket on the other side.

## License

Apache License 2.0; see [LICENSE](LICENSE).
