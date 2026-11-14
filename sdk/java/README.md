# pfrelay for Java

The Java SDK for the [pf-simple](../../README.md) relay hub: serve a tunnel
from your own program, or connect through one, with nothing but the JDK.
It speaks tunnel protocols 0 and 1, as described in
[docs/PROTOCOL.md](../../docs/PROTOCOL.md), and passes the
[conformance suite](../../conformance/README.md).

- Java 17 or later, no dependencies.
- A blocking, thread-based API: `Listener.accept()` and `Client.dial()`
  give you a `Conn` with an `InputStream` and an `OutputStream`.
- Package `io.github.wushilin.pfrelay`.

## Building

```sh
sdk/java/build.sh        # compiles, runs the tests, writes build/pfrelay.jar
```

`pom.xml` is there for publishing; `build.sh` needs only `javac` and `jar`.

## Serving a tunnel

```java
import io.github.wushilin.pfrelay.*;
import java.net.Socket;
import java.nio.file.Path;

Client client = Client.builder()
        .server("https://hub.example.com")
        .word(Words.newWord())                 // or the word you were given
        .serveToken(System.getenv("PF_SERVE_TOKEN"))
        .name("Office SSH")                    // what the hub's console shows
        .target("localhost:22")                // shown in the console only
        .logger(System.err::println)
        .build();

try (Listener listener = client.listen()) {    // returns once registered
    System.out.println("serving " + client.word());
    while (true) {
        Conn conn = listener.accept();
        new Thread(() -> {
            try (Socket target = new Socket("localhost", 22)) {
                pipe(conn, target);            // copy both ways, see below
            } catch (java.io.IOException e) {
                conn.fail("the serving side could not reach its target");
            }
        }).start();
    }
}
```

`listen()` throws when the hub refuses for good: `AccessDeniedException`
(a wrong serve token), `StatusException` (such as 409, a word that belongs
to another tenant, with the hub's message), or `ProtoException` (a hub too
old for what was asked, such as a client token). Anything else, a hub that
cannot be reached included, is retried with a pause from 1 to 30 seconds.
Once registered, the listener keeps itself registered until `close()`,
re-registering after it loses the hub.

## Connecting through a tunnel

```java
Client client = Client.builder()
        .server("https://hub.example.com")
        .word("k3f9-x2mq-7hpa")
        .caFile(Path.of("hub.pem"))            // only for a hub with its own certificate
        .build();

client.check();                                // throws AccessDeniedException if nobody serves it

try (Conn conn = client.dial()) {
    conn.getOutputStream().write("hello\n".getBytes());
    conn.shutdownOutput();                     // half-close: the far end reads the end
    byte[] answer = conn.getInputStream().readAllBytes();
    if (conn.error() != null) {                // a failure can arrive after the half-close
        throw conn.error();
    }
}
```

The hub answers `dial()` before the serving side has: when the serving side
cannot reach its target, the first read throws a `RemoteException` with its
reason.

## Copying both ways

```java
static void pipe(Conn conn, Socket local) throws java.io.IOException {
    Thread up = new Thread(() -> {
        try {
            local.getInputStream().transferTo(conn.getOutputStream());
            conn.shutdownOutput();             // TCP EOF -> the stream's half-close
        } catch (java.io.IOException e) {
            conn.fail("the local connection failed: " + e.getMessage());
        }
    });
    up.start();
    try {
        conn.getInputStream().transferTo(local.getOutputStream());
        local.shutdownOutput();                // the stream's half-close -> TCP shutdown
        up.join();
        conn.close();                          // clean when both ends half-closed
    } catch (java.io.IOException e) {
        conn.fail(e.getMessage());
    } catch (InterruptedException e) {
        conn.fail("interrupted");
    } finally {
        local.close();
    }
}
```

The conformance driver, `src/conformance/java/.../Driver.java`, is a
complete example.

## API overview

| Type | What it is |
|---|---|
| `Client` | One hub and one word. Built with `Client.builder()`: `server`, `word`, `sslContext` or `caFile`, `serveToken`, `clientToken`, `name`, `target`, `agent` (default `pfrelay-java 0.1.0`), `logger`. `build()` checks every value (PROTOCOL.md §3) and throws `IllegalArgumentException`. |
| `Client.listen()`, `listen(Duration)` | Register and return a `Listener`. |
| `Client.dial()` | Open one connection; a `Conn`. |
| `Client.check()` | Returns if someone serves the word; throws `AccessDeniedException` otherwise. |
| `Client.probe()` | The hub's `ServerInfo` (version, protoMin, protoMax, token); needs a serve token. |
| `Client.stats()`, `conns()` | Local bookkeeping: `Stats` (opened, active, failed, sent, received) and the open connections as `ConnInfo` (id, side, opened, sent, received, wroteEof, readEof). |
| `Listener` | `accept()`, `isUp()`, `close()`. At most 128 connections wait for `accept()`; more are refused and their connecting side is told why. |
| `Conn` | `getInputStream()` (-1 at the far end's half-close), `getOutputStream()` (closing it half-closes), `shutdownOutput()`, `fail(reason)`, `close()`, `error()`, `id()`, `info()`, `setSoTimeout(ms)`. |
| `Words` | `newWord()`, `normalize(word)`. |
| `Tls` | `trusting(Path pem)`: an `SSLContext` that trusts a PEM file. |
| Exceptions | All are `IOException`s: `StatusException` (`code()`, `hubMessage()`, `isFinal()`), its subclass `AccessDeniedException` (403), `ProtoException` (`serverProto()`, `need()`), `RemoteException` (`reason()`). |

### Behavior worth knowing

- **TLS** is always verified, the host name included (IP addresses match
  IP SANs). Plain `http://` is refused. Pass `caFile` or `sslContext` for a
  hub whose certificate the JDK does not trust.
- **Protocol negotiation.** Every request offers `X-PF-Tunnel-Proto: min-1`,
  where `min` is 1 when the request depends on a client token or on serving
  without a serve token, and 0 otherwise. A hub that answers with a lower
  protocol (or none at all: a hub from before 0.14.0) is refused with a
  `ProtoException` rather than having the feature quietly ignored.
- **Half-close and failure.** `read` returns -1 after the far end's `eof`.
  The hub may pass a failure on as `eof` first and the reason later, so
  `error()` can turn a finish into a failure after the fact.
  `close()` without both half-closes, or a lost link, is reported as a
  failure on the other side, never as a half-close.
- **Keepalive.** Each `Conn` pings every 10 seconds and gives up after 30
  seconds of silence; the control channel pings every 20 seconds and gives
  up after 60. Nothing relies on pongs.
- **Threads.** Each `Conn` has a reader thread, and each `Listener` a
  registration thread; all are daemons. A `Conn` takes one reader and one
  writer at a time.

## Conformance

```sh
sdk/java/build.sh
PF_CONFORMANCE_DRIVER="sdk/java/driver.sh" go test -count=1 -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="sdk/java/driver.sh" go test -count=1 -run 'TestConformance/idle' .
```

Run them from the repository root.
