# pfrelay for Java

The Java SDK for the [pf-simple](../../README.md) relay hub: serve a tunnel
from your own program, or connect through one, with nothing but the JDK.
It speaks tunnel protocols 0, 1 and 2, as described in
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
                pipe(conn, target);            // your copy loop, such as the conformance driver's pipe
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

## Forwarders

To carry TCP connections, let the SDK do the copying: it passes half-closes
on, and when something breaks it tells the far end which hop broke.

```java
// serving: the target is reached before the hub is answered, so an
// unreachable target is refused at once, with a reason the far end hears
try (Forwarder f = client.serve("localhost:22")) {      // returns once registered
    Thread.sleep(Long.MAX_VALUE);
}

// connecting: every local connection goes through the tunnel
try (ServerSocket local = new ServerSocket(2222);
     Forwarder f = client.connect(local);
     Watcher w = client.watch()) {                       // onTunnel: up and down
    Thread.sleep(Long.MAX_VALUE);
}
```

Closing a forwarder stops it and drops the connections it carries, telling
their far ends that this side is stopping. The conformance driver,
`src/conformance/java/.../Driver.java`, shows the listen/accept and dial
API used with a copy loop of its own.

## Events

```java
Client client = Client.builder()
        .server("https://hub.example.com")
        .word("k3f9-x2mq-7hpa")
        .events(new ClientEvents() {
            @Override public void onOpen(ConnInfo info) {
                System.out.println("open " + info.id() + " " + info.side());
            }
            @Override public void onClose(ConnInfo info, IOException error) {
                System.out.println("closed " + info.id() + (error == null ? "" : ": " + error.getMessage()));
            }
        })
        .build();
```

Every method of `ClientEvents` does nothing by default. They are called
synchronously, on the SDK's thread where the event happened, so a handler
**must return quickly and must not block**. It may call `drop`, `conns`
and `stats`.

| Event | When |
|---|---|
| `onServing(up)` | a listener or serve forwarder registered (true) or lost its registration (false) |
| `onTunnel(up, error)` | a watcher's first result, then every change |
| `onOpen(info)` | a connection opened: dialed, accepted, or carried by a forwarder |
| `onClose(info, error)` | exactly once per `onOpen`, with the final figures; `error` is null after a clean finish |
| `onRefuse(id, reason)` | this side refused a connection: the backlog was full, or the target could not be reached |

## Protocol 2: reusing the serving side's legs

Against a pf-simple 0.15 hub, the serving side reuses its `accept` legs
([PROTOCOL.md §12](../../docs/PROTOCOL.md)): a connection that finished
cleanly leaves its WebSocket open and idle, and the hub hands the tunnel's
next connection to it with one frame instead of asking for a new
WebSocket. That saves a TCP connect, a TLS handshake and a round trip per
connection. It is on by default, and needs nothing from the application:

- Each connection still arrives as a new `Conn` from `accept()` or the
  serve forwarder, with its own id, figures and events. The application
  never sees legs.
- A connection on a leg the hub offered to reuse is reported closed only
  once the hub's verdict is in (at most 3 seconds after both half-closes):
  `idle` is a clean finish, `err:` a failure, and silence or a close is
  judged as in protocol 1.
- At most `maxIdleLegs` (16 by default) idle legs are kept; past that, the
  hub's offer is declined. When the registration is lost, its idle legs are
  closed, and the new registration starts afresh.
- The hub may ask again for a connection that was bound on a leg that died
  before the hub heard about it. The first attempt is then reported as
  failed, with a `DroppedException` whose reason is "the leg was lost
  before the server took the connection", and the connection arrives again
  as a new one with the same id.

**Older hubs.** Nothing depends on reuse. Against a pf-simple 0.14 hub
(protocol 1) or an older one (protocol 0), the SDK sees no offer and works
exactly as in protocol 1: one leg per connection. Connecting sides are
unaffected in every combination.

**Options.**

| Builder option | Effect |
|---|---|
| `noReuse()` | never offer legs for reuse: one leg per connection, as with an older hub |
| `maxIdleLegs(n)` | keep at most `n` idle legs (default 16) |
| `maxProto(n)` | offer no protocol newer than `n`: `0` (the default) is the newest, `1` behaves like pf-client 0.14, `-1` announces no protocol at all, like a client from before 0.14. For testing. |

## API overview

| Type | What it is |
|---|---|
| `Client` | One hub and one word. Built with `Client.builder()`: `server`, `word`, `sslContext` or `caFile`, `serveToken`, `clientToken`, `name`, `target`, `agent` (default `pfrelay-java 0.1.0`), `logger`, `events`, `maxProto`, `noReuse`, `maxIdleLegs`. `build()` checks every value (PROTOCOL.md §3) and throws `IllegalArgumentException`. |
| `Client.listen()`, `listen(Duration)` | Register, and return a `Listener`. |
| `Client.serve(target)`, `serve(target, Duration)` | Register, and forward each connection to a TCP `host:port`; returns a `Forwarder`. |
| `Client.dial()` | Open one connection; a `Conn`. |
| `Client.connect(ServerSocket)` | Forward each local connection through the tunnel; returns a `Forwarder`. |
| `Client.watch()` | Check the tunnel until closed (every 30 s while it is up, from 1 s doubling to 30 s while it is down); a `Watcher` with `isUp()`, `lastError()`, `close()`. |
| `Client.check()` | Returns if someone serves the word; throws `AccessDeniedException` otherwise. |
| `Client.probe()` | The hub's `ServerInfo` (version, protoMin, protoMax, token); needs a serve token. |
| `Client.drop(ConnId, reason)` | Drop an open connection, telling its far end why; false if no such connection is open. |
| `Client.stats()`, `conns()` | Local bookkeeping: `Stats` (opened, active, failed, sent, received) and the open connections as `ConnInfo` (id, side, opened, sent, received, wroteEof, readEof), every connection included, forwarded or not. |
| `Listener` | `accept()`, `isUp()`, `close()`. At most 128 connections wait for `accept()`; more are refused at once, their connecting side is told why, and `onRefuse` hears of it. |
| `Forwarder` | `isUp()`, `isClosed()`, `close()`. |
| `Conn` | `getInputStream()` (-1 at the far end's half-close), `getOutputStream()` (closing it half-closes), `shutdownOutput()`, `fail(reason)`, `close()`, `error()`, `id()`, `info()`, `setSoTimeout(ms)`. |
| `ConnId` | The hub's id for a connection, the same on both ends: opaque, with `equals`, `hashCode`, `toString()` (16 hex digits) and `shortForm()`. |
| `Side` | `CONNECT` or `SERVE`; prints as `connect` or `serve`. |
| `Words` | `newWord()`, `normalize(word)`. |
| `Tls` | `trusting(Path pem)`: an `SSLContext` that trusts a PEM file. |
| Exceptions | All are `IOException`s: `StatusException` (`code()`, `hubMessage()`, `isFinal()`), its subclass `AccessDeniedException` (403), `ProtoException` (`serverProto()`, `need()`), `RemoteException` (`reason()`: the far end or the hub said why), `DroppedException` (`reason()`: this side dropped it, with `fail` or `drop`). |

### Behavior worth knowing

- **TLS** is always verified, the host name included (IP addresses match
  IP SANs). Plain `http://` is refused. Pass `caFile` or `sslContext` for a
  hub whose certificate the JDK does not trust.
- **Protocol negotiation.** Every request offers `X-PF-Tunnel-Proto: min-2`,
  where `min` is 1 when the request depends on a client token or on serving
  without a serve token, and 0 otherwise. A hub that answers with a lower
  protocol (or none at all: a hub from before 0.14.0) is refused with a
  `ProtoException` rather than having the feature quietly ignored. Reusing
  legs is never depended on, so it never raises `min`.
- **Half-close and failure.** `read` returns -1 after the far end's `eof`.
  The hub may pass a failure on as `eof` first and the reason later, so
  `error()` can turn a finish into a failure after the fact.
  `close()` without both half-closes, or a lost link, is reported as a
  failure on the other side, never as a half-close.
- **Keepalive.** Each `Conn` pings every 10 seconds and gives up after 30
  seconds of silence; the control channel pings every 20 seconds and gives
  up after 60. Nothing relies on pongs.
- **Dropping.** `drop(id, reason)` cuts the stream at once; whoever holds
  the `Conn` sees its reads and writes fail, and `onClose` reports a
  `DroppedException` when it closes the connection (forwarders do at once).
- **Threads.** Each `Conn` has a reader thread, each `Listener`, forwarder
  and watcher a thread of its own; all are daemons. A `Conn` takes one
  reader and one writer at a time.

## Conformance

```sh
sdk/java/build.sh
PF_CONFORMANCE_DRIVER="sdk/java/driver.sh" go test -count=1 -run TestConformance .
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="sdk/java/driver.sh" go test -count=1 -run 'TestConformance/hub_2,_client_2/idle' .
```

Run them from the repository root. The suite runs every case against hubs
of protocols 2, 1 and 0, with the driver offering 2, 1 and 0
(`--proto-max`); `driver.sh protocols` prints `0-2`.

## License

Apache License 2.0; see [LICENSE](LICENSE).
