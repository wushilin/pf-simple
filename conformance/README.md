# Conformance suite

The suite checks a client implementation of the tunnel protocol
([`docs/PROTOCOL.md`](../docs/PROTOCOL.md)) against a real pf-simple hub. It
puts the implementation on one side or both sides of a tunnel, and the Go
SDK ([`pfrelay`](../pfrelay)) on the other. It also uses hub settings that
cannot be reached from outside: a hub that answers like protocol 0,
anonymous serving switched on and off, and a short idle timeout.

## Running it

```sh
# the Go SDK's own driver (built on the fly)
go test -run TestConformance .

# another SDK's driver: the command line that starts it
PF_CONFORMANCE_DRIVER="python3 -I sdk/python/driver.py" go test -run TestConformance .

# also the cases that take a minute (keepalive)
PF_CONFORMANCE_SLOW=1 PF_CONFORMANCE_DRIVER="..." go test -run TestConformance .
```

Run it from the repository root. It needs Go, and whatever the driver
needs.

## The driver

Each SDK ships a small program, its **driver**, that the suite starts once
for each step. The driver MUST use the SDK's public API in the way an
application would. Serving goes through the SDK's listen/accept API and
connecting through its dial API, so the suite tests what users get.

```
driver serve   --server URL --ca FILE --word WORD --target HOST:PORT
               [--serve-token T] [--client-token T] [--name NAME]
               [--mode listen|forward] [--no-accept]
driver connect --server URL --ca FILE --word WORD --listen HOST:PORT
               [--client-token T] [--mode listen|forward]
driver check   --server URL --ca FILE --word WORD [--client-token T]
driver version --server URL --ca FILE --serve-token T
driver protocols
```

`protocols` prints the range of tunnel protocols the driver speaks, such
as `0-2`, and exits. A driver without it is taken to speak `0-1`.

A driver of a QUIC SDK (pfrelay-quic, protocol 3) prints `3-3`. The suite
then runs every case with the hub's QUIC listener on: the driver reaches
the hub over QUIC, and the Go SDK on the other side of each case stays on
WebSockets, so each case also goes through the hub's bridge between the
two. The cases about protocol 2 (reuse) and older hubs do not apply, and
`--proto-max` is never passed. `go test -run TestConformanceQUIC .` runs
the Go SDK's own QUIC driver.

A driver that speaks protocol 2 also takes `--proto-max N` on every
command: the SDK then offers no protocol newer than N, to behave like an
older client. `1` behaves like pf-client 0.14, and `0` like one from before
0.14, which announces no protocol at all. Each SDK needs an option for this
(Go: `Client.MaxProto`).

`--mode` chooses which part of the SDK carries connections:

- `listen` (the default) uses the listen/accept and dial API, with the
  driver's own copy loop.
- `forward` uses the SDK's forwarders: serving to a TCP target, and
  connecting a local TCP listener.

The driver SHOULD define its commands, modes, queries, events and outcomes
as constants or enums of its language, not as string literals scattered
through the code. The Go driver (`go-driver/main.go`) shows the shape.

Flags may come in any order. Rules that apply to every command:

- **TLS.** `--ca` is a PEM file holding a test CA. The hub's certificate
  is a leaf for `127.0.0.1` that this CA signed, as with a hub that issues
  its own certificates. The driver MUST trust that CA and verify the hub
  against it. It MUST NOT turn verification off or loosen it.
- **Agent.** The driver SHOULD send an `X-PF-Version` that names the SDK,
  such as `pfrelay-py 0.1.0 conformance`.
- **Output.** Diagnostics go to stderr. Stdout carries only the lines below.
- **Exit codes:**

  | Code | Meaning |
  |---|---|
  | 0 | success |
  | 1 | any other failure |
  | 2 | wrong usage |
  | 3 | protocol error: the hub is too old for what was asked (PROTOCOL.md §5.3) |
  | 4 | access denied: the hub answered 403 |

### Events

While `serve` or `connect` runs, the driver installs the SDK's event
handlers and prints one line for each event. The tokens in each line are
separated by single spaces:

| Line | When |
|---|---|
| `ready` | the first time the tunnel is registered (`serve`) |
| `opened <id> <side>` | a connection opened; `<side>` is `connect` or `serve` |
| `closed <id> <sent> <received> ok\|failed` | a connection ended, exactly once per `opened`, with its final byte counts; `failed` when the SDK reports an error |
| `refused <id>` | this side refused a connection the hub offered (backlog full, target unreachable) |
| `tunnel up`, `tunnel down` | the SDK's watch: the first result, then every change (`connect`) |

`<id>` is the connection id as the SDK's opaque id type prints it: the
hub's 16 hex digits.

### Queries

While `serve` or `connect` runs, the driver reads lines from stdin and
answers each one on stdout with a single line: the query's name, a space,
and then JSON.

| Query | Answer |
|---|---|
| `stats` | `stats {"opened":N,"active":N,"failed":N,"sent":N,"received":N}`, from the SDK's stats |
| `conns` | `conns [{"id":"…","side":"connect","sent":N,"received":N}, …]`, from the SDK's list of open connections |
| `drop <id>` | `drop true` or `drop false`, from the SDK's drop-by-id. The driver drops the connection with the reason `dropped by the conformance suite` |

### `serve`

1. Register the tunnel. In `listen` mode that means the SDK's listen; in
   `forward` mode, its forwarder to `--target`. On success, print `ready`
   and flush stdout. On a refusal that waiting cannot cure, exit with the
   code above.
2. With `--no-accept` (`listen` mode only), register but never accept a
   connection, so that the backlog fills.
3. In `listen` mode, for each accepted connection, dial `--target` over TCP. If the dial
   fails, fail the connection with a reason; any text will do, such as
   `the serving side could not reach its target`. Otherwise copy both ways
   until both directions finish:
   - pass a half-close on in each direction: end of the tunnel stream
     becomes a TCP shutdown of the write side, and TCP EOF becomes the
     stream's half-close;
   - if either side fails, fail the stream with a reason and close both
     ends.
4. Keep serving, and register again after losing the hub, until it gets
   SIGTERM. Then exit 0.

### `connect`

1. Listen on `--listen` over TCP; port 0 means any port. Print
   `listening HOST:PORT` with the address actually bound, and flush stdout.
2. Start the SDK's watch, which prints `tunnel up` and `tunnel down`.
3. In `listen` mode, for each accepted TCP connection, open a connection
   through the tunnel (the SDK's dial), and copy both ways as `serve`
   does. If the dial fails, close the TCP connection and say why on
   stderr. In `forward` mode, hand the listener to the SDK's connect
   forwarder.
4. Run until SIGTERM, then exit 0.

### `check`

Ask whether the tunnel is up. Exit 0 if it is, 4 on a 403, 3 on a protocol
error, and 1 otherwise.

### `version`

Probe the hub's version. Print the answer as one line of JSON with at
least `version`, `protoMin`, `protoMax` and `token`, then exit 0. Exit 4 on
a 403.

## Protocol versions

`TestConformance` runs every case at each combination of the hub's and the
driver's protocols:

| Hub | Driver | Like |
|---|---|---|
| 2 | 2 | today's hub and SDK |
| 2 | 1 | a 0.14 client against today's hub |
| 2 | 0 | a client from before 0.14 against today's hub |
| 1 | 2 | today's SDK against a 0.14 hub |
| 0 | 2 | today's SDK against a hub from before 0.14 |

The hub plays the older ones itself. A driver that speaks only `0-1` runs
the combinations it can: hub 2, 1 and 0 with driver 1. A case that needs a
protocol 1 feature, such as a client token, runs only where both sides have
protocol 1. The slow case runs only in the first combination.

## The cases

| Case | What it shows |
|---|---|
| serve/echo to a Go connector | data both ways, half-close, 8 parallel connections, 1 MiB each |
| connect/echo through a Go server | the same, from the connecting side |
| both sides/echo | the SDK talking to itself through the hub |
| serve/the target speaks first, connect/the target speaks first | nothing waits for the application to speak first |
| serve/the target cannot be reached | the connecting side hears a reason (§8.3, including a reason that arrives after a half-close) |
| connect/nobody serves the word | the local connection ends at once |
| check | 204 and 403 |
| client token | registering a client token's hash, sending the token, refusal without it |
| serve/a wrong serve token is final | 403 on the first registration ends the run |
| serve/a word of another tenant is final | 409, with the hub's message shown |
| serve/anonymous | serving without a token, off and on |
| protocol 0 hub | features of protocol 1 are refused (§5.3); plain tunnels still work |
| version | the probe, and its refusal |
| serve/registers again after losing the hub | the retry loop (§9) |
| serve/retries with a growing pause | the first three registrations are refused with 503; the pauses are 1s, 2s and 4s (§9) |
| serve/a full backlog refuses with a reason | with `--no-accept`, 128 connections wait and the rest are refused with a reason, and reported as `refused` (§9) |
| stats/connect side, stats/serve side (both modes) | `stats` and `conns` agree with what was sent, the ids are the hub's, and `opened`/`closed` come exactly once per connection with the right figures |
| serve/drop a connection by its id (both modes) | dropping by id reaches the far end with the reason, and the connection closes as `failed` |
| forward/serve, forward/connect | echo through the forwarders |
| forward/serve: an unreachable target is reported at once | the forwarder refuses through `accept` with a reason, so the far end hears it on its first read |
| connect/watch reports the tunnel coming up | `tunnel down`, then `tunnel up` once someone serves |
| reuse/sequential connections reuse a leg (both modes) | protocol 2 on both sides: after the first, every connection runs on a reused leg (§12), each with its own events |
| reuse/an unreachable target on a reused leg is reported at once | the forwarder answers `bound`, then fails with a reason, which reaches the connecting side on its first read |
| reuse/a failed connection's leg is not reused | a failure is never reused, and the tunnel goes on working |
| reuse/never with an older side | in every other combination, no leg is ever reused |
| idle connections stay up (slow) | pings on streams and on the control channel (§7, §8.5) |

## Adding an SDK

1. Put the SDK under `sdk/<language>/` with its driver.
2. Run the suite until it passes, including the slow cases.
3. Add the driver to CI, in `.github/workflows/ci.yml`.
