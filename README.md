# pf-simple

A small TCP port forwarder that supports multiple mappings.

## Quick start

Give each mapping as `listen@target`, either as plain arguments or with
`--forward`/`-f`:

```sh
./pf-simple 8080@10.0.0.6                     # :8080 -> 10.0.0.6:8080
./pf-simple 8080@10.0.0.6:80 9030@db:9030     # two listeners
./pf-simple -f 127.0.0.1:4100@10.0.0.7:3306 --console 18222@secret
```

Defaults keep the common case short:

| You write | It means |
| --- | --- |
| `8080@10.0.0.6` | listen on every interface, port 8080; forward to `10.0.0.6:8080` |
| `127.0.0.1:4100@db:3306` | exactly those addresses |
| `9030@[2001:db8::6]` | IPv6 target (brackets required), port 9030 |
| `--console 18222` | console on `127.0.0.1:18222` only; use `:18222` for every interface |
| `--console 18222@secret` | console password `secret`; without `@...` it comes from `$PF_PASSWORD` |

Flags and mappings can come in any order. `pf-simple -h` prints the usage.
Anything more (names, connection caps, speed limits) goes in a
[configuration file](#configuration-file), started with `-c`/`--config`.

The two directions of a connection are copied independently. When one
direction reaches EOF, the forwarder half-closes the corresponding destination
socket so the other side can still send a final response. If the connection is
idle for 30 seconds after that half-close, both sockets are closed. SIGINT and
SIGTERM stop the listeners.

## Configuration file

For anything beyond simple mappings, put the setup in a TOML file:

```sh
./pf-simple -c /etc/pf-simple.toml      # or --config /etc/pf-simple.toml
```

`-c`/`--config` cannot be combined with any other flag or with mappings on
the command line: `pf-simple -c pf.toml --forward 8080@x` exits with an
error naming `--forward`. Unknown keys are errors too, so a typo stops
pf-simple at startup instead of being silently ignored. The address
shorthand above works in the file as well.

```toml
# Optional web console; leave the table out to disable it.
[console]
listen = "127.0.0.1:18222"
password = "change-me"        # or leave out to use $PF_PASSWORD

[[forward]]
name = "HTTP"                 # optional; the console shows "HTTP [0.0.0.0:8080]"
listen = "0.0.0.0:8080"
target = "10.0.0.6:8080"

[[forward]]
name = "Doris MySQL"
listen = "0.0.0.0:9030"
target = "10.0.0.6:9030"
max_connections = 200
total_speed = "1GiB/s"
per_connection_max_speed = "15MiB/s"
```

Each `[[forward]]` takes:

| Key | Required | Meaning |
| --- | --- | --- |
| `listen` | yes | Address to accept connections on. |
| `target` | yes | Address to forward each connection to. |
| `name` | no | Label for the console and logs. Without it the listen address is shown. |
| `max_connections` | no | Most simultaneous connections. Further clients are refused with an immediate TCP reset and counted as "refused" in the console. Default: unlimited. |
| `total_speed` | no | Speed limit shared by all connections on this listener. Default: unlimited. |
| `per_connection_max_speed` | no | Speed limit for each connection. Default: unlimited. |

Speed limits exist only in config files, not on the command line. When both
are set, both are enforced: a connection never exceeds its own cap, and all
connections together never exceed the total. Each limit applies to each
direction separately (client to target and target to client), like a
full-duplex link. Units are `B`, `KB`, `MB`, `GB` (1000-based), `KiB`, `MiB`,
`GiB` (1024-based), or bit rates `bit`, `Kbit`, `Mbit`, `Gbit` (also `Kbps`,
`Mbps`, `Gbps`); `/s` is optional, so `512B/s`, `14KiB/s`, `100Mbit` and
`1GiB/s` all work.

Limits keep the splice data path: pf-simple waits between chunks rather than
copying through a buffer, and uses smaller chunks on limited listeners so the
rate stays smooth. On a Linux test host a listener with
`per_connection_max_speed = "40MiB/s"` held one iperf3 stream at 40.0 MiB/s,
and `total_speed = "100MiB/s"` held four streams at 100.0 MiB/s combined.

A config file may also hold only a `[console]` table and no forwards, since
the console can add them; with neither, pf-simple refuses to start.

The `[console]` table takes `listen` (required) and `password` (optional,
falling back to `$PF_PASSWORD`; empty means no password). If the file holds a
password and is readable by every user, pf-simple prints a warning; use
`chmod 600`. See [`pf-simple.example.toml`](pf-simple.example.toml) for a
commented example.

To run it as a systemd service without a console, keep the file root-owned
with `chmod 600` and pass it in with `LoadCredential`, so the unprivileged
service user can read it while nobody else can:

```ini
[Service]
LoadCredential=pf-simple.toml:/etc/pf-simple.toml
ExecStart=/usr/local/bin/pf-simple --config %d/pf-simple.toml
DynamicUser=yes
Restart=always
```

With a `[console]`, the console writes listener changes back to the file, so
it must live somewhere writable instead; see
[Managing listeners from the console](#managing-listeners-from-the-console).

## Managing listeners from the console

What the console may change depends on how pf-simple was started:

| Action | Command line | Config file (`-c`) |
| --- | --- | --- |
| Disconnect a pipe (Stop on a row) | yes | yes |
| Stop / Start a listener | yes, until restart | yes, saved |
| Add a listener | no | yes |
| Edit a listener (every field) | no | yes, while stopped |
| Delete a listener | no | yes, while stopped |

On the command line, a console alone is refused, because it could not add
anything. In a config file, `[console]` alone is fine: start it empty and add
listeners from the browser. Every change is written back to the config file.

```toml
[console]
listen = "0.0.0.0:20000"
password = "change-me"
# Optional fences for listeners added or edited in the console.
# An omitted one means no restriction.
allow_target_hosts = ["10.0.0.6", "10.0.0.0/24", "db.internal"]   # IPs, CIDRs, exact hostnames
allow_target_ports = "80, 8080, 9030, 3000-3999"
allow_bind_hosts = ["0.0.0.0", "127.0.0.1"]                       # "0.0.0.0" or "::" allows "all interfaces"
allow_bind_ports = "18000-19999"
```

- **Fences.** A hostname is matched by name only and never resolved, so DNS
  cannot redirect it. Without any fences, anyone with the console password can
  make the host relay to any address it can reach, so set at least
  `allow_target_hosts` on a host that is exposed.
- **Stop** stops accepting, resets every open pipe, and waits for them to
  close before it reports success. A stopped listener is saved as
  `enabled = false`.
- **Edit and Delete** need a stopped listener. Edit keeps the listener's
  counters; it stays stopped until you start it.
- **Saving** rewrites the whole file atomically (temporary file, fsync,
  rename) with mode 600. `[console]` is written back exactly as loaded; a
  password that came from `$PF_PASSWORD` is never written into the file.
  Comments are not kept.
- **Startup.** In config mode a listener whose port is busy shows "failed to
  start" in the console while the others keep running. On the command line a
  busy port stops pf-simple, as before.
- **Writable location.** With a `[console]`, pf-simple checks at startup that
  it can create files in the config file's directory and refuses to start
  otherwise. Under systemd, keep the file in a `StateDirectory`:

```ini
[Service]
StateDirectory=pf-simple
ExecStart=/usr/local/bin/pf-simple --config /var/lib/pf-simple/pf-simple.toml
DynamicUser=yes
Restart=always
```

## Web console

Add `--console` (or a `[console]` table in the config file) to serve a live
dashboard:

```sh
./pf-simple --forward 0.0.0.0:8080@10.0.0.6:8080 --console 127.0.0.1:18222@xyz123
```

The value is `listen-address[@password]`. Without a password after `@`, the
password comes from `$PF_PASSWORD`; if that is empty too, the console is open
to anyone who can reach it.

What it shows:

- A summary strip: active pipes, accepted connections, current throughput in
  each direction, bytes transferred, uptime, and a two-minute throughput chart.
- One table per listener (`listen → target`, or `name [listen] → target`)
  with a sparkline, live rates and totals, plus its connection cap and speed
  limits when set. Expand it to list its active pipes (forwarded connections), newest
  first, with client address, age, TCP state (`ESTABLISHED`, `CLIENT FIN`,
  `UPSTREAM FIN`, `CLOSING`, `RESET`) and per-direction rates.
- Expand a pipe to see both legs, client ⇄ pf-simple and pf-simple ⇄
  upstream, with bytes counted in all four directions, half-close markers and
  bytes still in flight.
- A filter box that matches addresses, ports and `#id`.
- **Stop** on each pipe (click twice to confirm) resets it: both sockets close
  with `SO_LINGER 0`, so both peers get a TCP RST.

How it stays light:

- The server pushes state over a WebSocket only when something changed, at
  most once every 100 ms. An idle forwarder sends nothing but a ping every
  30 seconds. The page never polls.
- Byte counters are per-pipe atomics. Live pipes sit in one registry whose
  mutex is only taken to add, remove or list them, so the console does not
  slow the copy path (see the benchmark below).
- A page left open forever uses bounded memory. Chart history is a fixed ring
  of 120 points, rate samples are capped, state for a closed pipe is dropped
  as soon as it disappears, at most 200 rows per listener are drawn, and each
  push carries at most the 500 newest pipes per listener (the true count is
  still shown).
- If the connection drops, the page reconnects on its own with backoff.

Everything the page needs (HTML, CSS, JavaScript, logo) is compiled into the
binary with `go:embed`. It loads nothing from other sites, and the
Content-Security-Policy (`default-src 'self'`) makes the browser refuse
anything external. A test enforces both.

Security notes: the console speaks plain HTTP, so the password and session
cookie cross the network unencrypted. Bind it to `127.0.0.1` and use an SSH
tunnel (`ssh -L 18222:127.0.0.1:18222 host`), or keep it on a trusted network.
Sessions use an `HttpOnly`, `SameSite=Strict` cookie that lasts 12 hours and
are kept in memory, so restarting the forwarder signs everyone out. Every
state-changing request needs a custom header, WebSocket connections from
other origins are refused, and a wrong password is answered after a one-second
delay.

## Data path: zero-copy on Linux

On Linux, pf-simple moves bytes with `splice(2)`, so payload data never
enters user space:

```
client socket ──splice──▶ kernel pipe (64 KiB) ──splice──▶ upstream socket
```

Each direction of each connection owns one kernel pipe. pf-simple asks the
kernel to move up to 64 KiB from the source socket into the pipe, then from
the pipe into the destination socket. The data stays in kernel memory the
whole way, so there is no `read()` into a Go buffer and no `write()` back
out, and two system calls move each chunk. "Zero-copy" here means no copies
into or out of user space; the kernel may still copy internally, depending on
the network driver.

The sockets stay non-blocking. When a socket has no data or no room, the
goroutine parks in Go's network poller instead of holding a thread, so
thousands of idle connections cost almost nothing. Closing a socket from
another goroutine (Stop in the console, the idle timeout, shutdown) wakes it
immediately.

Go's own `TCPConn.ReadFrom` also splices, but it returns only after its byte
limit or EOF, so the console would see a slow trickle of traffic only in large
steps and the idle timer would misfire. pf-simple runs its own splice loop and
counts every chunk, which keeps the console accurate and the half-close idle
timeout correct. Speed limits keep this path too: pf-simple waits between
chunks instead of switching to a buffer.

In numbers, on a Linux test host (see the benchmark below), splice forwarded
a single localhost stream 20 to 35% faster than a user-space copy, and four
streams at about the speed of a direct connection. `strace` during a transfer
shows only `splice` calls carrying data, no `read` or `write`.

macOS and FreeBSD have no socket-to-socket splice, so there pf-simple uses a
read/write loop with a 64 KiB buffer.

## Performance test (localhost to localhost)

Run an `iperf3` server, put the forwarder in front of it, and point the
client at the forwarded port:

```sh
iperf3 -s -p 5201 &
./pf-simple --forward 127.0.0.1:5202@127.0.0.1:5201 &

iperf3 -c 127.0.0.1 -p 5201 -t 10        # baseline, no forwarder
iperf3 -c 127.0.0.1 -p 5202 -t 10        # through pf-simple
iperf3 -c 127.0.0.1 -p 5202 -t 10 -R     # reverse direction
iperf3 -c 127.0.0.1 -p 5202 -t 10 -P 4   # 4 parallel streams
```

Sample results, 10 second runs:

| Host | Path | 1 stream | 1 stream `-R` | 4 streams |
| --- | --- | --- | --- | --- |
| Linux 6.12 x86_64, 12 cores | direct (no forwarder) | 59.1 Gbit/s | — | 59.3 Gbit/s |
| | pf-simple, splice | **35.8 Gbit/s** | **33.8 Gbit/s** | **62.7 Gbit/s** |
| | pf-simple, 64KiB buffer | 28.3 Gbit/s | 29.2 Gbit/s | 51.5 Gbit/s |
| | previous `io.Copy` version | 29.5 Gbit/s | 25.6 Gbit/s | 45.9 Gbit/s |
| macOS, Apple Silicon | direct (no forwarder) | 92.1 Gbit/s | — | — |
| | pf-simple, 64KiB buffer | 36.1 Gbit/s | — | — |

The forwarded path uses two loopback hops instead of one, so a single stream
cannot match the direct baseline. With 4 streams the forwarder spreads work
across more cores and keeps up with the direct path.
