# pf-simple

A small TCP port forwarder that supports multiple mappings.

**Zero copy** on Linux.

## Screenshots
<img width="424" height="404" alt="image" src="https://github.com/user-attachments/assets/80424dca-3f9d-421a-b118-126656d8ff63" />

<img width="1430" height="720" alt="image" src="https://github.com/user-attachments/assets/fc684662-7f2b-4c89-86be-6d16684d336d" />

<img width="565" height="527" alt="image" src="https://github.com/user-attachments/assets/d133e2c3-79a4-45de-9169-036deaa3db1b" />




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
idle for 30 seconds after that half-close, both sockets are closed. Intentional
waits for bandwidth limits do not count as idle time. SIGINT and SIGTERM stop
the listeners.

## Docker

Images for `linux/amd64` and `linux/arm64` are published for every release
as `wushilin/pf-simple` on Docker Hub and `ghcr.io/wushilin/pf-simple`.
Tags are the version (`0.7.0`), the minor line (`0.7`) and `latest`.

Host networking is the simplest fit for a forwarder: listeners bind straight
on the host, including ones added later in the console, with no `-p` per
port. The arguments are the same as for the binary:

```sh
docker run -d --name pf-simple --restart unless-stopped --network host \
  wushilin/pf-simple 8080@10.0.0.6 9030@db:9030 --console 18222@secret
```

The console is then on `http://127.0.0.1:18222/pf/` of the host.

With a config file, mount a writable directory at `/data`; the console
writes listener changes back to the file:

```sh
mkdir -p pf-data
cp pf-simple.example.toml pf-data/pf-simple.toml   # edit it first
chmod 600 pf-data/pf-simple.toml
docker run -d --name pf-simple --restart unless-stopped --network host \
  -v "$PWD/pf-data:/data" \
  wushilin/pf-simple -c /data/pf-simple.toml
```

Without `--network host`, publish each listen port and make the console
listen on every interface inside the container (`:18222`, not
`127.0.0.1:18222`):

```sh
docker run -d -p 8080:8080 -p 18222:18222 \
  wushilin/pf-simple 8080@10.0.0.6 --console :18222@secret
```

The image runs as root so listeners can bind ports below 1024 on the host
network. Add `--user 65532:65532` to run unprivileged; low ports then fail
to bind on the host network, and a mounted `/data` must be writable by that
user.

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

Limits keep the splice data path: pf-simple reserves bandwidth before sending
each chunk. Limited listeners use smaller chunks to keep the rate smooth.
On a Linux test host a listener with
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
  otherwise. Under systemd, keep the file in a `StateDirectory` (see
  [Running under systemd](#running-under-systemd)).

## Running under systemd

```ini
# /etc/systemd/system/pf-simple.service
[Unit]
Description=pf-simple TCP port forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
StateDirectory=pf-simple
ExecStart=/usr/local/bin/pf-simple --config /var/lib/pf-simple/pf-simple.toml
DynamicUser=yes
Restart=always
RestartSec=2
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

`DynamicUser=yes` runs pf-simple as a throwaway unprivileged user, and
`StateDirectory=pf-simple` gives that user a writable
`/var/lib/pf-simple/` for the config file, which the console rewrites. Let
systemd create the directory rather than making it yourself: on a host with
SELinux enforcing, systemd cannot adopt a directory that already exists
there. So, in order:

```sh
systemctl daemon-reload
systemctl start pf-simple          # fails on the missing config, but creates the directory
systemctl stop pf-simple
install -m 0600 pf-simple.toml /var/lib/pf-simple/pf-simple.toml
chown --reference=/var/lib/private/pf-simple /var/lib/pf-simple/pf-simple.toml
systemctl enable --now pf-simple
```

`/var/lib/pf-simple` is a symlink into root-only `/var/lib/private/`, so
only root and the service can read the file (it holds the console
password). Root can edit it by hand while the service is stopped. If you
run without a console, a read-only file passed in with `LoadCredential=`
works too, as shown in [Configuration file](#configuration-file).

Ports below 1024 need `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the
`[Service]` section, because the unprivileged user cannot bind them.

## Web console

Add `--console` (or a `[console]` table in the config file) to serve a live
dashboard:

```sh
./pf-simple --forward 0.0.0.0:8080@10.0.0.6:8080 --console 127.0.0.1:18222@xyz123
```

The value is `listen-address[@password]`. Without a password after `@`, the
password comes from `$PF_PASSWORD`; if that is empty too, the console is open
to anyone who can reach it.

Everything the console serves, the page, its assets and the `api/` endpoints,
lives under `/pf/`, so open `http://127.0.0.1:18222/pf/`. The bare `/`
redirects there; nothing else is served. The session cookie is scoped to
`/pf` as well. This lets a reverse proxy mount the console next to other
applications by path without rewriting anything:

```nginx
location /pf/ {
    proxy_pass http://127.0.0.1:18222;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;     # the live view is a WebSocket
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

The page builds its WebSocket URL from its own location, so it works at
whatever host and scheme the proxy presents. The `Origin` of the handshake
must match the `Host` the proxy forwards, hence `Host $host` above.

What it shows (the build version sits next to the name in the top bar;
`pf-simple --version` prints it too):

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
- Per-listener **Stop/Start**, and in config mode **Add listener**, **Edit**
  and **Delete** (see [Managing listeners from the console](#managing-listeners-from-the-console)).
- A **Flow log** tab: every connection from accept to close, newest first,
  including ones that never became pipes. Each row shows the listener,
  client, upstream, start time, duration, bytes each way and how it ended:
  `OPEN`, `CLOSED`, `RESET` (from the console, or its listener stopped),
  `IDLE TIMEOUT`, `FAILED` (target unreachable) or `REFUSED`
  (`max_connections`, or the listener was stopping). Hover a result for the
  reason. Filter by text or result, pause the view, or reset an open
  connection from its row. The last 2000 ended connections are kept in
  memory, so the log starts filled when you open it.
- An **API** tab: Swagger UI over the [REST API](#rest-api), to read the
  docs and try each call live with the page's session.

How it stays light:

- The server pushes state over a WebSocket only when something changed, at
  most once every 400 ms. An idle forwarder sends nothing but a ping every
  30 seconds. The page never polls.
- Each push is serialized once and handed to every open tab through a
  bounded broadcast queue
  ([go-named-queue](https://github.com/wushilin/go-named-queue)). The queue
  keeps 8 frames and drops the oldest when full, so a tab on a slow link
  misses stale frames instead of slowing the others, and nothing is
  serialized at all while no tab is open.
- Byte counters are per-pipe atomics. Live pipes sit in one registry whose
  mutex is only taken to add, remove or list them, so the console does not
  slow the copy path (see the benchmark below).
- A page left open forever uses bounded memory. Chart history is a fixed ring
  of 120 points, rate samples are capped, state for a closed pipe is dropped
  as soon as it disappears, at most 200 rows per listener are drawn, and each
  push carries at most the 500 newest pipes per listener (the true count is
  still shown).
- If the connection drops, the page reconnects on its own with backoff.

Everything the page needs (HTML, CSS, JavaScript, logo, Swagger UI) is compiled into the
binary with `go:embed`. It loads nothing from other sites, and the
Content-Security-Policy (`default-src 'self'`) makes the browser refuse
anything external. A test enforces both.

Security notes: the console speaks plain HTTP, so the password and session
cookie cross the network unencrypted. Bind it to `127.0.0.1` and use an SSH
tunnel (`ssh -L 18222:127.0.0.1:18222 host`), or keep it on a trusted network.
Sessions use an `HttpOnly`, `SameSite=Strict` cookie that lasts 12 hours and
are kept in memory, so restarting the forwarder signs everyone out. Logout and
session expiry also close that session's open WebSocket connections. Every
state-changing request needs a custom header, WebSocket connections from
other origins are refused, and a wrong password is answered after a one-second
delay.

### Flow log

The Flow log tab has its own WebSocket (`/pf/api/flows`), open only while
the tab is showing. Each connection's open and close events go to a second
broadcast queue (4096 events, drop-oldest), and nothing is built while no
page watches. Every 5 seconds the page also gets the authoritative list of
open connections, which repairs any event a slow page missed. Closed
connections live in a fixed ring of 2000 slots written with one atomic add,
so recording one never takes a lock.

### REST API

Everything the console does is also a JSON API under `/pf/api/`, described
by `/pf/openapi.json` and browsable in the console's API tab (or at
`/pf/swagger/`).

| Method & path | What it does |
|---|---|
| `GET /pf/api/health` | Liveness and build version; needs no authentication |
| `GET /pf/api/stats` | Totals: uptime, listeners, active connections, bytes |
| `GET /pf/api/policy` | Whether management is on, and the `allow_*` fences |
| `GET /pf/api/listeners` | Every listener with its counters |
| `POST /pf/api/listeners` | Add, start and save a listener |
| `POST /pf/api/listeners/validate[?id=N]` | Check a spec as add (or edit of N) would, without changing anything |
| `GET /pf/api/listeners/{id}` | One listener |
| `PUT /pf/api/listeners/{id}` | Edit a **stopped** listener (409 while running) |
| `DELETE /pf/api/listeners/{id}` | Delete a **stopped** listener |
| `POST /pf/api/listeners/{id}/start`, `/stop` | Start or stop it |
| `GET /pf/api/listeners/{id}/connections` | Its open connections |
| `GET /pf/api/connections[?listener=N]` | Every open connection, with live byte counters |
| `GET /pf/api/connections/{id}` | One open connection |
| `DELETE /pf/api/connections/{id}` | Reset it (TCP RST both ways) |
| `GET /pf/api/flows[?since=ms]` | Flow log as JSON; upgraded to a WebSocket, the live stream |

Authenticate with the console password in an `X-API-Token` header, or with
a console session cookie. A request that changes something must also carry
`X-PF-Console: 1` or `X-API-Token`. A browser cannot add either header to a
cross-site request, which is what stops cross-site request forgery. A wrong
token gets its 401 after a one-second delay, the same as a wrong password at
sign-in.

```sh
T='X-API-Token: secret'
curl -H "$T" http://127.0.0.1:18222/pf/api/listeners
curl -H "$T" -X POST -d '{"name":"web","listen":"18080","target":"10.0.0.6:8080"}' \
     http://127.0.0.1:18222/pf/api/listeners
curl -H "$T" -X POST http://127.0.0.1:18222/pf/api/listeners/2/stop
curl -H "$T" -X PUT -d '{"name":"web","listen":"18080","target":"10.0.0.7:8080"}' \
     http://127.0.0.1:18222/pf/api/listeners/2
curl -H "$T" -X POST http://127.0.0.1:18222/pf/api/listeners/2/start
```

The older routes the console page uses (`POST /pf/api/listeners/{id}/edit`,
`/delete`, `POST /pf/api/pipes/{id}/stop`, `GET /pf/api/state`) still work.
Swagger UI 5.17.14 is vendored under `console/swagger/` (Apache-2.0, see its
`LICENSE`).

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

macOS, FreeBSD and Windows have no socket-to-socket splice, so there
pf-simple uses a read/write loop with a 64 KiB buffer.

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
