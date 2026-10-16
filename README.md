# pf-simple

A small TCP port forwarder that supports multiple mappings:

```sh
./pf-simple \
  --forward 0.0.0.0:4099@10.0.0.6:2778 \
  --forward 127.0.0.1:4100@10.0.0.7:3306
```

Each mapping listens on the address before `@` and connects to the address
after it. Repeat `--forward` as many times as needed. Use bracketed IPv6
addresses when specifying ports, for example `[::1]:4099@[2001:db8::6]:2778`.

The two directions of a connection are copied independently. When one
direction reaches EOF, the forwarder half-closes the corresponding destination
socket so the other side can still send a final response. If the connection is
idle for 30 seconds after that half-close, both sockets are closed. SIGINT and
SIGTERM stop the listeners.

## Data path

On Linux, each direction is copied with `splice(2)` through a 64KiB kernel
pipe, so payload bytes never enter user space. The sockets stay non-blocking
and wait in Go's netpoller, so a half-close (EOF) on one side ends that
direction while the other keeps flowing, and closing a socket interrupts a
pending copy. Other platforms (macOS, FreeBSD) have no `splice`, so they use a
read/write loop with a 64KiB buffer.

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
