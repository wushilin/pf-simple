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
