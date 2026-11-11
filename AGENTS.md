# Notes for agents working on pf-simple

## The tunnel protocol is sealed

`pf-client` and the relay hub in `pf-simple` speak a versioned protocol.
Its definition is the comment at the top of
[`internal/tunnel/proto.go`](internal/tunnel/proto.go); read it before
touching anything under `internal/tunnel/`, `tunnel.go`, or
`cmd/pf-client/`.

**Protocol 1 is sealed** (it is what 0.14.0 speaks):

- `serve`: a word, a name and a target; a serve token, or none where the
  server allows serving without one; optionally a client token (sent as its
  SHA-256) that whoever connects must give.
- `connect` and `check`: a word; the client token if the tunnel has one.
- `accept`: a word and a connection id, or the reason there is no
  connection.
- `version`: a serve token; answers with the server's program version and
  protocol range. The server's version is told to nobody without a valid
  serve token: not in a header, not in an error.
- The `X-PF-*` headers, the WebSocket framing, and the `eof` and `err:`
  text frames.

Rules:

1. **Do not change protocol 1.** No header renamed, removed or given a new
   meaning; no new header that a peer has to understand; no change to the
   frames or to what a status code means to the other side. Released
   binaries in the field depend on it staying exactly as it is.
2. **Anything new on the wire is a new protocol version.** Raise
   `ProtoMax`, describe the version in `proto.go`, add it to
   `protoRelease`, give each new feature an entry in `featureProto`, make
   `Client.needs` name it, and make the server honor it only when the
   negotiated version allows. The steps are at the end of the comment in
   `proto.go`.
3. **Never decide behavior from the program version** (`X-PF-Version`). It
   is for logs and the console. Behavior follows the negotiated protocol
   number only.
4. **Keep speaking old versions.** One `pf-client` must work with servers
   of several ages and the other way round. Do not raise `ProtoMin`, and do
   not drop protocol 0 (peers from before 0.14.0 that announce nothing),
   unless the project's owner asks for it.
5. **A feature the peer cannot honor is refused loudly, never ignored.**
   The client raises the minimum it offers to the version of the newest
   feature the run depends on, and refuses a server that answers with less
   (`ProtoError`).
6. **Do not change the protocol on your own initiative.** If a task seems
   to need a wire change, say so and propose it as the next protocol
   version; do not slip it into the current one.

Changes that are not on the wire (logging, retries, the console, command
line flags, config keys) are not protocol changes and need no new version.
