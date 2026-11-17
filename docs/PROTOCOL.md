# The pf-simple tunnel protocol

This document defines how a client (`pf-client`, or a program using one of
the SDKs) talks to the relay hub of `pf-simple`. It is the reference for
anyone writing a client in another language. It describes what pf-simple
0.16.0 speaks: over WebSocket, protocols 0 and 1 (§1 to §11) and protocol
2, which adds reusing the serving side's legs (§12); and over QUIC,
protocol 3 (§13). The conformance suite in
[`conformance/`](../conformance/README.md) checks it against the
implementation.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
RFC 2119.

The authoritative short form of the protocol versions is the comment at the
top of [`internal/tunnel/proto.go`](../internal/tunnel/proto.go). If this
document and that comment ever disagree, that is a bug in this document.

## 1. Overview

A tunnel connects an *application* on one machine to a *target* on another,
through a hub that both can reach over HTTPS. Neither side needs an open
port.

```
application --TCP-- connecting side ==WS== hub ==WS== serving side --TCP-- target
                    (pf-client connect)              (pf-client serve)
```

- The **serving side** registers a tunnel under a secret **word** and keeps a
  **control channel** (one WebSocket) open to the hub.
- The **connecting side** opens one WebSocket per TCP connection, naming the
  same word.
- For each such connection the hub sends the serving side an **open**
  message with a connection id over the control channel. The serving side
  answers by opening a second WebSocket to the hub with that id (the
  **accept** leg), or by saying why it cannot.
- The hub then copies bytes between the two legs. Each leg carries one
  **stream**: the bytes of one TCP connection, with half-close and a
  reason when it fails.

Nothing is buffered or resumed. A broken WebSocket ends its connection. A
broken control channel ends the tunnel and every connection in it; the
serving side registers again, and the connecting side opens new
connections.

## 2. Transport

- Every request goes over **TLS** (`https://`). A client MUST refuse a
  plain `http://` base URL. The hub refuses a request that reached it
  without TLS (status 400). A reverse proxy that terminates TLS tells it
  with `X-Forwarded-Proto: https`.
- **HTTP/1.1** only. A client that uses ALPN MUST offer `http/1.1`; it
  MUST NOT negotiate HTTP/2.
- WebSockets are **RFC 6455**, version 13, with no subprotocol and no
  extensions. A client MAY offer extensions (such as permessage-deflate);
  the hub accepts none, so none are in use.
- A client MUST NOT send an `Origin` header naming a host other than the
  hub's. Non-browser clients normally send no `Origin` at all.
- **Base URL.** The user gives the hub as `https://host[:port]`, optionally
  followed by a path: the hub's **prefix**, where the hub is mounted. One
  trailing `/` is ignored. An empty path, or `/`, means the prefix `/pf`,
  which is where every hub is unless its admin chose another. So
  `https://host` and `https://host/pf/` are the same hub, and
  `https://host/xzfe-aeeg-e2da/` is the hub mounted at `/xzfe-aeeg-e2da`.
  - A prefix is one or more segments, each `/` followed by 1 to 64 of
    `A-Z a-z 0-9 . _ ~ -`, and no segment is `.` or `..`; at most 200
    characters in all. It is case-sensitive. A client MUST refuse any
    other path (an empty segment, `%`-escapes, other characters), and a
    base URL with a query, a fragment or user information.
  - The endpoints are under:

    ```
    https://host[:port]<prefix>/api/tunnel/<endpoint>
    ```

    `https://host[:port]/pf/api/tunnel/<endpoint>` for a hub at the
    default prefix.
  - The prefix is not on the wire in any other way and is not negotiated:
    a client given the wrong prefix gets 404 from every endpoint.
    Clients from before pf-simple 0.16.3 (pf-client, the Go SDK) and SDK
    packages from before 0.16.2 accept only the default prefix. A hub at
    another prefix is hidden from whoever does not know it, and is closed
    to those clients.

  where `<endpoint>` is `serve`, `connect`, `accept`, `check` or `version`,
  and `quic` for discovering the QUIC listener (§13.2).
  All of them use the `GET` method.
- Every secret travels in a header, never in the URL, because reverse
  proxies log URLs.

## 3. Values

### 3.1 Word

A word names one tunnel. It is three groups of four ASCII letters or
digits, joined by `-`: `k3f9-x2mq-7hpa`. Case does not matter.

- A client MUST trim surrounding white space and lower-case the word, and
  MUST check it against `^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$` before
  sending it.
- A generated word SHOULD use only `abcdefghjkmnpqrstuvwxyz23456789` (no
  `0 o 1 i l`), chosen uniformly by a cryptographic random source.

### 3.2 Serve token

The permission to register tunnels on a hub, issued by the hub's admin.
It is 32 to 128 printable ASCII characters (`0x21`–`0x7E`). A client
SHOULD check this before sending it. The hub keeps only its SHA-256.

### 3.3 Client token

An optional second secret the serving side asks of whoever connects. It
is 8 to 128 printable ASCII characters (`0x21`–`0x7E`).

- The serving side sends its SHA-256 as 64 lower-case hex digits.
- The connecting side sends the token itself.

### 3.4 Tunnel name

What the hub's console calls the tunnel, chosen by the serving side. It is
UTF-8 text, 1 to 64 characters after trimming, with no control
characters. On the wire it is URL-query-escaped: space becomes `+`, other
reserved bytes become `%XX`. An example is Go's `url.QueryEscape`, or
Python's `urllib.parse.quote_plus`.

### 3.5 Connection id

A connection id is chosen by the hub. It is 16 lower-case hex digits (64
random bits). Clients MUST treat it as opaque text. In logs, the first 8
characters are enough to tell connections apart.

## 4. Headers

| Header | Sent by | On | Meaning |
|---|---|---|---|
| `X-PF-Tunnel-Session` | hub, then client | serve (101), then accept | protocol 2: the registration's secret (§12.3) |
| `X-PF-Tunnel-Keep-Alive` | hub | accept (101) | protocol 2: the offer to reuse the leg (§12.3) |
| `X-PF-Tunnel-Proto` | client | every request | the protocol range this request can use, `min-max` (§5) |
| `X-PF-Tunnel-Proto` | hub | every answer past the TLS check | the protocol it chose, a single number |
| `X-PF-Version` | client | every request | the client program and version, such as `pf-client 0.14.0`; for logs only (§5.4) |
| `X-PF-Tunnel-Word` | client | serve, connect, accept, check | the word (§3.1) |
| `X-PF-Serve-Token` | client | serve, version | the serve token (§3.2); on serve, leave it out to register anonymously |
| `X-PF-Tunnel-Name` | client | serve | the tunnel name, escaped (§3.4) |
| `X-PF-Tunnel-Target` | client | serve | what the serving side forwards to, such as `localhost:22` or `stdio`; for the console only |
| `X-PF-Client-Token-SHA256` | client | serve | SHA-256 of the client token, 64 hex digits; leave it out for no client token |
| `X-PF-Client-Token` | client | connect, check | the client token, if the tunnel has one |
| `X-PF-Tunnel-Conn` | client | accept | the connection id being answered |
| `X-PF-Tunnel-Conn` | hub | connect (101) | the id the hub gave this connection |
| `X-PF-Tunnel-Error` | client | accept | why the serving side cannot carry this connection |
| `X-PF-Tunnel-Op` | client | quic (discovery) | protocol 3: what the QUIC run is for, `serve` or `connect` (§13.2) |

Header names are case-insensitive, as in HTTP. A request MUST NOT repeat
any of these headers.

## 5. Protocol versions

The protocol has a version number of its own, separate from the program
versions. Each side speaks a range of versions, and they use the highest
version both have.

- **Protocol 0** is the name for a side that announces no version:
  pf-simple and pf-client before 0.14.0. Such a hub understands a word, a
  serve token, a name and a target. It may or may not do the rest of
  protocol 1 without saying so, so a client MUST NOT rely on anything else
  with it.
- **Protocol 1** (pf-simple 0.14.0) is everything in §1 to §11. It is
  **sealed**: nothing in it will ever change. Anything new is protocol 2
  or later.
- **Protocol 2** (pf-simple 0.15.0) adds one optional thing: reusing the
  serving side's accept legs (§12). Nothing depends on it, so a client
  offering `0-2` works with hubs of every age.
- **Protocol 3** (pf-simple 0.16.0) is the QUIC transport (§13). It is
  spoken only over QUIC and negotiated there; the WebSocket endpoints
  stay at 0 to 2.

### 5.1 What the client offers

In `X-PF-Tunnel-Proto`, the client sends `min-max`, two decimal numbers
with `0 <= min <= max`. A single number `n` means `n-n`.

- `max` is the highest protocol the client implements over WebSocket. Today that is `2`.
- `min` is the protocol of the newest **feature** this request depends on:

  | Feature | Protocol | Requests that depend on it |
  |---|---|---|
  | client token | 1 | serve, connect and check, when a client token is set |
  | anonymous serve | 1 | serve, when no serve token is given |
  | reusing accept legs | 2 | none: it is optional, so nothing ever raises `min` for it (§12) |

  With none of them, `min` is `0`.

Raising `min` makes a hub that knows about versions refuse a request it
cannot honor, instead of quietly ignoring the feature.

### 5.2 What the hub answers

- The hub answers **every** request with its choice in `X-PF-Tunnel-Proto`
  as a single number, whether it refuses the request or not, including the
  101. The choice is `min(max, hub's max)`.
- If that choice is below the client's `min`, or below the hub's own
  minimum, the hub answers `426 Upgrade Required`. The body is a JSON
  error saying which side to upgrade. In that answer `X-PF-Tunnel-Proto` is
  the hub's highest protocol.
- A malformed range is `400`.

There are two exceptions, which carry no `X-PF-Tunnel-Proto`:

- a hub whose relay is switched off (or a server without one) answers
  `404` with an empty body;
- a request that did not come over TLS gets `400`.

### 5.3 What the client checks

A protocol 0 hub sends no `X-PF-Tunnel-Proto` and ignores what it does not
understand. So the client MUST check every answer, refusals included,
except `404`:

- read `X-PF-Tunnel-Proto` as the hub's protocol; if it is missing or not a
  number, the hub's protocol is 0;
- if any feature the request depends on needs a higher protocol than that,
  stop with a *protocol error*: tell the user that the hub is too old for
  that feature and must be upgraded. Waiting or retrying cannot help.

### 5.4 Program versions

`X-PF-Version` is free text identifying the client, normally
`<program> <version>`, such as `pf-client 0.14.0` or `pfrelay-py 0.1.0`.
The hub shows its first 40 printable characters in its log and console.

**No behavior may depend on it**, on either side. Behavior follows the
negotiated protocol number only.

The hub never sends its own program version, except in the answer to
`version` (§6.5).

## 6. Endpoints

All refusals carry a JSON body `{"error": "<message>"}` with
`Content-Type: application/json`, unless noted otherwise. A reverse proxy
in front of the hub may answer with anything, so a client SHOULD show the
`error` field when there is one, and otherwise a short plain-text body.

### 6.1 Status codes common to all endpoints

These come before the endpoint is looked at:

| Status | Meaning | Retry? |
|---|---|---|
| 404, empty body | no relay hub here (switched off, or not configured) | no |
| 400 | not over TLS, or a malformed `X-PF-Tunnel-Proto` | no |
| 426 | no protocol in common (§5.2) | no |
| 429 | too many refused attempts from this address; `Retry-After: 60` | yes, later |

**Guessing protection.** Every `403` costs the hub about one second before
it answers. An address that collects 30 refusals within a minute gets
`429` for the rest of that minute, whether its next guess is right or
wrong. When too many refusals are being delayed at once, the hub answers
`429` immediately instead of `403`.

### 6.2 `serve`: register a tunnel and hold its control channel

This is a WebSocket upgrade. The request headers are:

- the word;
- the name;
- the target;
- the serve token, or none for an anonymous registration;
- the client-token hash, optionally.

The answers are:

| Status | Meaning | Retry? |
|---|---|---|
| 101 | registered; this WebSocket is the control channel (§7) | — |
| 400 | bad word, name or client-token hash; the body says which | no |
| 403 | wrong serve token; no token where the hub requires one; or the tenant was just deleted or rotated | no |
| 409 | this word is bound to another tenant | no |
| 503 | anonymous, and the word is already being served (an anonymous serve cannot take over); or the tenant is at its limit of 256 words, all currently served | yes |

Rules of registration:

- The first tenant to serve a word owns it, until an admin releases it, or
  until the tenant binds so many words that the one it served longest ago
  is released.
- A tenant serving a word it already serves **takes it over**. The hub ends
  the old control channel and every connection in it. This is how a
  serving side that lost its link gets back in before the hub has noticed.
- Anonymous registrations belong to a tenant named `anonymous`. They need
  the hub's "allow serving without a token" switch.

### 6.3 `connect`: open one connection through the tunnel

This is a WebSocket upgrade. The request headers are the word, and the
client token if the tunnel has one.

| Status | Meaning |
|---|---|
| 101 | `X-PF-Tunnel-Conn` names the connection; this WebSocket is a stream (§8) |
| 403 | no tunnel under this word, or a missing or wrong client token; the hub does not say which |

**The 101 comes before the serving side has answered.** The hub then asks
the serving side for its leg, and waits up to 10 seconds. If the serving
side does not answer in time, or reports a failure, the hub sends
`err:<reason>` on the stream and closes it (§8.3). So a connecting side
learns that the target is unreachable from its first read on the stream,
not from the handshake.

### 6.4 `check`: is the tunnel there?

This is a plain GET, not an upgrade. The request headers are the word, and
the client token if the tunnel has one.

| Status | Meaning |
|---|---|
| 204 | someone serves this word, and the client token, if one is needed, is right |
| 403 | otherwise, as for `connect` |

### 6.5 `version`: the hub's version

This is a plain GET. The request header is a serve token. The serve token
is required even on hubs that allow anonymous serving.

| Status | Meaning |
|---|---|
| 200 | JSON: `{"version": "0.15.0", "protoMin": 0, "protoMax": 2, "token": "<tenant name>"}` |
| 403 | no serve token, or a wrong one |
| 404 | the relay is off, or the hub is older than 0.14.0 |

Clients MUST ignore JSON fields they do not know.

### 6.6 `accept`: the serving side's leg of a connection

The serving side sends this request after an open message (§7). The
request headers are the word and the connection id. No serve token and no
client token are needed.

The connection id is random, and it reaches two parties: the serving side,
over the control channel, and the connecting side, in the 101 of its
`connect` (§6.3). So whoever connects could also answer `accept` for its
own connection. That gains it nothing, since it would only be talking to
itself, but `accept` is not proof of being the serving side. Nothing may be
granted on the strength of an `accept` alone.

There are two forms:

- **To carry the connection:** a WebSocket upgrade. A `101` makes this
  WebSocket the serving side's stream (§8).
- **To refuse it:** a plain GET with a non-empty `X-PF-Tunnel-Error`. The
  answer is `204`. The hub passes the reason (printable ASCII, at most 128
  characters) to the connecting side as `err:<reason>`.

The refusals are:

| Status | Meaning |
|---|---|
| 403 | nobody serves this word |
| 404, JSON body | no pending connection with this id: it has ended, or was already answered |

Each connection id can be answered once. The hub waits 10 seconds for the
answer, counted from the open message.

## 7. The control channel

The control channel is the WebSocket of a successful `serve`.

- **Hub to serving side:** a text frame holding a JSON object:

  ```json
  {"open": "8f14e45fceea167a"}
  ```

  This means "connection 8f14e45fceea167a is waiting; answer it at
  `accept`" (§6.6). The serving side SHOULD answer each open concurrently,
  and promptly: the hub gives up after 10 seconds. It MUST ignore text
  frames that are not such an object, or that lack a non-empty `open`, and
  it MUST ignore fields it does not know.
- **Serving side to hub:** nothing but control frames.
- **Keepalive:**
  - The serving side MUST send a WebSocket ping at least every 60
    seconds; it SHOULD send one every 20 seconds.
  - The hub answers each ping with a pong, and sends no pings of its own.
  - Either end treats 60 seconds without receiving any frame as a dead
    link.
- **Frame size:** frames on the control channel are at most 4096 bytes.
- **The end:** the control channel ends when either side closes it, or
  when the link dies. Then the tunnel and its open connections are gone.
  The serving side SHOULD register again (§9).

## 8. Streams

A stream is what a `connect` or `accept` WebSocket carries after its 101.
It is one TCP connection's bytes in both directions, plus half-close and a
reason when it fails. Both legs of a connection use the same framing.

### 8.1 Frames

| Frame | Meaning |
|---|---|
| binary (opcode 2), and its continuation frames (opcode 0) | the next bytes of the stream, in order |
| text `eof` | the sender's half-close (its FIN): no more data from it |
| text `err:<reason>` | the stream is being dropped, and why (§8.3) |
| close (opcode 8) | the end of the stream (§8.4) |
| ping (opcode 9) | keepalive (§8.5) |
| pong (opcode 10) | ignored |

Rules for frames:

- **Data frames.** Each data frame carries at most 1 MiB. A receiver drops
  the stream if a frame is larger. Senders SHOULD send at most 64 KiB per
  frame. Empty data frames are allowed and carry nothing.
- **Text frames** MUST NOT be fragmented (FIN set, no continuation), and
  are at most 1024 bytes. A receiver ignores any text frame other than
  `eof` and `err:…`. On a leg offered reuse (protocol 2), `idle`, `bind`
  and `bound` are frames too (§12).
- **Order.** Data, `eof` and `err:` frames are read in the order they are
  sent, so `eof` follows the last byte of data.
- **Masking.** As RFC 6455 requires, a client masks every frame it sends
  and the hub masks none. A frame masked the wrong way breaks the stream.
- **Extensions.** No extensions, and no RSV bits, are used.

### 8.2 Half-close

After sending `eof`, an end MUST NOT send more data on that stream; the
other end treats data after `eof` as a broken stream. Each direction closes
on its own: the end that received `eof` may keep sending until it sends
its own `eof`.

The hub passes a half-close through to the other leg. After a half-close,
the hub ends a connection that carries nothing either way for 30 seconds.

### 8.3 Failure: `err:`

An end that drops a stream for a reason the other end cannot see for
itself MUST send `err:<reason>` and then a close frame. Examples: its local
TCP connection was reset, it is shutting down, or the target was
unreachable.

The reason is free text for people. It SHOULD say which hop broke, such as
`the target reset its connection to pf-client serve`. A receiver MUST
treat it as untrusted: strip characters that are not printable, and cut it
to 200 characters before logging it.

The hub also sends `err:` when it ends a leg, naming what happened on the
other leg. A receiver reports a stream that ended this way as failed, with
that reason.

**A failure can arrive after a half-close.** The hub copies each direction
on its own. When one leg fails, the hub ends that direction toward the
other leg with `eof`, the same as a clean finish. The reason follows as
`err:<reason>` only when the hub ends the whole connection. That happens
when the other direction ends as well, or after the 30-second idle timeout
(§8.2). On a serving leg offered reuse it does not follow: the hub ends
that leg's generation instead (§12.5).

So a receiver that has read `eof` MUST keep reading the stream: it can
still receive `err:`, which turns the finish into a failure. pf-client and
the SDKs report the connection as failed in that case.

### 8.4 Ending a stream

- **A clean finish** is when both ends have sent `eof`. Then each end sends
  a close frame, which carries no payload or only a 2-byte status code. It
  then waits up to 3 seconds for the other end's close, and closes the TCP
  connection.
- **A close without both `eof`s** is a broken stream. So is a TCP
  connection that ends without a close frame. A receiver MUST NOT take
  either for a half-close: it reports the stream as failed, not finished.
- On receiving a close frame, an end answers with a close frame, as RFC
  6455 requires.

### 8.5 Keepalive

- Each end of a stream SHOULD send a ping every 10 seconds, on its own
  timer, whether it hears pings or not. It MUST send one at least every 30
  seconds.
- Each end treats 30 seconds without receiving any frame as a dead link.
- Pings on streams are not answered. A pong is harmless, and is ignored,
  so a WebSocket library that answers pings by itself is fine. **A peer
  MUST NOT rely on getting a pong.**

## 9. Recommended client behavior

This part is not on the wire, and other clients may differ. It is how
pf-client behaves, and SDKs SHOULD do the same so users meet one
behavior.

- **When to give up.** Retrying cannot help after a refusal with a
  4xx status other than 408 and 429, or after a protocol error. The client
  reports those and stops.
- **Serving.**
  - The first registration fails on any refusal of that kind.
  - Any other failure is retried with a growing pause: 1 second, doubling
    up to 30 seconds. This includes a hub that cannot be reached, and a
    lost control channel.
  - After a control channel that lasted at least a minute, the pause
    starts again from 1 second.
  - Once a tunnel has been up, the client retries even refusals of that
    kind. The hub may have been briefly reconfigured.
- **Serving to a TCP target.** Connect to the target first, and answer
  `accept` with `X-PF-Tunnel-Error` if it cannot be reached. The
  connecting side then hears the reason at once.
- **Accepting.** A serving side that hands connections to an application
  holds at most 128 that have not been accepted yet. It refuses the rest
  at once through `accept` with `X-PF-Tunnel-Error`, so the connecting
  side is not left waiting.
- **Connecting.** Use `check` to tell the user whether the tunnel is up,
  but open each connection with `connect` regardless: a tunnel may come up
  or go away at any time.
- **Messages for the user.** Turn 403 into "access denied". Show the
  hub's message for 409 and 426. Turn a 404 with an empty body into "this
  server does not accept tunnels".
- **Certificates.** Verify the hub's certificate normally. When it does
  not verify, a client MAY let the user pin it by its SHA-256 fingerprint
  for that run.

## 10. Example

A connection through a tunnel, as seen on the wire. Headers that do not
matter here are left out. `S` is the serving side, `C` the connecting
side, `H` the hub.

```
S -> H  GET /pf/api/tunnel/serve HTTP/1.1
        Upgrade: websocket
        X-PF-Tunnel-Proto: 0-1
        X-PF-Version: pf-client 0.14.0
        X-PF-Tunnel-Word: k3f9-x2mq-7hpa
        X-PF-Serve-Token: 1d9f...(40 chars)
        X-PF-Tunnel-Name: Office+SSH
        X-PF-Tunnel-Target: localhost:22
H -> S  HTTP/1.1 101 Switching Protocols
        X-Pf-Tunnel-Proto: 1

C -> H  GET /pf/api/tunnel/connect HTTP/1.1
        Upgrade: websocket
        X-PF-Tunnel-Proto: 0-1
        X-PF-Tunnel-Word: k3f9-x2mq-7hpa
H -> C  HTTP/1.1 101 Switching Protocols
        X-Pf-Tunnel-Proto: 1
        X-PF-Tunnel-Conn: 8f14e45fceea167a

H -> S  (control) text {"open":"8f14e45fceea167a"}
S -> H  GET /pf/api/tunnel/accept HTTP/1.1
        Upgrade: websocket
        X-PF-Tunnel-Proto: 0-1
        X-PF-Tunnel-Word: k3f9-x2mq-7hpa
        X-PF-Tunnel-Conn: 8f14e45fceea167a
H -> S  HTTP/1.1 101 Switching Protocols

C -> H -> S   binary "SSH-2.0-OpenSSH_9.6\r\n" ...
S -> H -> C   binary ...
C -> H -> S   text "eof"
S -> H -> C   text "eof"
both legs     close
```

## 11. Conformance

[`conformance/`](../conformance/README.md) runs a real hub and drives a
client through every case in this document, including:

- interoperability with the Go client in both directions;
- a protocol 0 hub;
- the refusals.

An SDK conforms when it passes the suite. See that README for how to plug
in a new implementation.

## 12. Protocol 2: reusing accept legs

Protocol 2 (pf-simple 0.15.0) is protocol 1 plus one optional feature. A
side that does not speak it, or does not want it, sees exactly protocol 1.

### 12.1 What it adds

Protocol 2 adds one optional thing to protocol 1: the serving side's
`accept` legs can be **reused**.

- Today, every connection costs the serving side a new WebSocket to
  `/accept`: a TCP connect, a TLS handshake, the upgrade, and the round
  trip of the open message.
- Under protocol 2, a leg whose connection is over may stay open, idle,
  however the connection ended, as long as the leg itself is healthy. The
  hub hands the tunnel's next connection to that leg with one frame,
  instead of asking for a new one.

The scope is deliberately small:

- **No leg is ever opened in advance.** Only a leg that has just carried a
  connection can be reused.
- **Only the registered serving side can offer legs for reuse.** It proves
  this with a secret it got when it registered (§12.3). An `accept` alone
  proves nothing: the connecting side also knows the connection id (§6.6).
- **Both sides must take part.** If either side does not, the leg closes as
  in protocol 1.
- **It is an optimization, never a requirement.** Not getting it is never
  an error (§5.3).
- **Only serving-side legs.** Connecting-side legs (`/connect`) are
  unchanged.

### 12.2 Compatibility

The hub chooses a protocol for every request (§5). Everything in this
section needs **both** of these:

- the tunnel's registration (`serve`) negotiated protocol 2; and
- the `accept` negotiated protocol 2.

Every other request is answered exactly as in protocol 1, byte for byte.

| Serving side | Hub | Chosen | Result |
|---|---|---|---|
| protocol 0 (before 0.14) | protocol 2 | 0 | protocol 1 behavior |
| offers `0-1` (0.14, today's SDKs) | protocol 2 | 1 | protocol 1 behavior |
| offers `0-2` | protocol 1 | 1 | protocol 1 behavior |
| offers `0-2` | protocol 2 | 2 | legs may be reused |

Further rules:

- **Connecting sides** of any protocol are unaffected, in every
  combination.
- **The client's minimum stays at the protocol of the features its request
  depends on** (§5.1).
- **`ProtoMin` stays 0.**

### 12.3 The registration secret, and the offer

**On the `serve` 101,** when protocol 2 was negotiated, the hub adds:

```
X-PF-Tunnel-Session: 3f9a0c7e5b2d4e8f1a6c9b0d7e2f4a1c
```

- **The value** is 32 lower-case hex digits: 128 random bits, new for every
  registration. Only the serving side that registered sees it.
- **It is a secret,** like the tokens. It is never logged and never put
  in an error body. The client sends it only on `accept`, never on
  `connect`, `check` or `version`.
- **It is valid** for as long as that control channel lives.

**On `accept`,** a serving side that wants its leg to be reusable sends the
session as `X-PF-Tunnel-Session`, along with the word and the connection
id.

**On the `accept` 101,** the hub MAY add:

```
X-PF-Tunnel-Keep-Alive: 60
```

- **When.** Only if all of these hold:
  - both requests negotiated protocol 2 (§12.2);
  - the session matches the tunnel's current registration (compared in
    constant time);
  - reuse is switched on;
  - the limits of §12.6 leave room.

  Otherwise the hub sends no offer, and the leg is a protocol 1 leg.
- **A missing or wrong session** is not an error, and is not counted as a
  guess. The accept itself still works as in protocol 1, because the
  connection id alone authorizes carrying one connection (§6.6).
- **The value** is the most seconds the hub keeps this leg idle each time
  it becomes idle (§12.6).
  - It is decimal digits only, no sign and no white space, from 1 to 3600.
  - The header appears at most once.
  - A client that cannot parse it treats it as no offer.
  - The client needs the value only to know that the offer was made; it
    MAY use it to close idle legs a little earlier on its own.
- **The offer is for the life of the leg.** The hub may withdraw it at any
  time: by closing an idle leg, or by ending a connection with a close
  instead of `idle` (§12.5).

### 12.4 Leg states

```
          (accept 101 with the offer)
                    |
                    v
   +----------> CARRYING <-------------------------------------+
   |                | generation over: hub sends "idle"         |
   |                v                                           |
   |            OFFERED --- client closes, or 3 s pass ---> closed
   |                | client sends "idle"                       |
   |                v                                           |
   |              IDLE ---- either closes; the idle limit ---> closed
   |                | hub sends "bind <id>"                     |
   |                v                                           |
   |            BINDING --- no "bound" in 2 s, or the leg dies ---> closed
   |                |                                           (the hub falls back, §12.7)
   +-- client sends "bound <id>" -------------------------------+
```

A leg without the offer only has CARRYING, then closed, as in protocol 1.

**What each side may send in each state.** Pings and pongs are allowed in
every state, in both directions, and keepalive (§8.5) runs throughout.
Unknown text frames are ignored, as in §8.1.

| State | Hub may send | Client may send | Anything else is |
|---|---|---|---|
| CARRYING | as in §8, then `idle` (§12.5) | as in §8 | as in §8 |
| OFFERED | nothing | `idle`, or a close | a violation |
| IDLE | `bind <id>`, or a close | a close | a violation |
| BINDING | a close | `bound <id>`, or a close | a violation |

A **violation** closes the leg at once. If a connection was on it
(BINDING), the hub falls back as in §12.7.

- **Known frames in the wrong state are violations,** not unknown text.
  For example, an `idle` or `bound` from the client while CARRYING, or a
  `bound` whose id is not the one bound.
- **Legs without the offer** are protocol 1 legs. There, these words are
  unknown text, ignored as §8.1 says, though a conforming peer never sends
  them.

### 12.5 The end of a generation: the hub's `idle`

Each connection a leg carries is one **generation** of the leg. The leg's
fate depends on the leg alone, never on how the connection ended: a
connection that the connecting side's application, network or program
ends badly leaves a healthy serving leg behind, and the leg is reused.

1. **A generation ends when both `eof`s have passed on the serving leg:**
   the hub sent its `eof`, and received the serving side's. One `eof` is
   only a half-close (§8.3): the other direction may go on carrying data
   for as long as it likes.
2. **The hub completes the generation when the connection ends otherwise.**
   The connecting side failed or went away (§8.3), or the hub ended the
   connection itself, such as by the idle rule of a half-closed connection
   (§8.4). Then, if the serving leg is healthy:
   - the hub sends its `eof` on the serving leg, unless it has already;
   - it then reads the serving leg and drops what arrives, since nobody is
     left to receive it, up to the serving side's `eof`. The serving side
     sends it in the usual way: its target was half-closed by the `eof`,
     and closes in turn;
   - if that `eof` has not come within 3 seconds, the hub closes the leg.
     A target that keeps talking after a half-close costs the leg.

   No data from one generation reaches the next: everything the serving
   side sends before its `eof` belongs to the generation that ended.
3. **The leg is healthy** unless its link failed or went silent, the
   serving side ended the connection with `err:` (it closes the leg after
   it), the connection was reset by the hub's console, or the tunnel is
   ending. Then the hub closes the leg as in protocol 1.
4. **On an offered leg whose generation is over, the hub sends the text
   frame `idle`,** instead of starting the close handshake. The leg is
   OFFERED. The hub sends nothing more for that connection: no `err:`
   follows an `idle`.
5. **The client answers within 3 seconds:**
   - **`idle`:** it keeps the leg, which joins the tunnel's idle pool
     (§12.6);
   - **a close:** it does not want the leg. The hub answers the close, and
     the leg is gone.
   - **If neither comes in time,** the hub closes the leg.
6. **The connection's outcome is the hub's to record.** A connection that
   failed on the connecting side still counts as failed, with its reason,
   in the hub's flow log and counters, though its serving leg is reused.
   The serving side does not learn that reason: on its leg the connection
   ended with an `eof`, as when the application closes its end (§8.3).
7. **The client reports the connection as finished when it receives the
   hub's `idle`,** with its close event and final figures.
   - Until then, the outcome is open.
   - An `err:` or a close without `idle` means protocol 1 rules apply
     (§8.3, §8.4).
   - The client waits at most 3 seconds after both `eof`s. If no verdict
     has come by then, it closes as in §8.4 and reports by protocol 1
     rules, so a silent hub never delays a connection's end by the
     30-second silence limit.
   - A client that has already sent its close ignores an `idle` that
     crosses it.
8. **After the client's `idle`,** both ends forget the connection: its id,
   its half-close state, its byte counts and its reason.

A client that never answers `idle`, because it does not want reuse or does
not know protocol 2, simply closes. That costs nothing but the reuse.

### 12.6 The idle pool

The hub keeps the idle legs of each tunnel in a pool. A leg belongs to the
registration it was offered under, and never passes to another one.

- **Only legs without a connection.** The idle limit and the pool concern
  legs that carry no connection. A connection, busy or quiet, is never
  closed by them.
- **Idle limit, max idle and min idle.** These are configurable per tunnel
  in the hub's config file and console (defaults 60 s, 10 and 3):
  - **max idle:** the most idle legs the pool holds. A leg beyond it is
    closed instead of pooled.
  - **idle limit:** a leg idle for longer than this is closed, unless min
    idle keeps it. The clock restarts each time the leg becomes idle. It
    is the value of the offer (§12.3).
  - **min idle:** the most recently idle legs, up to this number, are kept
    past the idle limit. Above it, expired legs are closed one at a time,
    oldest first, until only min idle remain.
  - **Min idle never opens a leg.** If traffic leaves fewer idle legs than
    min idle, the pool stays smaller until real connections bring legs
    back. Legs kept by min idle stay open indefinitely, pinged every 10
    seconds by each side (§8.5).
  - **The client may still close any idle leg** (§12.9). Min idle is the
    least the hub keeps, never a demand on the client.
- **Limits.** These are defaults; the console can change them:
  - at most 256 idle legs per tenant, the anonymous tenant included;
  - at most 4096 for the whole hub.

  They win over a tunnel's max idle and min idle. A leg that would exceed
  any limit gets no offer at `accept`, or is closed instead of being
  pooled.
- **A switch.** The console can turn reuse off. The hub then makes no new
  offers, and closes the idle legs it has.
- **Which leg next.** For a new connection, the hub takes the leg that
  became idle most recently. The hub SHOULD skip a leg it has heard nothing
  from for longer than 15 seconds, and close it: it may be dead, and
  binding it would only delay the connection.
- **The registration ends.** When the control channel ends, or another
  registration takes the word over (§6.2), the hub closes every leg of the
  old registration. That includes legs that are OFFERED, IDLE or BINDING,
  and connections in BINDING fail with the hub's usual reason ("the tunnel
  closed"). The hub MUST check, under the same lock as the takeover, that
  the registration is still current before it puts a leg in the pool.
- **The client may close an idle leg at any time.** The hub forgets it.
- **No failed connection.** A closed idle leg carries none, so the hub
  never logs it as a failed connection.

### 12.7 Reuse: `bind` and `bound`

When a connection arrives for a tunnel whose pool has a leg, the hub takes
it (§12.6) and sends:

```
bind 8f14e45fceea167a
```

That is the text frame `bind`, one space, and the connection id (§3.5). The
id is everything after the first space, and `bound` must repeat it byte for
byte. The leg is now BINDING.

- **The client answers at once** with `bound 8f14e45fceea167a`, the same
  id, before doing anything else, such as dialing a target.
  - `bound` only says "this leg is alive, and takes the connection".
  - The leg is then CARRYING the new connection, under the rules of §8, as
    a new stream.
- **If the connection then cannot be carried,** for example because the
  forwarder cannot reach its target, or the listener's backlog is full, the
  client ends it the protocol 1 way: `err:<reason>` and a close. The
  connecting side hears the reason as `err:` on its first read, exactly as
  in §6.3. The leg is not reused.
- **Reasons at once.** On a leg that was offered reuse, the hub passes an
  `err:` from the serving side on to the connecting side at once, instead
  of a half-close first and the reason later (§8.3). The serving side
  answers `bound` before it dials its target, so this is how the
  connecting side hears an unreachable target on its first read.
- **No data before `bound`.** The hub MUST NOT send data, `eof` or `err:`
  for the new connection before it has received a `bound` with that id.
  The client may be closing the idle leg at that very moment, and data sent
  on it would be lost.
- **Falling back.** If no `bound` arrives within 2 seconds, or a `bound`
  with another id arrives, or the leg closes or dies first, the hub closes
  the leg and never uses it again: a late `bound` on it is ignored. The connection has
  not been touched, so the hub asks for a new leg as in protocol 1
  (`{"open": id}`, §7), with the same id, within the same 10-second limit
  (§6.3).
- **The same id may come twice: a new attempt.** A client may receive
  `{"open": id}` for an id it had answered `bound` for, when its `bound`
  was lost with a dying leg. It treats the open as a **new attempt** at
  that connection:
  - it ends the old attempt: it closes the old leg, and with it the target
    socket or the connection it gave the application;
  - it reports the old attempt as failed, with the reason "the leg was
    lost before the server took the connection";
  - it then carries the connection on the new leg, as in protocol 1: a
    fresh dial, or a new connection for the application.

  This is safe because the hub sent nothing for that id on the old leg. So
  the target and the application got nothing from the connecting side
  through it. Bytes the application or target wrote on the old leg are
  lost, but they never reached anyone.

  A client's events may therefore name the same id twice, the first time
  as failed. An SDK MAY wait for the first frame from the hub before it
  hands a listener's application the connection, but it is not required
  to: that cannot work for protocols where the server speaks first.
- **The connecting side leaves during BINDING.** The hub waits for
  `bound`, and then ends the new stream with `err:` and the usual reason. A
  leg that misses `bound` is closed, as above.
- **Each connection is new.** Each `bind` gives a new id, its own
  half-close state, its own byte counts, and its own open and close events
  on both sides. The hub's console, flow log and per-word counters list it
  like any other connection.
- **The flow log.** A `bind` that is refused with `err:` appears in the
  hub's flow log as a failed connection with that reason, as an
  `X-PF-Tunnel-Error` refusal does today. Reasons are cut to 128 printable
  ASCII characters, as for `X-PF-Tunnel-Error` (§6.6).

### 12.8 What does not change

- **Connecting legs, the control channel, and every endpoint other than
  `serve` and `accept`** are as in protocol 1.
- **The stream framing of §8** is unchanged, apart from the new frames:
  - `idle`, `bind` and `bound` are text frames, at most 1024 bytes and
    never fragmented, like every text frame on a stream;
  - they are only ever sent on legs with the offer.
- **The 10-second limit for answering a connection** (§6.3, §6.6) still
  holds, counted from the connection's arrival, including any fallback.

### 12.9 Recommended client behavior

This part is not on the wire.

- **Accepting the offer.** Reuse SHOULD be on by default when the hub
  offers it. An SDK SHOULD let the application turn it off, and set how
  many idle legs it keeps at most (default 16). It closes the rest by
  answering the hub's `idle` with a close.
- **Its own idle limit.** An SDK MAY close idle legs before the hub's
  limit.
- **The application never sees legs.** Each connection, whether `bind` or
  `open`, arrives as a new connection through the listener's accept or the
  forwarder, with the events of a new connection.
- **The registration ends.** When the control channel is lost, the SDK
  closes all its legs that are OFFERED, IDLE or BINDING: the hub has
  dropped them. After registering again, it uses the new session.

### 12.10 Testing

The conformance suite (§11) runs every case at each combination of the
hub's and the client's protocols: 2 with 2, 1 and 0, and 1 and 0 with 2.
Where both speak 2, it checks that legs are reused, including after a
connection the connecting side failed. Everywhere else, it checks that
legs are never reused.

## 13. Protocol 3: the QUIC transport

Protocol 3 lets a client reach the hub over **QUIC** instead of
WebSockets. The relay is unchanged: the same words, tokens, tenants and
rules (§3, §6), the same meeting of a serving side and a connecting side.
Only the transport between a client and the hub is new.

- **Protocol 3 lives in its own SDK, `pfrelay-quic`.** All of it goes
  there: discovery, the QUIC connection, keepalive, `serve`, `connect` and
  `check`.
  - The Go SDK comes first, as a separate package built on quic-go, so
    pfrelay and pf-client never carry that library.
  - Python, Rust and Java follow later, each as `pfrelay-quic`.
  - The conformance suite checks each of them, as it does the WebSocket
    SDKs (§13.13).
- **`pf-client-quic` is a thin command line over that SDK,** as pf-client
  is over pfrelay. Its `serve`, `connect` (including stdio) and `check` are
  the SDK's, so a program using the SDK behaves exactly like the binary.
- **The SDK keeps pfrelay's shape.** Its API mirrors pfrelay's: a client
  made from a hub URL, a word and tokens; `Serve`, `Dial`, `Check`; the
  same events and errors. Moving a program from WebSocket to QUIC should
  mean changing the import, little more. The shape is not on the wire, so
  it belongs to the SDK's own docs, not to this protocol.
- **Protocol 3 exists only over QUIC.** The WebSocket endpoints speak
  protocols 0 to 2, unchanged, and know nothing of it (§13.11). A QUIC
  client and a WebSocket client work together through the hub, which
  bridges them (§13.9): compatibility is by bridging, not by a shared
  version range.
- **Both transports meet at the hub.** A side on QUIC works with a side on
  WebSockets, in either role (§13.9).
- **There is no fallback.** If QUIC cannot reach the hub, pf-client-quic
  says it failed to connect. Where UDP is blocked, use pf-client.

### 13.1 Overview

```
application --TCP-- pf-client-quic connect ==QUIC==  hub  ==QUIC or WS== serving side --TCP-- target
```

1. **Discovery.** Over the existing HTTPS endpoint, the client asks the
   hub where its QUIC listener is and which certificate it uses (§13.2).
2. **The client opens a QUIC connection to that listener.** It pins the
   certificate by its fingerprint (§13.3).
3. **Each request is one bidirectional QUIC stream** (§13.4).
   - `connect` is one stream per TCP connection, so stdio uses exactly one
     stream.
   - `serve` is one stream kept open as the registration. One QUIC
     connection may hold several registrations.
   - For each connection to a registration, the hub opens a new stream
     **to** the serving side. That stream replaces both the open message
     and the `accept` request.
4. **On a stream,** the connection's bytes travel in small frames, with
   `eof` and `err` as in §8 (§13.5).

QUIC streams are cheap, so a connection simply gets a new stream.
Protocol 2's leg reuse has no counterpart here.

**The discovery endpoint and the QUIC listener are the same hub process.**
The QUIC listener is not load-balanced away from the HTTPS endpoint, so
what discovery answers is what the listener does.

### 13.2 Discovery: `quic`

This is a plain `GET https://host[:port]<prefix>/api/tunnel/quic`, under §2
and §4. Its certificate is verified normally (§9). That is what makes the
fingerprints it returns trustworthy.

- **No protocol negotiation.** Discovery is not a WebSocket request and
  carries no `X-PF-Tunnel-Proto`; the protocol over QUIC is negotiated in
  each QUIC request (§13.4). The client sends `X-PF-Version` as usual.
- **What the run is for.** The request MUST carry `X-PF-Tunnel-Op:
  serve` or `X-PF-Tunnel-Op: connect`. Without it, or with any other value,
  the answer is 400.
  - This header is new. It exists only on this endpoint, which only
    protocol 3 has, so no older peer ever sees it.
  - A check counts as `connect`.
- **Credentials** are the ones the run is about to use, so discovery tells
  nobody more than `check` would:

  | `X-PF-Tunnel-Op` | Headers | Accepted when |
  |---|---|---|
  | `serve` | `X-PF-Serve-Token`, or none to serve anonymously | the serve token is valid; or there is none and the hub allows anonymous serving |
  | `connect` | `X-PF-Tunnel-Word`, and `X-PF-Client-Token` if the tunnel has one | `check` would answer 204 (§6.4) |

**Answers:**

| Status | Meaning | Retry? |
|---|---|---|
| 200 | JSON, below | — |
| 403 | the credentials were refused, as for `serve` or `check`; guessing protection applies (§6.1) | no |
| 400 | no `X-PF-Tunnel-Op`, or an unknown one | no |
| 404 | the hub does not offer QUIC: it is older than pf-simple 0.16.0, or its relay hub is off | no |
| 501, JSON body | the hub offers QUIC, but its QUIC listener is off, or has no advertised host | yes, later |
| 429 | as in §6.1 | yes, later |

**A hub without QUIC** knows no `quic` endpoint, and answers it 404, with
or without a body. The client MUST stop with a clear message, such as
"this hub does not offer QUIC: it is older than pf-simple 0.16.0, or its
relay hub is off; upgrade it, or use pf-client (WebSocket)". Waiting cannot
help, so it does not retry.

The 200 body:

```json
{
  "host": "gate.wushilin.net",
  "port": 443,
  "fingerprints": ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
}
```

- **`host`** is the advertised host that the hub's admin set in the
  console or the config (§13.10). It is either:
  - a DNS name;
  - an IPv4 address; or
  - an IPv6 address **without** brackets, such as `2001:db8::1`.

  It can change without a restart. The hub cannot know its public address
  behind a proxy or a NAT, so it never guesses one.
- **`port`** is 1 to 65535. A client refuses any other value.
- **`fingerprints`** are 1 to 4 lowercase hex SHA-256 values, each of the
  **DER encoding of a leaf certificate** the listener may present. While
  a certificate is being replaced there are two of them (§13.10).
- Clients MUST ignore JSON fields they do not know.

**When to discover again:**
- at the start of each run;
- before each new QUIC connection, such as a re-registration after a lost
  link, so a changed address or certificate is picked up;
- once more after a fingerprint mismatch (§13.3).

**A connecting side started before its serving side** gets 403 from
discovery, as it would from `check`. For a one-off `connect` (stdio) that
is the answer. A connecting listener (`pf-client-quic connect` on a local
port) MUST NOT treat it as fatal: it reports it, and discovers again for
the next TCP connection, as §9 says ("open each connection regardless").


### 13.3 The QUIC connection

- **QUIC version 1** (RFC 9000) with TLS 1.3 (RFC 9001), and nothing else.
  A client that gets a Version Negotiation packet fails loudly: "the hub's
  QUIC listener does not speak QUIC version 1".
- **ALPN `pf-tunnel`.** The protocol number is negotiated per request
  (§13.4), not by ALPN.
- **SNI** is the advertised `host` when it is a DNS name. When it is an IP
  address, the client SHOULD send no SNI (RFC 6066 §3); some QUIC
  libraries, such as kwik, send it anyway. The hub MUST ignore SNI: it has
  one certificate, and the pin is what the client checks.
- **Certificate pinning.**
  - The client MUST accept the hub's certificate if and only if the
    SHA-256 of its leaf certificate's DER encoding is one of the
    discovered `fingerprints`.
  - The check MAY be made inside the TLS library's verification hook, or
    after the handshake but **before the client opens any stream**. Some
    libraries, such as aioquic and kwik, may offer only the latter.
  - Only the chain, the name and the dates go unchecked. The TLS handshake
    itself is verified as usual, including the CertificateVerify
    signature. Without that, a pinned fingerprint proves nothing.
  - **On a mismatch,** the client discovers once more (§13.2) and tries
    again with the new fingerprints. A second mismatch fails the attempt
    loudly: "the hub's QUIC certificate does not match what its HTTPS
    endpoint announced". The certificate is never accepted. A one-off
    request (connect, check) reports it and stops; a serving side counts it
    as a failed attempt and tries again with its usual growing pause
    (§9), since a hub replacing its certificate, or a fault that is put
    right, should not leave it stopped for good.
- **The hub's certificate.**
  - An X.509 v3 certificate, self-signed and generated by the hub.
  - Its key is ECDSA P-256, and it signs with `ecdsa_secp256r1_sha256`.
  - Its subject alternative name is the advertised host: a dNSName for a
    DNS name, an iPAddress for an IP address. Nobody checks it, but some
    libraries refuse a certificate without one.
  - Its subject is only a common name, the advertised host, so the
    certificate says nothing about what serves it. A client MUST NOT check
    the subject. (Hubs before 0.16.3 named it `pf-simple relay hub`; such a
    certificate stays valid until it is replaced.)
  - Changing the advertised host does not replace the certificate, so the
    fingerprint stays. The name in the certificate follows at the next
    replacement (§13.10).
- **No 0-RTT, no resumption.**
  - The hub MUST NOT accept 0-RTT data, and the client MUST NOT send it. A
    replayed `serve` would be a takeover (§6.2).
  - The hub MUST NOT issue session tickets, so every handshake is a full
    one and shows the certificate to be pinned. Clients keep their QUIC
    connections for a long time (below), so this costs little.
- **Keepalive and idle timeout** are part of every QUIC connection to the
  hub (§13.6).
- **Only bidirectional streams.** Both ends allow 0 unidirectional
  streams. Neither uses QUIC DATAGRAM frames, nor offers the extension.
- **Library version.** The Go side uses quic-go v0.65.0 or later, for
  path validation after NAT rebinding on the hub (§13.6).
- **Connections and requests.**
  - A QUIC connection carries any number of requests, and any number of
    registrations (§13.4).
  - A client SHOULD keep one QUIC connection per hub for a whole run, and
    open a new one only when it is lost.

#### Stream limits and flow control

The numbers are per QUIC connection.

| | Before the connection's first successful request | After it |
|---|---|---|
| bidirectional streams the hub allows the client | 1000 | 1000 |
| the hub's connection receive window | at most 256 KiB | allowed to grow to at least 16 MiB |
| the hub's stream receive window, on each client stream | at least 64 KiB | at least 64 KiB |

- **Window growth.** QUIC libraries set an initial window and a maximum.
  The window grows as data is read, up to the maximum, and quic-go lets
  the hub veto each increase. So "allowed to grow" is a rule about the
  maximum, and about not vetoing growth once the connection has a
  successful request.
- **Memory before authentication.**
  - **The hub reads one request at a time** on a connection that has had
    no successful request yet. The bytes on its other streams stay unread,
    so they count against the connection window and are never given back.
  - So an unauthenticated connection can make the hub hold at most 256
    KiB, plus the one request (4096 bytes) it is reading. With §13.8's
    limit of 64 connections, that is 16 MiB per address.
  - A small stream limit before authentication is not an option. quic-go,
    like most libraries, cannot raise MAX_STREAMS later.
- **Memory after authentication.** One valid word unlocks 1000 streams of
  up to 128 KiB each, counting window and buffer. So the hub also allows
  at most 4096 open client streams per address, across its connections.
  Beyond that, a request gets 429.
- **Hub-wide caps.** Per-address limits do not bound the whole hub: IPv6
  gives one client many /64s, and anyone with a word can stall their own
  serving side. So the hub also caps, across all addresses:
  - its QUIC connections (default 10000): beyond it, it refuses
    handshakes (`CONNECTION_REFUSED`);
  - the bytes it buffers for QUIC streams (default 1 GiB): beyond it,
    new requests get 429 (`"scope": "address"`).

  Both are settings (§13.10).
- **One stalled stream must not starve the others.**
  - **Each end,** hub and clients alike, reads each carrying stream's
    data into a buffer of its own, of up to 64 KiB per stream, and stops
    reading that stream when its buffer is full. So the connection window
    is given back, and a stalled stream holds up only itself. For the
    hub, that starts once it has accepted the stream's request.
  - Without this, a serving side with a few hundred stalled targets
    would fill its own connection window. New opens and `end` messages
    would then stall, and the hub would time out healthy connections.
  - Each end SHOULD make its connection window at least 16 times its
    stream window.
- **A serving side** MUST allow the hub at least 128 concurrent
  bidirectional streams per connection, as many as it may hold
  connections waiting to be accepted (§9). It SHOULD allow 1000.
  - §9's 128 is per registration, but stream credit is per connection.
    So a serving side SHOULD hold at most 7 registrations (1000 / 128) on
    one QUIC connection, and open another connection for more.
  - Its stream receive window MUST be at least 64 KiB.
  - Its connection receive window MUST be allowed to grow to at least 16
    MiB, so that a few slow targets cannot hold up the rest, or the
    registration's `end` message (§13.4).
- **A connecting client** allows the hub stream windows of at least 64
  KiB, and lets its connection window grow to at least 16 MiB.
- **No stream credit at once is a rule for the hub.** quic-go reports it
  at once; quinn and aioquic may block or queue instead. A future hub in
  those libraries must still fail the connection at once (§13.4).

### 13.4 Requests and answers

#### Messages

Before frames, a stream carries **messages**: a 2-byte big-endian length,
then that many bytes of UTF-8 JSON (an object), at most 4096 bytes long.

- **A client stream** begins with one **request** from the client, and one
  **answer** from the hub.
  - The request MUST be complete within 10 seconds of the stream being
    opened. Otherwise the hub resets the stream (`request-timeout`,
    §13.7).
  - The client waits up to 15 seconds for the answer. Then it resets the
    stream (`request-timeout`) and reports that the hub did not answer.
- **A hub-opened stream** (`serve`, below) begins with the hub's open and
  the serving side's answer.
- **The serve stream** carries further messages from the hub after its
  answer (`serve`, below).

**What is frozen.** The client request's envelope, a length then a JSON
object with `op` and `proto`, and the answer's `status` and `proto`, stay
the same in every future protocol. So any later hub can always answer any
later client, if only with 426. Messages on hub-opened streams and on the
serve stream follow the protocol that the registration negotiated.

#### The request

The request carries the same values as the WebSocket headers (§4), as
JSON fields:

```json
{"op": "connect", "proto": "3", "version": "pf-client-quic 0.16.0",
 "word": "…", "clientToken": "…"}
```

| Field | Ops | Header it replaces |
|---|---|---|
| `op` | all | the endpoint: `serve`, `connect` or `check` |
| `proto` | all | the protocol range over QUIC, `min-max` or one number: today `3` (§13.11) |
| `version` | all | `X-PF-Version`, for logs only (§5.4) |
| `word` | all | `X-PF-Tunnel-Word` |
| `serveToken` | serve | `X-PF-Serve-Token`; leave it out to serve anonymously |
| `name` | serve | `X-PF-Tunnel-Name`, as plain UTF-8, not escaped |
| `target` | serve | `X-PF-Tunnel-Target` |
| `clientTokenSHA256` | serve | `X-PF-Client-Token-SHA256` |
| `clientToken` | connect, check | `X-PF-Client-Token` |

#### The answer

The answer is `{"status": <code>, "proto": <n>, …}`.

- **`status`** uses the status codes of the matching WebSocket endpoint
  (§6.2 to §6.4), with 200 in place of 101. So the tables there apply
  unchanged, including 403 delays, 409 and 503.
- **`proto`** is the protocol the hub chose over QUIC: today always 3.
- **A refusal** adds `"error": "<message>"`. A 429 also adds
  `"retryAfter": <seconds>` and `"scope"`: `"address"` when the client's
  address is blocked, `"connection"` when only this connection is
  (§13.8). The stream then ends as §13.5 describes for a
  refusal.
- **A request the hub cannot read** gets one of these:

  | Problem | Answer |
  |---|---|
  | the `proto` range does not include a protocol the hub speaks over QUIC (today, 3) | 426, `proto` being the hub's protocol, and an error saying which side to upgrade |
  | malformed range, not JSON, not an object, unknown `op`, a field of the wrong type | 400 with the reason |
  | longer than 4096 bytes, or a FIN before the message is complete | no answer: the hub resets the stream (`protocol`, §13.7) |

- Unknown fields are ignored, on both sides.
- `version` stays an HTTPS-only endpoint (§6.5).

#### Other inputs, and timers

- **Bytes after the request on a `serve` or `check` stream,** other than
  the FIN that ends it, break the protocol: the hub resets the stream
  (`protocol`).
- **A second `eof`, or any frame after `err`,** breaks the protocol too.
  The receiver resets the stream (`protocol`) and reports a broken
  stream.
- **The 501 body** of discovery is `{"error": "<message>"}`, as every
  refusal (§6).
- **The 10-second request timer** runs only once the hub has started
  reading a stream. Streams waiting their turn before authentication
  (§13.3) do not time out while they wait.
- **A serving side waits 10 seconds** for the open on a stream the hub
  opened. Then it resets the stream (`request-timeout`).

#### `serve`

**The answer is 200 when registered,** with the registration's id:

```json
{"status": 200, "proto": 3, "reg": "5b2d4e8f1a6c9b0d"}
```

The id is random, at least 64 bits as 16 hex digits, and new for each
registration. It is for matching opens to registrations (below), not a
secret: holding it grants nothing.

**The serve stream stays open as the registration.**
- The client sends nothing more on it after the request. In particular it
  MUST NOT send FIN as part of sending the request, as some
  request/response helpers do. A FIN from the client ends the
  registration.
- **To unregister,** the client sends FIN. The hub answers with FIN.
- **When the hub ends a registration,** it sends one more message, then
  FIN:

  ```json
  {"end": "takeover", "error": "another registration of this word took over"}
  ```

  | `end` | When | The serving side |
  |---|---|---|
  | `takeover` | a `serve` of the same tenant and word took over (§6.2) | registers again, with the usual growing pause, as a WebSocket serving side does today |
  | `tenant` | its tenant was deleted or rotated | registers again only if the tunnel has been up, as after a 403 (§9) |
  | `off` | the relay or anonymous serving was switched off | registers again, with the usual growing pause (§9) |
  | `shutdown` | the hub is stopping | registers again, with the usual growing pause |
  | anything else | — | registers again, with the usual growing pause |

  The serving side reports `error` to the user. It decides only from
  `end`, never from `error`.
- **Two live serving sides of one word** therefore take it from each
  other in turn, as over WebSocket. That is the owner's decision: the
  same behavior on both transports. Each takeover is reported, and logged
  by the hub.
- **Other messages** on the serve stream, unknown ones included, are
  ignored.
- **A RESET of the serve stream** from either side, or a lost QUIC
  connection, ends the registration with no reason. The serving side
  registers again, as after a lost control channel (§9).
- **Ending a registration** ends every connection in it, as a lost
  control channel does (§7).

**Takeover.** The rules of §6.2 apply across transports and connections.
A `serve` of the same tenant and word takes over the registration, whether
it is a QUIC one (on this connection or another) or a WebSocket one. A QUIC
takeover of a WebSocket registration closes that registration's idle legs,
as any takeover does (§12.6).

**For each connection, the hub opens a stream to the serving side.** Its
first message is the **open**:

```json
{"open": "8f14e45fceea167a", "reg": "5b2d4e8f1a6c9b0d"}
```

- **The hub opens no stream for a registration before sending its 200.**
- **But streams are not ordered with one another.** So the serving side
  can receive an open before the 200 of its own `serve`. If it names a
  `reg` the serving side does not know, it waits for its outstanding
  `serve` answers on that connection. If the `reg` is still unknown once
  they have arrived, or after 10 seconds, it refuses the open (below).

The serving side answers with one message:

| Answer | Meaning |
|---|---|
| `{"status": 200}` | it carries the connection; the stream then carries it (§13.5) |
| `{"status": 502, "error": "<reason>"}` | it refuses it, for example because the target is unreachable. As with `X-PF-Tunnel-Error` (§6.6), the reason is printable ASCII of at most 128 characters, and the hub passes it on. |
| `{"status": 410, "error": "no such registration"}` | the open names a `reg` it does not know, or has just ended. The hub tells the connecting side "the tunnel closed". |

Rules for this stream:

- **The answer comes promptly.** As over WebSocket, a serving side SHOULD
  connect to its target first, and refuse with the reason when it cannot
  (§9).
- **The hub waits 10 seconds for the answer.** Then it resets the stream
  (`request-timeout`) and fails the connection as in §6.3.
- **The hub sends no frames on the stream before the serving side's 200.**
  It holds the connecting side's early data until then (`connect`, below).
- **No streams left.** When the serving side has no stream credit left
  (MAX_STREAMS), the hub does not wait. It fails the connection at once,
  with "the serving side has too many connections open".
- **A WebSocket `accept` for a connection whose serving side is on QUIC**
  gets 404, as for a connection that is not pending (§6.6).

#### `connect`

**The hub answers as soon as it has checked the request,** before asking
the serving side, as the WebSocket 101 does (§6.3):

```json
{"status": 200, "proto": 3, "conn": "8f14e45fceea167a"}
```

- **200 never means that the target was reached.** If the serving side
  refuses the connection, does not answer within 10 seconds, or the target
  fails, the client hears it as an `err` frame on the stream, as a
  WebSocket connecting side hears `err:` (§13.5).
- **Accepted** means, depending on how the serving side is connected:
  - over QUIC, its `{"status": 200}`;
  - over WebSocket, the 101 of its `accept` (§6.6);
  - on a reused WebSocket leg, its `bound` (§12.7).
- **Early data.**
  - The client MAY send frames right after its request, without waiting
    for the answer. So a connection costs no extra round trip.
  - Until the connection is accepted, the hub holds that data as §13.3
    describes. A client blocked by flow control is not in error.
  - If the connection is refused, the hub discards that data (§13.5).
  - Then the client's writes fail. **The client MUST keep reading** after
    a failed write, and report the `err` reason it reads, not the write
    error.
- **A client that gives up,** at any time, sends `err`, or resets its
  stream (`cancelled`). The hub handles both in every state. It cannot
  know what the client has seen, and the client cannot know whether the
  serving side has accepted yet.
  - **If the serving side has not accepted yet,** the hub withdraws the
    open. It resets a QUIC stream it had opened (`cancelled`). An `accept`
    that arrives later over WebSocket gets 404, as for an ended connection
    (§6.6).
  - **Otherwise** the serving side hears `err`: the client's reason, or
    "the link to the connecting side was lost" (§13.9).

#### `check`

The answer is `{"status": 204, "proto": 3}` or a refusal, as in §6.4. Then
both sides send FIN.

### 13.5 Streams

After the request and its answer (or, on a hub-opened stream, the open and
its answer), each direction of a stream carries **frames**.

#### Frames

Every frame, of every type, now and in all future protocols, is:

| Type | Length | Payload |
|---|---|---|
| 1 byte | 2 bytes, big-endian | that many bytes |

| Type | Name | Length | Meaning |
|---|---|---|---|
| `0x00` | data | 0 to 65535 | the next bytes of the connection |
| `0x01` | eof | 0 | the sender's half-close (§8.2) |
| `0x02` | err | 1 to 1024 | the connection is being dropped, and why (§8.3): UTF-8 |

- **Unknown types are skipped** by their length, like unknown text frames
  (§8.1).
- **Order.** Frames are read in the order they were sent, so `eof` follows
  the last byte of data.

#### The rules of §8, on QUIC

- **Half-close.** After `eof` the sender sends no more data. Data after
  `eof` breaks the stream. The other direction carries on until its own
  `eof`.
- **Failure.** An end that drops the connection sends `err` and nothing
  after it. `err` may still follow the sender's own `eof`: as in §8.3, a
  finish can turn into a failure later.
- **Half-close idle.** After a half-close, the hub ends a connection that
  carries nothing either way for 30 seconds (§8.2), with `err`.

#### Ending a stream

**Every stream MUST be driven to its end in both directions.** QUIC gives
back stream credit only when both directions are over. A stream left half
open would slowly use up the peer's MAX_STREAMS, until the serving side
seems to have "too many connections open".

Each direction ends in one of two ways: its sender sends FIN or
RESET_STREAM, or its receiver sends STOP_SENDING, which the sender answers
with RESET_STREAM.
- **An end MUST answer STOP_SENDING with RESET_STREAM.** quic-go does
  this by itself. quinn only records the STOP_SENDING, so a Rust SDK must
  watch for it, even on streams it is not writing to, and reset the
  stream itself.
- The answering RESET_STREAM SHOULD echo the STOP_SENDING's code. Some
  libraries send 0 instead.
- **No end decides anything from the code** of a RESET_STREAM or a
  STOP_SENDING, only from the stream's state (§13.7).

**To reset a stream** means, everywhere in this section: RESET_STREAM for
the own direction and STOP_SENDING for the other, both with the same
code. It ends both directions at once.

| The stream | What each end does |
|---|---|
| **Clean finish** | Each end sends `eof`, then FIN once it has also received the other's `eof`. Each reads to the other's FIN, for at most 3 seconds after its own. Then it resets the stream (`cancelled`). |
| **Failure: the end that sends `err`** | Sends `err`, then FIN. Keeps reading, and discards what it reads, until the other direction ends, for at most 3 seconds (below). Then sends STOP_SENDING (`cancelled`) if it has not ended. |
| **Failure: the end that receives `err`** | Stops using the data. Ends its own direction at once: RESET_STREAM (`cancelled`), or FIN. Neither is a broken stream: the `err` already said why. |
| **A refused request** (any answer but 200 or 204) | The hub sends the answer, then FIN, and STOP_SENDING (`refused`) for the client's direction, which discards any early data. The client ends its direction with RESET_STREAM (`refused`) or FIN. |
| **A refused open** (502, 410) | The serving side sends the answer, then FIN. The hub, which sent only the open, sends FIN. |
| **`check`** | The client MAY send FIN with its request. The hub sends FIN after the answer. |
| **The serve stream, ended by the hub** | The hub sends `end`, then FIN. The client sends FIN. |
| **The serve stream, ended by the client** (unregister) | The client sends FIN. The hub sends FIN. |
| **A registration's connections, when it ends** (by `end`, unregister, takeover, or a lost serve stream) | The hub sends each of the registration's streams `err` "the tunnel closed", and each then ends as a failure. The other side of each connection hears the same reason (§13.9). |

- **A `connect` client sends FIN only as the table says,** after its own
  `eof` and the hub's. A FIN with the request is out of turn.

- **FIN out of turn.** A FIN in any state other than these, or in the
  middle of a frame or a message, is a broken stream.
- **Broken stream.** A RESET_STREAM that arrives before the receiver has
  sent or received `err`, a refusal, an `end` or a STOP_SENDING on that
  stream; a FIN out of turn; a lost QUIC connection, or a frame that breaks these
  rules. The receiver reports the connection as failed, and has no reason
  to report beyond "the link was lost" or "the peer broke the protocol".
- **Delivering a reason.** QUIC libraries do not tell a sender when its
  data was acknowledged. Closing a QUIC connection drops data still
  queued. So:
  - An end that sends `err`, an `end` message, or a refusal keeps the
    stream, and the connection, until the peer has ended its direction
    (FIN or RESET_STREAM), for at most 3 seconds. Only then does it
    close the connection or exit.
  - The receiver of any of these MUST end its direction promptly, as the
    table says.
  - This is the counterpart of the 3-second close wait in §8.4.
- **A write can fail before the reason is read.** A STOP_SENDING can
  overtake the `err` frame, or the refusal, that was sent before it. This
  can happen on any stream, in either role. So an end whose write fails
  MUST keep reading. It reports the `err`, answer or `end` it reads, and
  reports the write error only if none comes.
- **The hub resets streams** (both directions, as defined above) **only
  for its own reasons:** a request, open or
  answer that did not come in time (`request-timeout`), a peer that broke
  the protocol (`protocol`), or a connecting side that gave up
  (`cancelled`). It never resets a stream to pass on what happened to the
  other side of the connection. That always travels as `err` (§13.9).

#### Reasons

- **Untrusted.** A receiver treats an `err` as untrusted: it strips
  characters that are not printable and cuts it to 200 characters before
  logging it, as in §8.3.
- **Toward WebSocket.** Before passing a reason to a WebSocket peer, the
  hub does the same. It cuts at a UTF-8 character boundary, so that
  `err:` and the reason fit in 1024 bytes.
- **From WebSocket.** An `err:` with an empty reason becomes the QUIC
  `err` "the peer gave no reason", since a QUIC `err` is never empty.

**Why frames, and not raw bytes and FIN?** In QUIC nothing can follow a
FIN, and a RESET_STREAM carries only a number. So with raw bytes, a
failure after a half-close would have no way to arrive, and no failure
could carry its reason. Frames carry `eof` and `err` in order with the
data. They map one to one onto the WebSocket frames, so the hub bridges
the two transports without losing anything (§13.9). Each frame costs 3
bytes per 64 KiB.

### 13.6 Keepalive

Keepalive belongs to the **QUIC connection**, not to its streams. It
replaces the WebSocket pings of the control channel (§7) and of streams
(§8.5). It applies to every QUIC connection to the hub: serving or
connecting, busy or idle, for as long as the connection is open.

- **Idle timeout.**
  - Both ends MUST set the transport parameter `max_idle_timeout` to 30
    seconds. QUIC uses the smaller of the two values.
  - An end that receives nothing from the other for that long treats the
    connection as dead. It is closed silently, as QUIC defines.
- **Keepalive on both ends.**
  - Each end MUST run QUIC keepalive with an interval of at most 10
    seconds: after 10 seconds in which it has received nothing, it sends
    an ack-eliciting packet, such as a PING frame.
  - This is how quic-go's keepalive works: it counts from the last packet
    received. An end that keeps hearing from its peer need not ping.
  - So no 10 seconds pass without an ack-eliciting packet in at least one
    direction. The ACK that answers it travels the other way, and keeps
    that direction alive too.
  - A dead hub is noticed within 30 seconds, as on a WebSocket stream
    (§8.5).
- **Why 10 seconds.** UDP mappings in NATs and firewalls commonly expire
  after 30 seconds, and some after less. The PINGs keep the mapping open
  from both sides, including a serving side that carries nothing for
  hours.
- **What a dead connection ends.**
  - **Its registrations,** and every connection in them, as a lost control
    channel does (§7). The serving side SHOULD discover and register again
    (§9, §13.2).
  - **Its streams.** Each is a broken stream. The hub tells the other
    side of each connection with `err`: "the link to the connecting side
    was lost" or "the link to the serving side was lost" (§13.9).
- **Streams send no keepalive of their own.** An idle stream in an alive
  connection stays open for as long as it likes. The one exception is the
  30-second limit after a half-close (§8.2), which still applies.
- **Address changes** (NAT rebinding, a new network). The hub MUST accept
  a client's new address through QUIC path validation (RFC 9000 §9), and
  the client MUST NOT disable connection migration. A change of address
  then costs nothing, and does not end the connection. For guessing
  protection, the connection keeps the address it was opened from
  (§13.8).
- **For implementers.**
  - In quic-go these rules are `MaxIdleTimeout: 30s` and
    `KeepAlivePeriod: 10s` in both sides' `quic.Config`, with `Allow0RTT:
    false`, and `SessionTicketsDisabled: true` in the hub's `tls.Config`.
  - Libraries without a keepalive setting, such as aioquic and kwik,
    need a timer of the SDK's own that sends a PING by the same rule.

### 13.7 Error codes

QUIC's RESET_STREAM, STOP_SENDING and CONNECTION_CLOSE carry an
application error code. Protocol 3 uses these:

| Code | Name | Used when |
|---|---|---|
| `0x0` | `none` | a QUIC connection is closed because it is no longer needed: a client at the end of its run; the hub closing an unused connection (§13.8) |
| `0x1` | `broken` | an end drops a stream or a connection for which it has no other code, such as a local failure it cannot describe |
| `0x2` | `refused` | a refused request: the hub's STOP_SENDING, and the client's RESET_STREAM (§13.5) |
| `0x3` | `protocol` | the peer broke this protocol: a bad message or frame, a FIN out of turn |
| `0x4` | `request-timeout` | a request, open or answer did not come in time; a connection with no successful request in time (§13.8) |
| `0x5` | `cancelled` | the end gives up on a stream: after `err` (§13.5), or a connecting side giving up before it is accepted (§13.4) |
| `0x6` | `going-away` | the hub or the client is shutting down and closes its QUIC connections |
| `0x7` | `limit` | the hub closes a connection over a limit (§13.8) |

- The codes are for logs and for choosing a message. A reason that
  matters to the user travels in an `err` frame, an answer, or an `end`
  message.
- An unknown code means `broken`.
- **A refused handshake carries none of these.** Application codes cannot
  travel in QUIC's Initial and Handshake packets (RFC 9000 §10.2.3), so a
  hub refusing a handshake sends the transport error `CONNECTION_REFUSED`.
  The client treats it like a 429: it reports "the hub refused the
  connection", and retries later with the usual growing pause.

### 13.8 Guessing protection and limits

The hub protects its QUIC listener at least as well as its HTTPS
endpoints, without ever ending a tunnel that works.

- **The address.** Refusals are counted per source address, with IPv6
  addresses grouped by /64, as over HTTPS. A QUIC connection keeps the
  address it was opened from, even after it migrates (§13.6). Requests
  reach the hub only after a completed handshake, which has validated that
  address, so it cannot be spoofed.
- **Refusals.**
  - A refused `serve`, `connect`, `check` or discovery counts toward the
    same per-address total as the HTTPS endpoints (§6.1), and is delayed
    in the same way.
  - While an address is at 429, the hub answers each new request from it
    with 429, on every QUIC connection.
  - After 5 refused requests on one connection within 60 seconds, the
    hub answers every further request on that connection with 429, until
    those 60 seconds are over, whatever the address's total. So many
    guesses cannot wait on parallel streams of one connection.
  - A 429 answer is not itself a refusal: it counts toward neither total.
  - A client that gets a 429 with `"scope": "connection"` opens a new
    connection for its next requests. It closes the old one (`none`) once
    it holds nothing. With `"scope": "address"`, it waits `retryAfter`.
- **What a limit closes.** The hub closes a connection over a limit
  (`limit`) only if it holds no registration and no accepted stream.
  **A registration or an accepted connection is never ended for guessing
  protection.** That includes other users behind the same NAT. Over
  WebSocket, a 429 never ends a channel either.
- **Unauthenticated connections.**
  - A connection that has not made a successful request within 10 seconds
    of its handshake is closed (`request-timeout`).
  - A connection that holds no registration and no open stream for 5
    minutes is closed (`none`). The client opens a new one when it next
    needs one.
  - **Both closes are routine.** The client shows no error. It discovers
    again and opens a new connection when it next needs one.
- **Connections per address.** The hub accepts at most 64 QUIC
  connections per address. Beyond that, it refuses the handshake
  (`CONNECTION_REFUSED`, §13.7).
  - Only connections whose address is validated count: completed
    handshakes, or handshakes past a Retry.
  - Once an address has handshakes pending, the hub sends Retry to its new
    ones (quic-go's `VerifySourceAddress`). So spoofed Initials cannot
    fill a NAT's 64 slots.
- **Handshake floods.** The hub SHOULD send QUIC Retry packets when under
  load, so that it does not spend effort on spoofed addresses. QUIC's
  anti-amplification limit applies in any case.
- **Memory.** Before its first successful request, a connection can make
  the hub hold at most 256 KiB (§13.3).
- **Relay limits.** Tenant limits (256 words) and every other relay limit
  are the same whichever transport is used.

### 13.9 Mixing transports

The hub pipes bytes between the two sides of a connection, whatever each
side uses.

| WebSocket (§8) | QUIC (§13.5) |
|---|---|
| binary frames (up to 1 MiB) | `0x00` data frames; the hub splits WebSocket data into frames of at most 65535 bytes |
| text `eof` | `0x01` eof |
| text `err:<reason>` | `0x02` err, cleaned up toward WebSocket (§13.5) |
| close after a clean finish or an `err` | the ends of §13.5 |

#### When one side breaks or fails

What the hub sends the **surviving** side depends on how that side is
connected:

| The surviving side | What it receives |
|---|---|
| **on QUIC**, either role | `err` with the reason at once, and the stream ends as for a failure (§13.5) |
| **on a WebSocket stream**, connecting, or serving without reuse | as today (§8.3): `eof` in the direction that ended, and `err:` once the whole connection ends, or after the 30-second idle timeout |
| **on a WebSocket serving leg offered reuse** | as today (§12.5): the hub ends the generation with `eof` and `idle`, and the leg goes back to the pool. A QUIC `err` from the other side reaches this leg only as that `eof`; its reason is logged by the hub, not sent. |

- **The reason** is that of the other side's `err`, or, for a break, one
  the hub writes, such as "the link to the serving side was lost".
- **Never a break.** The hub never passes on a break as a break. It does
  not reset a stream, or drop a WebSocket, because the other side's link
  was lost.

#### How each pairing works

- **The connecting side is on QUIC and the serving side on WebSockets.**
  - The hub answers 200 at once, sends the open message on the control
    channel, and waits for the `accept` leg (§6.6). That leg may be a
    reused protocol 2 leg (§12.7).
  - A reused leg answers `bound` before its serving side dials the
    target, so an unreachable target arrives later, as `err`. This is one
    more reason why 200 never means that the target was reached.
  - If `bound` does not come in time, the hub falls back to a new
    `accept`, all within the same 10 seconds, as today.
- **The connecting side is on WebSockets and the serving side on QUIC.**
  - The hub sends the WebSocket 101 at once, as in §6.3, and opens a
    stream to the serving side.
  - A refusal reaches the connecting side as `err:<reason>`, just as fast
    as a WebSocket `accept` refusal (§9).
- **Both sides are on QUIC.** The hub copies frames between the two
  streams.

### 13.10 Hub configuration (not on the wire)

`[tunnel.quic]`. Every setting can be changed in the console without a
restart.

| Key | Meaning |
|---|---|
| `enabled` | QUIC listener on or off; off makes discovery answer 501 |
| `listen` | the UDP address, such as `:443`; changing it restarts the listener, which ends its QUIC connections (`going-away`) |
| `advertise_host`, `advertise_port` | what discovery answers; with no host set, discovery answers 501 |
| `max_connections`, `max_buffered` | the hub-wide caps of §13.3 (10000, 1 GiB) |
| certificate | generated by the hub (§13.3), valid for 60 days, and kept beside the config. The hub looks every hour and replaces it once less than 15 days are left. |

**Replacing the certificate.**
- The listener presents only the new certificate on new handshakes.
  Existing connections keep going.
- For 10 minutes, discovery lists both fingerprints. That covers a client
  between its discovery and its handshake.
- A client that discovered just before the change gets a mismatch,
  discovers again, and succeeds (§13.3).

The console's relay tab shows each side's transport, `ws` or `quic`.

### 13.11 Protocol numbers

- **Two transports, two ranges.** The WebSocket endpoints speak protocols
  0 to 2 (§5), and nothing about them changes: `X-PF-Tunnel-Proto`, the
  features of §5.1 and the gates of §12 stay as they are, and the hub
  still answers WebSocket requests with at most 2.
- **Protocol 3 is the first protocol over QUIC,** and today the only one.
  It is negotiated in the `proto` field of each QUIC request (§13.4),
  which a later QUIC protocol (4, …) extends the same way.
- **No client speaks both.** pfrelay and pf-client speak 0 to 2 over
  WebSocket; pfrelayquic and pf-client-quic speak 3 over QUIC. They work
  with each other through the hub's bridge (§13.9), in either role.
- **The hub's version answer** (§6.5) still gives its WebSocket range.
- **Nothing is decided from `version`** (§5.4), over QUIC as over
  WebSocket.

### 13.12 Decisions

These were open questions, now settled by the owner:

1. **Discovery asks for the run's credentials** (§13.2). The alternative,
   answering anyone, was rejected.
2. **`connect` is answered at once,** with failures as `err` frames
   (§13.4). The client needs that path anyway, for an unreachable target
   behind a reused WebSocket leg (§13.9), and one path is easier to get
   right in four SDKs.
3. **A QUIC connection holds any number of registrations,** each opened
   stream naming its registration (§13.4). This avoids one connection,
   handshake, NAT mapping and PING timer per word, and changing it later
   would take a protocol 4.
4. **A serving side that is taken over registers again,** over QUIC as
   over WebSocket (§13.4). Two live serving sides of one word take it
   from each other in turn. Stopping instead was rejected, to keep the
   two transports alike.

### 13.13 Conformance

The suite runs every SDK's driver against a test hub, as for WebSocket
(§11).

**A QUIC driver** answers `protocols` with `3-3`. The suite then runs
every case with the hub's QUIC listener on, the driver on QUIC and the Go
SDK on the other side of each case on WebSocket, so each case also
crosses the bridge (`conformance_test.go`, `TestConformanceQUIC` for the
Go driver). The cases that need protocol 2 (reuse) or an older hub do not
apply to it.

**Hooks in the test hub,** to reach the cases a real hub rarely shows:
- present a wrong certificate, or one replaced since discovery;
- answer discovery with 501, or with a 404 as a hub without QUIC does;
- withhold flow-control credit from a client;
- for the hub's own rules, such as failing at once without stream credit,
  a raw quic-go peer in the suite plays a serving side that grants the hub
  little or no credit;
- send STOP_SENDING and withhold the `err`, to check that an end keeps
  reading after a failed write;
- answer STOP_SENDING with a RESET_STREAM of code 0, as some libraries
  do;
- delay an open past 10 seconds, or answer it before the `serve` answer
  arrives;
- send each `end` code;
- send unknown frame types, unknown messages and unknown error codes;
- break the protocol: data after `eof`, a FIN out of turn, an oversize
  message;
- shorten the timers, as the WebSocket suite does.

**What the suite checks only at packet level,** through the test hub's
quic-go tracing (qlog):
- `max_idle_timeout` is 30 seconds;
- no 10 seconds pass without an ack-eliciting packet in at least one
  direction, allowing some slack;
- no early data.

**A hook for resumption:** the test hub can issue session tickets and
offer 0-RTT, as a hub must not. The suite then checks that the client
still makes a full handshake, checks the pin, and sends no early data.

#### The cross-transport matrix

One table-driven test, `TestCrossTransport`, runs every **case** below on
every **pairing**, through one hub with shortened timers. It is the
answer to "does every side work with every other side, and fail the same
way?"

**Pairings: 2 connecting sides × 4 serving sides = 8.**

| Connecting side | Serving side |
|---|---|
| WebSocket (pfrelay, protocol 2) | WebSocket, protocol 1 (no reuse) |
| QUIC (pfrelayquic) | WebSocket, protocol 2, on a fresh leg |
| | WebSocket, protocol 2, on a reused leg |
| | QUIC (pfrelayquic) |

**Cases: every point where a connection can end.**

| # | Case | The connecting side must report | The serving side must report |
|---|---|---|---|
| 1 | clean echo, each side half-closing in turn | finished | finished |
| 2 | wrong client token | refused: access denied | nothing (no open) |
| 3 | target unreachable | failed: the serving side's reason | refused at once |
| 4 | serving side never answers the open | failed: did not answer, after the timer | nothing, or a late open refused |
| 5 | target resets mid-stream | failed: the target's reason | failed |
| 6 | application resets mid-stream | failed | failed: the application's reason |
| 7 | serving side's link lost mid-stream | failed: link to the serving side lost | — |
| 8 | connecting side's link lost mid-stream | — | failed: link to the connecting side lost |
| 9 | failure after a half-close (late `err`) | failed, not finished | failed |
| 10 | half-closed, then silent past the idle timer | failed: idle | failed: idle |
| 11 | connecting side gives up before the serving side answers | cancelled | open withdrawn, or nothing |
| 12 | registration ends mid-stream (unregister, takeover) | failed: the tunnel closed | failed: the tunnel closed |

**After each case, the test also checks:**
- the hub holds no pipe, pending connection or open stream for it (no
  leak);
- on the reused-leg pairing, the leg is back in the pool, except where
  §12.5 says the leg is lost;
- the reason the surviving side reports is the one in the table, matched
  by substring, as `tunnel_break_test.go` does.

It is one loop over pairings and cases, with one helper per side to start
it and to break it. Adding a transport later means adding rows, not
tests.

**Pairings with other SDKs.** The conformance suite runs every QUIC SDK
against every WebSocket SDK, in both roles, through the same hub,
including a reused protocol 2 leg on the WebSocket side.
