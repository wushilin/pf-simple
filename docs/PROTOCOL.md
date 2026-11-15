# The pf-simple tunnel protocol

This document defines how a client (`pf-client`, or a program using one of
the SDKs) talks to the relay hub of `pf-simple`. It is the reference for
anyone writing a client in another language. It describes what pf-simple
0.15.0 speaks: protocols 0 and 1 (§1 to §11), and protocol 2, which adds
reusing the serving side's legs (§12). The conformance suite in
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
  followed by `/` or `/pf` or `/pf/`. Any other path is an error. The
  endpoints are under:

  ```
  https://host[:port]/pf/api/tunnel/<endpoint>
  ```

  where `<endpoint>` is `serve`, `connect`, `accept`, `check` or `version`.
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

### 5.1 What the client offers

In `X-PF-Tunnel-Proto`, the client sends `min-max`, two decimal numbers
with `0 <= min <= max`. A single number `n` means `n-n`.

- `max` is the highest protocol the client implements. Today that is `1`.
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
