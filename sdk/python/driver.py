#!/usr/bin/env python3
"""The Python SDK's conformance driver; see conformance/README.md.

It uses only the SDK's public API, as an application would: listen/accept
and dial with its own copy loop (--mode listen), or the SDK's forwarders
serve(target) and connect(socket) (--mode forward).
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import enum
import json
import logging
import os
import signal
import socket
import ssl
import sys
from typing import Optional

# Run with python3 -I, the script's own directory is not on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pfrelay  # noqa: E402

AGENT = f"{pfrelay.DEFAULT_AGENT} conformance"
DEFAULT_WORD = "aaaa-bbbb-cccc"  # version needs none, but a client is made with one
DEFAULT_NAME = "conformance"
DROP_REASON = "dropped by the conformance suite"
LISTENING = "listening"  # "listening HOST:PORT"
COPY_CHUNK = 64 * 1024
NO_PROTOCOL = -1  # Client(max_proto=...) for a client that announces none
TARGET_DIAL_TIMEOUT = 5.0


class Command(str, enum.Enum):
    SERVE = "serve"
    CONNECT = "connect"
    CHECK = "check"
    VERSION = "version"
    PROTOCOLS = "protocols"  # print the protocol range the driver speaks


class Mode(str, enum.Enum):
    LISTEN = "listen"  # listen/accept and dial, with the driver's own copy loop
    FORWARD = "forward"  # the SDK's forwarders


class Query(str, enum.Enum):
    STATS = "stats"
    CONNS = "conns"
    DROP = "drop"  # "drop <id>"


class Event(str, enum.Enum):
    READY = "ready"  # the first registration (serve)
    OPENED = "opened"  # "opened <id> <side>"
    CLOSED = "closed"  # "closed <id> <sent> <received> ok|failed"
    REFUSED = "refused"  # "refused <id>"
    UP = "tunnel up"  # watch (connect)
    DOWN = "tunnel down"


class Outcome(str, enum.Enum):
    OK = "ok"
    FAILED = "failed"


class Exit(enum.IntEnum):
    OK = 0
    FAIL = 1
    USAGE = 2
    PROTO = 3
    DENIED = 4


@dataclasses.dataclass(frozen=True)
class StatsAnswer:
    opened: int
    active: int
    failed: int
    sent: int
    received: int


@dataclasses.dataclass(frozen=True)
class ConnAnswer:
    id: str
    side: str
    sent: int
    received: int


def eprint(*args) -> None:
    print(*args, file=sys.stderr, flush=True)


def say(*tokens) -> None:
    """One line of output, its tokens separated by single spaces."""
    print(" ".join(str(t.value if isinstance(t, enum.Enum) else t) for t in tokens), flush=True)


def answer(query: Query, value) -> None:
    say(query, json.dumps(value, separators=(",", ":")))


class Usage(argparse.ArgumentParser):
    def error(self, message):  # exit 2, as the suite expects
        eprint(f"usage: {message}")
        sys.exit(Exit.USAGE)


def exit_for(err: BaseException) -> None:
    eprint(err)
    if isinstance(err, pfrelay.ProtoError):
        sys.exit(Exit.PROTO)
    if isinstance(err, pfrelay.AccessDenied):
        sys.exit(Exit.DENIED)
    sys.exit(Exit.FAIL)


# ------------------------------------------------------------- events


def install_events(client: pfrelay.Client) -> None:
    ready = False

    def on_serving(up: bool) -> None:
        nonlocal ready
        if up and not ready:
            ready = True
            say(Event.READY)

    def on_tunnel(up: bool, _err: Optional[BaseException]) -> None:
        say(Event.UP if up else Event.DOWN)

    def on_open(info: pfrelay.ConnInfo) -> None:
        say(Event.OPENED, info.id, info.side)

    def on_close(info: pfrelay.ConnInfo, err: Optional[BaseException]) -> None:
        say(Event.CLOSED, info.id, info.sent, info.received, Outcome.FAILED if err else Outcome.OK)

    def on_refuse(cid: pfrelay.ConnID, _reason: str) -> None:
        say(Event.REFUSED, cid)

    client.events = pfrelay.Events(
        on_serving=on_serving, on_tunnel=on_tunnel, on_open=on_open, on_close=on_close, on_refuse=on_refuse
    )


# ------------------------------------------------------------- queries


async def queries(client: pfrelay.Client) -> None:
    """Answer the suite's questions on stdin until it closes."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    try:
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    except (OSError, ValueError) as e:
        eprint(f"no queries: {e}")
        return
    while True:
        raw = await reader.readline()
        if not raw:
            return
        word, _, arg = raw.decode("utf-8", "replace").strip().partition(" ")
        try:
            query = Query(word)
        except ValueError:
            continue
        if query is Query.STATS:
            answer(query, dataclasses.asdict(StatsAnswer(**dataclasses.asdict(client.stats()))))
        elif query is Query.CONNS:
            answer(
                query,
                [dataclasses.asdict(ConnAnswer(str(c.id), str(c.side), c.sent, c.received)) for c in client.conns()],
            )
        elif query is Query.DROP:
            answer(query, drop_by_name(client, arg.strip()))


def drop_by_name(client: pfrelay.Client, name: str) -> bool:
    """Drop the open connection whose id prints as name."""
    for info in client.conns():
        if str(info.id) == name:
            return client.drop(info.id, DROP_REASON)
    return False


# ------------------------------------------------------------- copying


async def pipe(conn: pfrelay.Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy both ways, passing half-closes on, until both directions are
    done or one fails."""

    async def outbound():  # TCP -> tunnel
        while data := await reader.read(COPY_CHUNK):
            await conn.write(data)
        await conn.close_write()

    async def inbound():  # tunnel -> TCP
        while data := await conn.read(COPY_CHUNK):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()

    tasks = [asyncio.ensure_future(outbound()), asyncio.ensure_future(inbound())]
    clean = False
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        failed = next((t.exception() for t in done if t.exception() is not None), None)
        if failed is not None:
            for t in pending:
                t.cancel()
            await conn.fail(str(failed) or type(failed).__name__)
        else:
            await conn.close()
            clean = True
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await conn.fail("the conformance driver is stopping")
        raise
    finally:
        if clean:
            writer.close()
        else:
            writer.transport.abort()


# ------------------------------------------------------------- commands


async def until(stop: asyncio.Event, work: asyncio.Future) -> None:
    """Run work until it ends or stop is set; exit with its error."""
    stopper = asyncio.ensure_future(stop.wait())
    await asyncio.wait({work, stopper}, return_when=asyncio.FIRST_COMPLETED)
    stopper.cancel()
    if work.done():
        if not work.cancelled() and work.exception() is not None:
            exit_for(work.exception())
        return
    work.cancel()
    await asyncio.gather(work, return_exceptions=True)


async def serve(client: pfrelay.Client, args, mode: Mode, stop: asyncio.Event) -> None:
    if mode is Mode.FORWARD:
        await until(stop, asyncio.ensure_future(client.serve(args.target)))
        return
    try:
        listener = await client.listen()  # its registration says Event.READY
    except (pfrelay.PfRelayError, OSError, ValueError) as e:
        exit_for(e)
    if args.no_accept:
        await stop.wait()
        await listener.close()
        return
    host, port = pfrelay.split_host_port(args.target)
    tasks: set[asyncio.Task] = set()

    async def one(conn: pfrelay.Conn) -> None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TARGET_DIAL_TIMEOUT)
        except (OSError, asyncio.TimeoutError) as e:
            eprint(f"connection {conn.id.short}: cannot reach {args.target}: {e}")
            await conn.fail(pfrelay.REASON_UNREACHABLE)
            return
        await pipe(conn, reader, writer)

    async def accept_loop() -> None:
        async for conn in listener:
            t = asyncio.ensure_future(one(conn))
            tasks.add(t)
            t.add_done_callback(tasks.discard)

    await until(stop, asyncio.ensure_future(accept_loop()))
    await listener.close()
    for t in list(tasks):
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def connect(client: pfrelay.Client, args, mode: Mode, stop: asyncio.Event) -> None:
    try:
        host, port = pfrelay.split_host_port(args.listen)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
        sock.setblocking(False)
    except (OSError, ValueError) as e:
        exit_for(e)
    addr = sock.getsockname()
    say(LISTENING, f"[{addr[0]}]:{addr[1]}" if family == socket.AF_INET6 else f"{addr[0]}:{addr[1]}")
    watch = asyncio.ensure_future(client.watch())
    try:
        if mode is Mode.FORWARD:
            await until(stop, asyncio.ensure_future(client.connect(sock)))
            return

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                conn = await client.dial()
            except Exception as e:
                eprint("dial:", e)
                writer.transport.abort()
                return
            await pipe(conn, reader, writer)

        server = await asyncio.start_server(handle, sock=sock)
        await stop.wait()
        server.close()
    finally:
        watch.cancel()


async def main() -> None:
    if len(sys.argv) < 2:
        eprint("usage: driver.py serve|connect|check|version [flags]")
        sys.exit(Exit.USAGE)
    try:
        cmd = Command(sys.argv[1])
    except ValueError:
        eprint(f"unknown command {sys.argv[1]}")
        sys.exit(Exit.USAGE)
    if cmd is Command.PROTOCOLS:
        say(pfrelay.proto_range(pfrelay.PROTO_MIN, pfrelay.PROTO_MAX))
        return
    ap = Usage(prog=f"driver.py {cmd.value}")
    ap.add_argument("--server", required=True)
    ap.add_argument("--ca", default=None)
    ap.add_argument("--word", default=DEFAULT_WORD)
    ap.add_argument("--serve-token", default="")
    ap.add_argument("--client-token", default="")
    ap.add_argument("--name", default=DEFAULT_NAME)
    ap.add_argument("--target", default="")
    ap.add_argument("--listen", default="")
    ap.add_argument("--mode", default=Mode.LISTEN.value, choices=[m.value for m in Mode])
    ap.add_argument("--no-accept", action="store_true")
    # Offer no protocol newer than N; 0 announces none, like a client from
    # before 0.14.
    ap.add_argument("--proto-max", type=int, default=None)
    args = ap.parse_args(sys.argv[2:])
    max_proto = args.proto_max
    if max_proto is not None and max_proto <= 0:
        max_proto = NO_PROTOCOL
    mode = Mode(args.mode)

    try:
        client = pfrelay.Client(
            args.server,
            args.word,
            ca_file=args.ca,
            serve_token=args.serve_token,
            client_token=args.client_token,
            name=args.name,
            target=args.target,
            agent=AGENT,
            max_proto=max_proto,
        )
    except (ValueError, OSError, ssl.SSLError) as e:
        eprint(e)
        sys.exit(Exit.USAGE)
    install_events(client)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    asking = asyncio.ensure_future(queries(client)) if cmd in (Command.SERVE, Command.CONNECT) else None
    try:
        if cmd is Command.VERSION:
            info = await client.probe()
            say(json.dumps(info.to_dict(), separators=(",", ":")))
        elif cmd is Command.CHECK:
            await client.check()
        elif cmd is Command.SERVE:
            await serve(client, args, mode, stop)
        else:
            await connect(client, args, mode, stop)
    except (pfrelay.PfRelayError, OSError, ssl.SSLError, asyncio.TimeoutError) as e:
        exit_for(e)
    finally:
        if asking is not None:
            asking.cancel()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    sys.exit(Exit.OK)
