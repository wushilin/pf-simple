#!/usr/bin/env python3
"""The Python SDK's conformance driver; see conformance/README.md.

It uses only the SDK's public API: listen/accept to serve, dial to connect.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import ssl
import sys

# Run with python3 -I, the script's own directory is not on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pfrelay  # noqa: E402

EXIT_FAIL, EXIT_USAGE, EXIT_PROTO, EXIT_DENIED = 1, 2, 3, 4


def eprint(*args) -> None:
    print(*args, file=sys.stderr, flush=True)


class Usage(argparse.ArgumentParser):
    def error(self, message):  # exit 2, as the suite expects
        eprint(f"usage: {message}")
        sys.exit(EXIT_USAGE)


def exit_for(err: BaseException) -> None:
    eprint(err)
    if isinstance(err, pfrelay.ProtoError):
        sys.exit(EXIT_PROTO)
    if isinstance(err, pfrelay.AccessDenied):
        sys.exit(EXIT_DENIED)
    sys.exit(EXIT_FAIL)


async def pipe(conn: pfrelay.Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy both ways, passing half-closes on, until both directions are
    done or one fails."""

    async def outbound():  # TCP -> tunnel
        while True:
            data = await reader.read(64 * 1024)
            if not data:
                break
            await conn.write(data)
        await conn.close_write()

    async def inbound():  # tunnel -> TCP
        while True:
            data = await conn.read(64 * 1024)
            if not data:
                break
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


async def serve(client: pfrelay.Client, target: str, stop: asyncio.Event) -> None:
    try:
        listener = await client.listen()
    except (pfrelay.PfRelayError, OSError, ValueError) as e:
        exit_for(e)
    print("ready", flush=True)
    host, _, port = target.rpartition(":")
    tasks: set[asyncio.Task] = set()

    async def one(conn: pfrelay.Conn) -> None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host.strip("[]"), int(port)), 5)
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            eprint(f"connection {conn.id[:8]}: cannot reach {target}: {e}")
            await conn.fail("the serving side could not reach its target")
            return
        await pipe(conn, reader, writer)

    async def accept_loop() -> None:
        while True:
            try:
                conn = await listener.accept()
            except pfrelay.ClosedError:
                return
            t = asyncio.ensure_future(one(conn))
            tasks.add(t)
            t.add_done_callback(tasks.discard)

    loop_task = asyncio.ensure_future(accept_loop())
    stopper = asyncio.ensure_future(stop.wait())
    await asyncio.wait({loop_task, stopper}, return_when=asyncio.FIRST_COMPLETED)
    if loop_task.done() and loop_task.exception() is not None:
        exit_for(loop_task.exception())
    await listener.close()
    loop_task.cancel()


async def connect(client: pfrelay.Client, listen: str, stop: asyncio.Event) -> None:
    host, _, port = listen.rpartition(":")

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            conn = await client.dial()
        except Exception as e:
            eprint("dial:", e)
            writer.transport.abort()
            return
        await pipe(conn, reader, writer)

    try:
        server = await asyncio.start_server(handle, host.strip("[]") or None, int(port))
    except (OSError, ValueError) as e:
        exit_for(e)
    addr = server.sockets[0].getsockname()
    shown = f"[{addr[0]}]:{addr[1]}" if ":" in addr[0] else f"{addr[0]}:{addr[1]}"
    print(f"listening {shown}", flush=True)
    await stop.wait()
    server.close()


async def main() -> None:
    if len(sys.argv) < 2:
        eprint("usage: driver.py serve|connect|check|version [flags]")
        sys.exit(EXIT_USAGE)
    cmd = sys.argv[1]
    ap = Usage(prog=f"driver.py {cmd}")
    ap.add_argument("--server", required=True)
    ap.add_argument("--ca", default=None)
    ap.add_argument("--word", default="aaaa-bbbb-cccc")  # version needs none
    ap.add_argument("--serve-token", default="")
    ap.add_argument("--client-token", default="")
    ap.add_argument("--name", default="conformance")
    ap.add_argument("--target", default="")
    ap.add_argument("--listen", default="")
    args = ap.parse_args(sys.argv[2:])
    if cmd not in ("serve", "connect", "check", "version"):
        eprint(f"unknown command {cmd}")
        sys.exit(EXIT_USAGE)

    ctx = ssl.create_default_context(cafile=args.ca)
    try:
        client = pfrelay.Client(
            args.server,
            args.word,
            ssl_context=ctx,
            serve_token=args.serve_token,
            client_token=args.client_token,
            name=args.name,
            target=args.target,
            agent=f"{pfrelay.DEFAULT_AGENT} conformance",
        )
    except ValueError as e:
        eprint(e)
        sys.exit(EXIT_USAGE)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    try:
        if cmd == "version":
            info = await client.probe()
            print(json.dumps(info.to_dict()), flush=True)
        elif cmd == "check":
            await client.check()
        elif cmd == "serve":
            await serve(client, args.target, stop)
        else:
            await connect(client, args.listen, stop)
    except (pfrelay.PfRelayError, OSError, ssl.SSLError, asyncio.TimeoutError) as e:
        exit_for(e)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    sys.exit(0)
