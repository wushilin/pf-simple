"""Forwarding: carry a local TCP connection through a tunnel connection,
both ways, with half-close and reasons. Mirrors bridge in the Go SDK."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from ._conn import CHUNK_SIZE, Conn
from ._proto import ClosedError, RemoteError
from ._ws import PeerClosedError, SilentLinkError

# How long to wait for the last direction after the far end went away, so
# that a clean finish is not taken for the far end leaving.
_GONE_GRACE = 0.2


@dataclass(frozen=True)
class Party:
    """The ends of the chain as one side sees them, so that a reason can say
    which hop broke:

        application -- connect side == hub == serve side -- target
    """

    self: str  # this program
    local: str  # what its TCP connection goes to
    far: str  # what is at the other end of the tunnel


PARTY_CONNECT = Party("pfrelay connect", "the application", "the target")
PARTY_SERVE = Party("pfrelay serve", "the target", "the application")


def link_reason(p: Party, err: BaseException) -> str:
    """A failure of the stream to the hub, in words."""
    if isinstance(err, RemoteError):
        return err.reason
    if isinstance(err, SilentLinkError):
        return f"the link between {p.self} and the server was silent for too long"
    if isinstance(err, PeerClosedError):
        return "the server closed the connection"
    return f"the link between {p.self} and the server was lost ({err})"


def local_reason(p: Party, err: BaseException) -> str:
    """A failure of the local TCP connection, in words."""
    if isinstance(err, (ConnectionResetError, BrokenPipeError)):
        return f"{p.local} reset its connection to {p.self}"
    return f"the connection between {p.self} and {p.local} failed ({err})"


@dataclass(frozen=True)
class _End:
    """How one direction stopped; both errors None: it finished cleanly."""

    outbound: bool  # local -> tunnel
    read_err: Optional[BaseException] = None
    write_err: Optional[BaseException] = None

    @property
    def clean(self) -> bool:
        return self.read_err is None and self.write_err is None


@dataclass(frozen=True)
class Ended:
    """The outcome of one carried connection."""

    reason: str  # why it ended, for the log
    err: Optional[BaseException]  # None after a clean finish


async def _outbound(conn: Conn, reader: asyncio.StreamReader) -> _End:
    while True:
        try:
            data = await reader.read(CHUNK_SIZE)
        except Exception as e:
            return _End(True, read_err=e)
        try:
            if not data:
                await conn.close_write()
                return _End(True)
            await conn.write(data)
        except Exception as e:
            return _End(True, write_err=e)


async def _inbound(conn: Conn, writer: asyncio.StreamWriter) -> _End:
    while True:
        try:
            data = await conn.read(CHUNK_SIZE)
        except Exception as e:
            return _End(False, read_err=e)
        try:
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return _End(False)
            writer.write(data)
            await writer.drain()
        except Exception as e:
            return _End(False, write_err=e)


def _describe(p: Party, r: _End) -> tuple[str, bool, Optional[BaseException]]:
    """(reason, mine, err): mine is True when the cause is on this side of
    the tunnel, which the far end cannot see for itself."""
    if r.clean and r.outbound:
        return f"{p.local} closed the connection", True, None
    if r.clean:
        return f"{p.far} closed the connection", False, None
    if r.outbound and r.read_err is not None:
        return local_reason(p, r.read_err), True, r.read_err
    if r.outbound:
        return link_reason(p, r.write_err), False, r.write_err
    if r.read_err is not None:
        # A silent link may still carry what this end sends, so say so.
        return link_reason(p, r.read_err), isinstance(r.read_err, SilentLinkError), r.read_err
    return local_reason(p, r.write_err), True, r.write_err


async def bridge(conn: Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, p: Party) -> Ended:
    """Copy both ways until both directions finish cleanly or either fails,
    then close both ends. When this end saw the break, it tells the far end
    why, so that both sides name the same cause."""
    out_t = asyncio.ensure_future(_outbound(conn, reader))
    in_t = asyncio.ensure_future(_inbound(conn, writer))
    tasks = {out_t, in_t}
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        first = done.pop()
        reason, mine, err = _describe(p, first.result())
        if err is None:
            # One direction finished cleanly. If it was the far end's
            # half-close, watch for the far end going away while this end
            # still has the floor.
            second = in_t if first is out_t else out_t

            def then(r: _End) -> None:
                nonlocal reason, mine, err
                why, whose, failed = _describe(p, r)
                if failed is not None:
                    reason, mine, err = why, whose, failed

            gone = asyncio.ensure_future(conn.wait_closed())
            try:
                await asyncio.wait({second, gone}, return_when=asyncio.FIRST_COMPLETED)
                if not second.done():
                    await asyncio.wait({second}, timeout=_GONE_GRACE)
                if second.done():
                    then(second.result())
                else:
                    mine = False
                    err = conn.err or PeerClosedError("the server closed the connection")
                    reason = str(conn.err) if conn.err else "the server closed the connection"
            finally:
                gone.cancel()
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await conn._fail(f"{p.self} is stopping", ClosedError(f"{p.self} is stopping"))
        writer.transport.abort()
        raise
    for t in tasks:
        t.cancel()
    if err is not None and mine:
        await conn._fail(reason, err)
    else:
        await conn._close_with(err)
    if err is None:
        writer.close()
    else:
        writer.transport.abort()
    return Ended(reason, err)
