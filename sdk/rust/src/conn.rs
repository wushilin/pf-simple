//! One connection through a tunnel: a stream (PROTOCOL.md §8) over its own
//! WebSocket, and the client's bookkeeping of its connections.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;
use tokio_util::sync::PollSender;

use crate::error::{Error, RemoteError, Result};
use crate::events::{ConnId, Events};
use crate::http::{Stream as Tls, Upgraded};
use crate::reuse::{Leg, Registration, MSG_IDLE};
use crate::values::clean_reason;
use crate::ws::{self, FrameReader, CHUNK, OP_BINARY, OP_CLOSE, OP_CONT, OP_PING, OP_TEXT, STREAM_LIMITS};

/// Each end of a stream pings this often, on its own timer.
pub const PING_EVERY: Duration = Duration::from_secs(10);
/// A stream that hears nothing for this long is dead.
pub const LINK_SILENCE: Duration = Duration::from_secs(30);
/// How long a close waits for the far end's close, and bounds each write
/// once closing has begun.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(3);
/// Frames queued for the writer.
const WRITE_QUEUE: usize = 8;
/// Frames read ahead of the application.
const READ_QUEUE: usize = 4;
const CLOSE_NORMAL: [u8; 2] = [0x03, 0xE8];
/// Bounds the write of this side's `idle`.
const IDLE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Which end of the tunnel a connection belongs to. It prints, parses and
/// serializes as `connect` or `serve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    /// Opened by [`Client::dial`](crate::Client::dial).
    Connect,
    /// Brought in by a [`Listener`](crate::Listener).
    Serve,
}

impl Side {
    pub const ALL: [Side; 2] = [Side::Connect, Side::Serve];

    pub fn as_str(self) -> &'static str {
        match self {
            Side::Connect => "connect",
            Side::Serve => "serve",
        }
    }
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Side {
    type Err = Error;
    fn from_str(s: &str) -> Result<Side> {
        Side::ALL
            .into_iter()
            .find(|side| side.as_str() == s)
            .ok_or_else(|| Error::Config(format!("unknown side {s:?}")))
    }
}

/// A snapshot of one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    /// The hub's connection id.
    pub id: ConnId,
    pub side: Side,
    /// When the connection was opened.
    pub opened: SystemTime,
    /// Bytes sent into the tunnel.
    pub sent: i64,
    /// Bytes received from the tunnel.
    pub received: i64,
    /// This end has half-closed.
    pub wrote_eof: bool,
    /// The far end has half-closed.
    pub read_eof: bool,
}

/// A client's connections, open and closed, since it was made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connections opened.
    pub opened: u64,
    /// Connections open now.
    pub active: u64,
    /// Connections that ended with an error.
    pub failed: u64,
    /// Bytes sent into the tunnel.
    pub sent: i64,
    /// Bytes received from the tunnel.
    pub received: i64,
}

pub(crate) struct Record {
    key: u64,
    id: ConnId,
    side: Side,
    opened: SystemTime,
    sent: AtomicI64,
    received: AtomicI64,
    wrote_eof: AtomicBool,
    read_eof: AtomicBool,
    finished: AtomicBool,
    /// The reason this side dropped it with, if it did.
    dropped: Mutex<Option<String>>,
    /// The stream, for `drop_conn`.
    stream: OnceLock<Weak<Shared>>,
}

impl Record {
    fn info(&self) -> ConnInfo {
        ConnInfo {
            id: self.id.clone(),
            side: self.side,
            opened: self.opened,
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            wrote_eof: self.wrote_eof.load(Ordering::Relaxed),
            read_eof: self.read_eof.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct Totals {
    live: BTreeMap<u64, Arc<Record>>,
    opened: u64,
    failed: u64,
    sent: i64,
    received: i64,
}

/// A client's live connections, its totals, and its event handlers.
#[derive(Default)]
pub(crate) struct Registry {
    next: AtomicU64,
    totals: Mutex<Totals>,
    pub(crate) events: Events,
}

impl Registry {
    pub(crate) fn new(events: Events) -> Registry {
        Registry { events, ..Registry::default() }
    }

    fn add(&self, id: &str, side: Side) -> Arc<Record> {
        let rec = Arc::new(Record {
            key: self.next.fetch_add(1, Ordering::Relaxed),
            id: ConnId::new(id),
            side,
            opened: SystemTime::now(),
            sent: AtomicI64::new(0),
            received: AtomicI64::new(0),
            wrote_eof: AtomicBool::new(false),
            read_eof: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            dropped: Mutex::new(None),
            stream: OnceLock::new(),
        });
        let mut t = self.totals.lock().unwrap();
        t.live.insert(rec.key, rec.clone());
        t.opened += 1;
        rec
    }

    /// Moves `rec` out of the live set and reports it, once. `err` is why it
    /// failed; a connection this side dropped reads as [`Error::Dropped`].
    fn finish(&self, rec: &Record, err: Option<Error>) -> bool {
        if rec.finished.swap(true, Ordering::AcqRel) {
            return false;
        }
        // A connection this side dropped failed, however it ended.
        let err = match rec.dropped.lock().unwrap().clone() {
            Some(reason) => Some(Error::Dropped { reason }),
            None => err,
        };
        {
            let mut t = self.totals.lock().unwrap();
            t.live.remove(&rec.key);
            if err.is_some() {
                t.failed += 1;
            }
            t.sent += rec.sent.load(Ordering::Relaxed);
            t.received += rec.received.load(Ordering::Relaxed);
        }
        if let Some(f) = &self.events.close {
            f(&rec.info(), err.as_ref());
        }
        true
    }

    /// Drops the open connection `id` and tells the far end `reason`.
    pub(crate) fn drop_conn(&self, id: &ConnId, reason: &str) -> bool {
        self.drop_where(id, None, reason)
    }

    /// Abandons the serving side's attempt at `id`, whose leg was lost
    /// before the hub heard `bound` (PROTOCOL.md §12.7). Only the serving
    /// side's connections are touched: the same client may also be
    /// connecting through the tunnel, and that connection has the same id.
    pub(crate) fn abandon(&self, id: &ConnId) -> bool {
        self.drop_where(id, Some(Side::Serve), crate::reuse::REASON_LEG_LOST)
    }

    fn drop_where(&self, id: &ConnId, side: Option<Side>, reason: &str) -> bool {
        let rec = self
            .totals
            .lock()
            .unwrap()
            .live
            .values()
            .find(|r| &r.id == id && side.is_none_or(|s| r.side == s))
            .cloned();
        let Some(sh) = rec.as_ref().and_then(|r| r.stream.get()).and_then(Weak::upgrade) else {
            return false;
        };
        let reason = clean_local(reason);
        sh.rec.dropped.lock().unwrap().get_or_insert(reason.clone());
        sh.set_failure(Failure::Dropped(reason.clone()));
        sh.closing.send_replace(true);
        let _ = sh.ctl.send(Ctl::Fail(reason));
        true
    }

    pub(crate) fn stats(&self) -> Stats {
        let t = self.totals.lock().unwrap();
        let mut st = Stats {
            opened: t.opened,
            active: t.live.len() as u64,
            failed: t.failed,
            sent: t.sent,
            received: t.received,
        };
        for rec in t.live.values() {
            st.sent += rec.sent.load(Ordering::Relaxed);
            st.received += rec.received.load(Ordering::Relaxed);
        }
        st
    }

    /// Open connections, oldest first.
    pub(crate) fn conns(&self) -> Vec<ConnInfo> {
        self.totals.lock().unwrap().live.values().map(|r| r.info()).collect()
    }
}

/// Why a stream broke, as its reader saw it.
#[derive(Debug, Clone)]
enum Failure {
    Remote(String),
    PeerClosed,
    Silent,
    Lost(String),
    Protocol(String),
    Dropped(String),
    Closed,
}

impl Failure {
    fn to_error(&self) -> Error {
        match self {
            Failure::Remote(r) => Error::Remote(RemoteError { reason: r.clone() }),
            Failure::PeerClosed => Error::Link("the server closed the connection".into()),
            Failure::Silent => Error::Link(format!(
                "the link to the server was silent for {}s",
                LINK_SILENCE.as_secs()
            )),
            Failure::Lost(why) => Error::Link(format!("the link to the server was lost ({why})")),
            Failure::Protocol(why) => Error::Protocol(why.clone()),
            Failure::Dropped(reason) => Error::Dropped { reason: reason.clone() },
            Failure::Closed => Error::Closed,
        }
    }

    fn to_io(&self) -> io::Error {
        let kind = match self {
            Failure::Remote(_) => io::ErrorKind::ConnectionAborted,
            Failure::PeerClosed | Failure::Lost(_) => io::ErrorKind::ConnectionReset,
            Failure::Silent => io::ErrorKind::TimedOut,
            Failure::Protocol(_) => io::ErrorKind::InvalidData,
            Failure::Dropped(_) => io::ErrorKind::ConnectionAborted,
            Failure::Closed => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, self.to_error())
    }

    fn of(err: &io::Error) -> Failure {
        match err.kind() {
            io::ErrorKind::TimedOut => Failure::Silent,
            io::ErrorKind::UnexpectedEof => Failure::Lost("it ended without a close".into()),
            io::ErrorKind::InvalidData => Failure::Protocol(err.to_string()),
            _ => Failure::Lost(err.to_string()),
        }
    }
}

/// What the reader, the writer and the application share.
struct Shared {
    rec: Arc<Record>,
    /// The first error that broke reading.
    failure: Mutex<Option<Failure>>,
    /// What broke writing.
    write_error: Mutex<Option<Failure>>,
    /// An `err:` that arrived after the far end's half-close.
    gone_reason: Mutex<Option<String>>,
    /// The reader has stopped: the far end closed, or the link died.
    gone: watch::Sender<bool>,
    /// Closing has begun: bound every write from now on.
    closing: watch::Sender<bool>,
    /// The far end sent a close frame, which must be answered.
    peer_close: Notify,
    /// This end failed: a broken read or write, or `fail`.
    failed: AtomicBool,
    /// Tells the writer to close or fail the stream.
    ctl: mpsc::UnboundedSender<Ctl>,
    /// The registration whose leg this is, when the hub offered reuse
    /// (protocol 2).
    reuse: Option<Arc<Registration>>,
    /// The reader stopped at the hub's valid `idle`, and left the leg's
    /// reader in `leg_reader`: the far end is not gone, the leg goes on.
    idled: watch::Sender<bool>,
    leg_reader: Mutex<Option<Frames>>,
    /// The writer has finished: the stream is over, one way or another.
    ended: watch::Sender<bool>,
    /// What `fail` or a forwarder said the connection ended with, if this
    /// end saw no error of its own.
    end_hint: Mutex<Option<Error>>,
    registry: Arc<Registry>,
    /// A protocol 3 stream over QUIC (PROTOCOL.md §13.5), not a WebSocket.
    framed: bool,
}

type Frames = FrameReader<ReadHalf<Tls>>;

impl Shared {
    fn set_failure(&self, f: Failure) {
        self.failed.store(true, Ordering::Release);
        self.failure.lock().unwrap().get_or_insert(f);
    }

    /// Why the connection failed, as `Conn::err` says it.
    fn err(&self) -> Option<Error> {
        if let Some(f) = self.failure.lock().unwrap().as_ref() {
            return Some(f.to_error());
        }
        self.gone_reason.lock().unwrap().as_ref().map(|r| Error::Remote(RemoteError { reason: r.clone() }))
    }

    /// The first error that broke this end: reading or writing.
    fn local_error(&self) -> Option<Error> {
        if let Some(f) = self.failure.lock().unwrap().as_ref() {
            return Some(f.to_error());
        }
        match self.write_error.lock().unwrap().as_ref() {
            // The far end's close after a clean finish breaks nothing.
            None | Some(Failure::PeerClosed) => None,
            Some(f) => Some(f.to_error()),
        }
    }
}

enum Event {
    Data(Vec<u8>),
    Eof,
    Failed(Failure),
}

enum Cmd {
    Data(Vec<u8>),
    Eof,
}

enum Ctl {
    Close,
    Fail(String),
}

struct ReadState {
    rx: mpsc::Receiver<Event>,
    pending: Vec<u8>,
    pos: usize,
    /// How reading ended: `Ok` for the far end's half-close.
    end: Option<std::result::Result<(), Failure>>,
}

struct WriteState {
    tx: PollSender<Cmd>,
    eof: bool,
}

/// One connection through a tunnel.
///
/// It is an [`AsyncRead`] + [`AsyncWrite`], and so is `&Conn`, so one task
/// can read while another writes:
///
/// - a read returns 0 bytes when the far end half-closes; it fails with an
///   [`Error::Remote`] (inside the `io::Error`; see [`Error::from_io`]) when
///   the far end or the hub dropped the connection with a reason;
/// - `shutdown` half-closes: the far end reads the end of the stream after
///   what was written so far, and may go on sending;
/// - [`Conn::fail`] drops the connection with a reason for the far end;
/// - [`Conn::close`] ends it, half-closing first if that was not done.
///
/// Writes are handed to a task that puts them on the wire in order; `close`
/// waits until they are sent. Dropping a `Conn` closes it the same way, in
/// the background.
pub struct Conn {
    shared: Arc<Shared>,
    registry: Arc<Registry>,
    rd: Mutex<ReadState>,
    wr: Mutex<WriteState>,
    writer: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").field("id", &self.shared.rec.id).field("side", &self.shared.rec.side).finish()
    }
}

impl Conn {
    /// A connection on a new WebSocket. `reuse` is its registration when
    /// the hub offered reuse.
    pub(crate) fn start(
        up: Upgraded,
        id: &str,
        side: Side,
        registry: Arc<Registry>,
        reuse: Option<Arc<Registration>>,
    ) -> Conn {
        let (r, w) = tokio::io::split(up.stream);
        let frames = FrameReader::new(r, up.leftover, STREAM_LIMITS, LINK_SILENCE);
        Conn::on_leg(Leg { frames, w }, id, side, registry, reuse)
    }

    /// A connection on a QUIC stream that has passed its request and answer
    /// (or its open and answer): protocol 3's framing, with the stream's
    /// FIN for the close (PROTOCOL.md §13.5).
    pub(crate) fn start_framed(stream: Tls, id: &str, side: Side, registry: Arc<Registry>) -> Conn {
        let (r, w) = tokio::io::split(stream);
        Conn::on_leg(Leg { frames: FrameReader::framed(r), w }, id, side, registry, None)
    }

    /// A connection on a leg: a new one, or a reused one that answered
    /// `bound`. Nothing else reads or writes the leg from now on.
    pub(crate) fn on_leg(
        leg: Leg,
        id: &str,
        side: Side,
        registry: Arc<Registry>,
        reuse: Option<Arc<Registration>>,
    ) -> Conn {
        let Leg { frames, w } = leg;
        let framed = frames.is_framed();
        let rec = registry.add(id, side);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            rec,
            failure: Mutex::new(None),
            write_error: Mutex::new(None),
            gone_reason: Mutex::new(None),
            gone: watch::channel(false).0,
            closing: watch::channel(false).0,
            peer_close: Notify::new(),
            failed: AtomicBool::new(false),
            ctl: ctl_tx,
            reuse,
            idled: watch::channel(false).0,
            leg_reader: Mutex::new(None),
            ended: watch::channel(false).0,
            end_hint: Mutex::new(None),
            registry: registry.clone(),
            framed,
        });
        let _ = shared.rec.stream.set(Arc::downgrade(&shared));
        let (ev_tx, ev_rx) = mpsc::channel(READ_QUEUE);
        let (cmd_tx, cmd_rx) = mpsc::channel(WRITE_QUEUE);
        let reader = tokio::spawn(read_loop(frames, ev_tx, shared.clone())).abort_handle();
        let writer = tokio::spawn(write_loop(w, cmd_rx, ctl_rx, shared.clone(), reader));
        let conn = Conn {
            shared,
            registry,
            rd: Mutex::new(ReadState { rx: ev_rx, pending: Vec::new(), pos: 0, end: None }),
            wr: Mutex::new(WriteState { tx: PollSender::new(cmd_tx), eof: false }),
            writer: Mutex::new(Some(writer)),
            closed: AtomicBool::new(false),
        };
        if let Some(f) = &conn.registry.events.open {
            f(&conn.shared.rec.info());
        }
        conn
    }

    /// The hub's id for this connection, the same on both ends.
    pub fn id(&self) -> &ConnId {
        &self.shared.rec.id
    }

    /// Which end of the tunnel this is.
    pub fn side(&self) -> Side {
        self.shared.rec.side
    }

    /// A snapshot of this connection.
    pub fn info(&self) -> ConnInfo {
        self.shared.rec.info()
    }

    /// Why the connection failed, once that is known: the far end's or the
    /// hub's reason ([`Error::Remote`]), or a lost link. `None` while it is
    /// fine, or after a clean finish.
    ///
    /// It can say more than a read did: the hub may pass a failure of the
    /// far end on as a half-close first, so a read returns 0 and the reason
    /// arrives just after it (PROTOCOL.md §8.3).
    pub fn err(&self) -> Option<Error> {
        self.shared.err()
    }

    /// Waits until the far end, having half-closed, is gone for good, or
    /// the link died, and returns what [`Conn::err`] then says.
    pub async fn finished(&self) -> Option<Error> {
        let sh = &self.shared;
        let (mut gone, mut idled, mut ended) = (sh.gone.subscribe(), sh.idled.subscribe(), sh.ended.subscribe());
        // Gone, or the hub's verdict "idle" (the far end finished cleanly),
        // or the stream ended here.
        tokio::select! {
            _ = gone.wait_for(|g| *g) => {}
            _ = idled.wait_for(|i| *i) => {}
            _ = ended.wait_for(|e| *e) => {}
        }
        self.err()
    }

    /// Drops the connection and tells the far end why: its reads fail with
    /// a [`RemoteError`] carrying `reason`.
    pub async fn fail(&self, reason: &str) {
        let reason = clean_local(reason);
        let hint = Error::Dropped { reason: reason.clone() };
        self.end(Ctl::Fail(reason), Some(hint)).await;
    }

    /// Ends the connection, after sending what was written. If this end has
    /// not half-closed, it does so first. When both ends had half-closed,
    /// the close is clean; otherwise the far end sees the connection cut.
    ///
    /// The connection is reported closed when its stream has ended, even if
    /// this future is dropped before then.
    pub async fn close(&self) -> Result<()> {
        self.end(Ctl::Close, None).await;
        Ok(())
    }

    /// Ends a broken connection: with `reason` for the far end, or cut
    /// without one. It ends with the first error this end saw, or `err`.
    pub(crate) async fn end_with(&self, reason: Option<&str>, err: Error) {
        let how = match reason {
            Some(r) => Ctl::Fail(clean_local(r)),
            None => Ctl::Close,
        };
        self.end(how, Some(err)).await;
    }

    /// Ends the stream, once: the first of `close`, `fail` and drop wins.
    /// `hint`, if any, is what it ended with unless this end saw an error
    /// of its own; it also marks the end as failed. The writer reports the
    /// connection when it has finished, so a dropped future changes nothing.
    async fn end(&self, how: Ctl, hint: Option<Error>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(h) = hint {
            self.shared.failed.store(true, Ordering::Release);
            *self.shared.end_hint.lock().unwrap() = Some(h);
        }
        self.shared.closing.send_replace(true);
        let _ = self.shared.ctl.send(how);
        let writer = self.writer.lock().unwrap().take();
        if let Some(w) = writer {
            let _ = w.await;
        }
    }

    fn poll_read_inner(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut st = self.rd.lock().unwrap();
        loop {
            if st.pos < st.pending.len() {
                let n = (st.pending.len() - st.pos).min(buf.remaining());
                buf.put_slice(&st.pending[st.pos..st.pos + n]);
                st.pos += n;
                if st.pos == st.pending.len() {
                    st.pending = Vec::new();
                    st.pos = 0;
                }
                self.shared.rec.received.fetch_add(n as i64, Ordering::Relaxed);
                return Poll::Ready(Ok(()));
            }
            if let Some(end) = &st.end {
                return Poll::Ready(end.clone().map_err(|f| f.to_io()));
            }
            if self.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(Failure::Closed.to_io()));
            }
            match st.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Event::Data(v))) => {
                    st.pending = v;
                    st.pos = 0;
                }
                Poll::Ready(Some(Event::Eof)) => st.end = Some(Ok(())),
                Poll::Ready(Some(Event::Failed(f))) => st.end = Some(Err(f)),
                Poll::Ready(None) => {
                    let f = self.shared.failure.lock().unwrap().clone().unwrap_or(Failure::Closed);
                    st.end = Some(Err(f));
                }
            }
        }
    }

    fn write_check(&self, st: &WriteState) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Failure::Closed.to_io());
        }
        if let Some(f) = self.shared.write_error.lock().unwrap().as_ref() {
            return Err(f.to_io());
        }
        if st.eof {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write after half-close"));
        }
        Ok(())
    }

    fn poll_write_inner(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut st = self.wr.lock().unwrap();
        self.write_check(&st)?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match st.tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(self.writer_gone())),
            Poll::Ready(Ok(())) => {
                let n = buf.len().min(CHUNK);
                if st.tx.send_item(Cmd::Data(buf[..n].to_vec())).is_err() {
                    return Poll::Ready(Err(self.writer_gone()));
                }
                self.shared.rec.sent.fetch_add(n as i64, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_shutdown_inner(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.wr.lock().unwrap();
        if st.eof {
            return Poll::Ready(Ok(()));
        }
        self.write_check(&st)?;
        match st.tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(self.writer_gone())),
            Poll::Ready(Ok(())) => {
                if st.tx.send_item(Cmd::Eof).is_err() {
                    return Poll::Ready(Err(self.writer_gone()));
                }
                st.eof = true;
                self.shared.rec.wrote_eof.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
        }
    }

    fn writer_gone(&self) -> io::Error {
        let dropped = match self.shared.failure.lock().unwrap().as_ref() {
            Some(f @ Failure::Dropped(_)) => Some(f.clone()),
            _ => None,
        };
        dropped
            .or_else(|| self.shared.write_error.lock().unwrap().clone())
            .unwrap_or(Failure::Closed)
            .to_io()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            // Closed in the background as `close` would; the writer reports
            // it once that is done: after the hub's verdict on a reusable leg.
            self.shared.closing.send_replace(true);
            let _ = self.shared.ctl.send(Ctl::Close);
        }
    }
}

impl AsyncRead for &Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for &Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_inner(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_inner(cx)
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_inner(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_inner(cx)
    }
}

/// A reason this side gives, made fit for a text frame.
fn clean_local(reason: &str) -> String {
    reason.chars().filter(|c| !c.is_control()).collect()
}

// ---------- the reader ----------

async fn read_loop(mut frames: Frames, tx: mpsc::Sender<Event>, sh: Arc<Shared>) {
    if read_data(&mut frames, &tx, &sh).await && watch_after_eof(&mut frames, &sh).await {
        // The hub's valid "idle": the leg goes on, and its reader with it.
        *sh.leg_reader.lock().unwrap() = Some(frames);
        sh.idled.send_replace(true);
        if *sh.ended.borrow() {
            // The writer finished meanwhile, and nobody will take the leg:
            // close its read half here.
            drop(sh.leg_reader.lock().unwrap().take());
        }
        return;
    }
    sh.gone.send_replace(true);
}

/// Reads the stream up to the far end's half-close (true) or its failure
/// (false).
async fn read_data(frames: &mut Frames, tx: &mpsc::Sender<Event>, sh: &Shared) -> bool {
    let failed = |f: Failure| {
        sh.set_failure(f.clone());
        Event::Failed(f)
    };
    loop {
        let frame = match frames.next().await {
            Ok(f) => f,
            Err(e) => {
                let _ = tx.send(failed(Failure::of(&e))).await;
                return false;
            }
        };
        match frame.op {
            OP_BINARY | OP_CONT => {
                if !frame.payload.is_empty() && tx.send(Event::Data(frame.payload)).await.is_err() {
                    return false; // nobody reads any more
                }
            }
            OP_TEXT => {
                if !frame.fin {
                    let _ = tx.send(failed(Failure::Protocol("a fragmented text frame".into()))).await;
                    return false;
                }
                if frame.payload == MSG_IDLE && sh.reuse.is_some() {
                    let _ = tx.send(failed(idle_violation(sh))).await;
                    return false;
                }
                if frame.payload == b"eof" {
                    sh.rec.read_eof.store(true, Ordering::Release);
                    let _ = tx.send(Event::Eof).await;
                    return true;
                }
                if let Some(reason) = frame.payload.strip_prefix(b"err:") {
                    let reason = clean_reason(&String::from_utf8_lossy(reason));
                    let _ = tx.send(failed(Failure::Remote(reason))).await;
                    return false;
                }
                // any other text frame is ignored
            }
            OP_CLOSE => {
                sh.peer_close.notify_one();
                let _ = tx.send(failed(Failure::PeerClosed)).await;
                return false;
            }
            _ => {} // pings are not answered; pongs are ignored
        }
    }
}

/// The hub's `idle` where it does not belong (before both half-closes): a
/// violation, which fails the connection and cuts the leg (§12.4).
fn idle_violation(sh: &Shared) -> Failure {
    let f = Failure::Protocol("the server said idle before this side had half-closed".into());
    sh.set_failure(f.clone());
    sh.closing.send_replace(true);
    let _ = sh.ctl.send(Ctl::Close);
    f
}

/// Keeps reading after the far end's half-close: an `err:` may still come
/// (PROTOCOL.md §8.3), and the far end's close or a dead link must be seen.
/// On a leg offered reuse, it stops at the hub's `idle` after both
/// half-closes, and returns true (§12.5).
async fn watch_after_eof(frames: &mut Frames, sh: &Shared) -> bool {
    loop {
        let Ok(frame) = frames.next().await else { return false };
        match frame.op {
            OP_BINARY | OP_CONT => {
                // Nothing may follow a half-close: a broken peer.
                sh.set_failure(Failure::Protocol("data after the far end's half-close".into()));
                return false;
            }
            OP_TEXT => {
                if sh.framed && frame.payload == b"eof" {
                    // A second eof breaks the protocol (§13.4).
                    sh.set_failure(Failure::Protocol("a second eof from the far end".into()));
                    return false;
                }
                if frame.payload == MSG_IDLE && sh.reuse.is_some() {
                    // Valid only once this end has half-closed too; in any
                    // other state it is a violation, which ends the leg.
                    if frame.fin && sh.rec.wrote_eof.load(Ordering::Acquire) {
                        return true;
                    }
                    let _ = idle_violation(sh);
                    return false;
                }
                if let Some(reason) = frame.payload.strip_prefix(b"err:") {
                    let reason = clean_reason(&String::from_utf8_lossy(reason));
                    *sh.gone_reason.lock().unwrap() = Some(reason);
                }
            }
            OP_CLOSE => {
                sh.peer_close.notify_one();
                return false;
            }
            _ => {}
        }
    }
}

// ---------- the writer ----------

/// Waits up to `wait`, after both half-closes, for the hub's `idle`: true
/// when it came. A close, a dead link, or nothing in time is false.
async fn await_idle(sh: &Shared, wait: Duration) -> bool {
    let (mut idled, mut gone) = (sh.idled.subscribe(), sh.gone.subscribe());
    tokio::select! {
        r = idled.wait_for(|i| *i) => r.is_ok(),
        _ = gone.wait_for(|g| *g) => false,
        _ = tokio::time::sleep(wait) => false,
    }
}

/// Writes one frame. Once closing has begun, the write may take at most
/// CLOSE_TIMEOUT, also when it was already under way.
async fn put(
    w: &mut WriteHalf<Tls>,
    closing: &mut watch::Receiver<bool>,
    framed: bool,
    op: u8,
    payload: &[u8],
) -> io::Result<()> {
    let fut = async {
        if framed {
            ws::write_framed(w, op, payload).await
        } else {
            ws::write_frame(w, op, payload).await
        }
    };
    tokio::pin!(fut);
    let bounded = |r: std::result::Result<io::Result<()>, _>| {
        r.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out while closing")))
    };
    let already = *closing.borrow();
    if already {
        return bounded(tokio::time::timeout(CLOSE_TIMEOUT, fut).await);
    }
    tokio::select! {
        r = &mut fut => return r,
        r = closing.wait_for(|c| *c) => drop(r),
    }
    bounded(tokio::time::timeout(CLOSE_TIMEOUT, &mut fut).await)
}

async fn write_loop(
    mut w: WriteHalf<Tls>,
    mut data: mpsc::Receiver<Cmd>,
    mut ctl: mpsc::UnboundedReceiver<Ctl>,
    sh: Arc<Shared>,
    reader: AbortHandle,
) {
    // However the writer ends, even aborted: the reader stops, a leg reader
    // parked by a late "idle" is closed, and the connection is reported.
    struct Exit(Arc<Shared>, AbortHandle);
    impl Drop for Exit {
        fn drop(&mut self) {
            let sh = &self.0;
            // "ended" first: a reader parking the leg after the take below
            // sees it, and closes the leg itself.
            sh.ended.send_replace(true);
            self.1.abort();
            drop(sh.leg_reader.lock().unwrap().take());
            let err = sh.local_error().or_else(|| sh.end_hint.lock().unwrap().take()).or_else(|| sh.err());
            sh.registry.finish(&sh.rec, err);
        }
    }
    let _exit = Exit(sh.clone(), reader);
    let mut closing = sh.closing.subscribe();
    let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut eof_written = false;
    let mut close_sent = false;
    let mut broken = false;
    let broke = |sh: &Shared, e: io::Error| {
        sh.failed.store(true, Ordering::Release);
        sh.write_error.lock().unwrap().get_or_insert(Failure::of(&e));
    };

    let how = loop {
        tokio::select! {
            biased;
            c = ctl.recv() => break c.unwrap_or(Ctl::Close),
            _ = sh.peer_close.notified(), if !close_sent => {
                // Answer the far end's close, as RFC 6455 requires.
                close_sent = true;
                if !broken {
                    let _ = put(&mut w, &mut closing, sh.framed, OP_CLOSE, &CLOSE_NORMAL).await;
                }
                broken = true;
                sh.write_error.lock().unwrap().get_or_insert(Failure::PeerClosed);
            }
            c = data.recv() => match c {
                None => break Ctl::Close, // the Conn was dropped
                Some(cmd) => {
                    if broken {
                        continue;
                    }
                    let r = match cmd {
                        Cmd::Data(b) => put(&mut w, &mut closing, sh.framed, OP_BINARY, &b).await,
                        Cmd::Eof => {
                            eof_written = true;
                            put(&mut w, &mut closing, sh.framed, OP_TEXT, b"eof").await
                        }
                    };
                    if let Err(e) = r {
                        broken = true;
                        broke(&sh, e);
                    }
                }
            },
            _ = ping.tick() => {
                if !broken && !sh.framed {
                    if let Err(e) = put(&mut w, &mut closing, sh.framed, OP_PING, &[]).await {
                        broken = true;
                        broke(&sh, e);
                    }
                }
            }
        }
    };

    match how {
        Ctl::Fail(reason) => {
            if !broken {
                let msg = format!("err:{reason}");
                let mut text = msg.as_bytes();
                if !sh.framed && text.len() > ws::MAX_TEXT_FRAME as usize {
                    let mut cut = ws::MAX_TEXT_FRAME as usize;
                    while !msg.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    text = &text[..cut];
                }
                if put(&mut w, &mut closing, sh.framed, OP_TEXT, text).await.is_ok() && !close_sent {
                    let _ = put(&mut w, &mut closing, sh.framed, OP_CLOSE, &CLOSE_NORMAL).await;
                }
            }
        }
        Ctl::Close => {
            // What was written before the close goes out first.
            while let Ok(cmd) = data.try_recv() {
                if broken {
                    break;
                }
                let r = match cmd {
                    Cmd::Data(b) => put(&mut w, &mut closing, sh.framed, OP_BINARY, &b).await,
                    Cmd::Eof => {
                        eof_written = true;
                        put(&mut w, &mut closing, sh.framed, OP_TEXT, b"eof").await
                    }
                };
                if let Err(e) = r {
                    broken = true;
                    broke(&sh, e);
                }
            }
            if !broken && !eof_written && !sh.failed.load(Ordering::Acquire) {
                eof_written = true;
                sh.rec.wrote_eof.store(true, Ordering::Release);
                if let Err(e) = put(&mut w, &mut closing, sh.framed, OP_TEXT, b"eof").await {
                    broken = true;
                    broke(&sh, e);
                }
            }
            let clean = eof_written && sh.rec.read_eof.load(Ordering::Acquire);
            if clean && !broken && !close_sent && !sh.failed.load(Ordering::Acquire) {
                if let Some(reg) = &sh.reuse {
                    // A leg offered reuse: the hub's verdict decides
                    // (PROTOCOL.md §12.5).
                    if await_idle(&sh, reg.verdict_wait()).await {
                        let frames = sh.leg_reader.lock().unwrap().take();
                        if let Some(frames) = frames {
                            if reg.keep() {
                                let answered =
                                    tokio::time::timeout(IDLE_WRITE_TIMEOUT, put(&mut w, &mut closing, sh.framed, OP_TEXT, MSG_IDLE)).await;
                                if matches!(answered, Ok(Ok(()))) {
                                    reg.adopt(Leg { frames, w });
                                    return;
                                }
                                reg.release();
                            }
                        }
                        // Not kept: the hub's "idle" is answered with a
                        // close. Nobody reads the leg any more, so nothing
                        // waits for the reply.
                        let _ = put(&mut w, &mut closing, sh.framed, OP_CLOSE, &CLOSE_NORMAL).await;
                        let _ = tokio::time::timeout(Duration::from_secs(1), w.shutdown()).await;
                        return;
                    }
                    // An err:, a close, or nothing in time: protocol 1 rules.
                }
            }
            if clean && !sh.failed.load(Ordering::Acquire) {
                // A clean finish: the closing handshake, then wait briefly
                // for the far end's close so the last bytes are not reset.
                if (close_sent || put(&mut w, &mut closing, sh.framed, OP_CLOSE, &CLOSE_NORMAL).await.is_ok())
                    && !broken
                {
                    // The far end's close, or nobody reading any more: a
                    // reader that stopped at the hub's "idle" sees no close.
                    let (mut gone, mut idled) = (sh.gone.subscribe(), sh.idled.subscribe());
                    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
                        tokio::select! {
                            _ = gone.wait_for(|g| *g) => {}
                            _ = idled.wait_for(|i| *i) => {}
                        }
                    })
                    .await;
                    let _ = tokio::time::timeout(Duration::from_secs(1), w.shutdown()).await;
                } else if close_sent {
                    let _ = tokio::time::timeout(Duration::from_secs(1), w.shutdown()).await;
                }
            }
            // Anything else cuts the stream: the socket is dropped.
        }
    }
    if sh.framed && sh.write_error.lock().unwrap().is_some() && !*sh.gone.borrow() {
        // A write can fail before the reason is read: a STOP_SENDING may
        // overtake the err that was sent before it. Keep reading for the
        // reason, which is reported instead of the write error (§13.5).
        let mut gone = sh.gone.subscribe();
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, gone.wait_for(|g| *g)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Head;
    use crate::ws::OP_PONG;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// The hub's end of a stream: sends unmasked frames, reads masked ones.
    struct Hub(DuplexStream);

    impl Hub {
        async fn send(&mut self, op: u8, payload: &[u8]) {
            let mut f = vec![0x80 | op];
            let n = payload.len();
            if n < 126 {
                f.push(n as u8);
            } else {
                f.push(126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            f.extend_from_slice(payload);
            self.0.write_all(&f).await.unwrap();
        }

        /// The next frame from the client, checked to be masked and final.
        async fn recv(&mut self) -> (u8, Vec<u8>) {
            let mut h = [0u8; 2];
            self.0.read_exact(&mut h).await.unwrap();
            assert_eq!(h[0] & 0xF0, 0x80, "FIN set, no RSV bits");
            assert_eq!(h[1] & 0x80, 0x80, "masked");
            let len = match h[1] & 0x7F {
                126 => {
                    let mut b = [0u8; 2];
                    self.0.read_exact(&mut b).await.unwrap();
                    u16::from_be_bytes(b) as usize
                }
                127 => {
                    let mut b = [0u8; 8];
                    self.0.read_exact(&mut b).await.unwrap();
                    u64::from_be_bytes(b) as usize
                }
                n => n as usize,
            };
            let mut mask = [0u8; 4];
            self.0.read_exact(&mut mask).await.unwrap();
            let mut body = vec![0u8; len];
            self.0.read_exact(&mut body).await.unwrap();
            for (i, b) in body.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
            (h[0] & 0x0F, body)
        }

        /// The next frame that is not a ping.
        async fn recv_data(&mut self) -> (u8, Vec<u8>) {
            loop {
                let f = self.recv().await;
                if f.0 != OP_PING {
                    return f;
                }
            }
        }
    }

    fn pair() -> (Conn, Hub, Arc<Registry>) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let reg = Arc::new(Registry::default());
        let up = Upgraded { stream: Box::new(a), leftover: Vec::new(), head: Head::default() };
        (Conn::start(up, "8f14e45fceea167a", Side::Connect, reg.clone(), None), Hub(b), reg)
    }

    #[tokio::test]
    async fn data_half_close_and_clean_close() {
        let (conn, mut hub, reg) = pair();
        let mut c = &conn;
        let big = vec![7u8; 100_000];
        c.write_all(&big).await.unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        loop {
            match hub.recv_data().await {
                (OP_BINARY, b) => {
                    assert!(b.len() <= CHUNK);
                    got.extend(b);
                }
                (OP_TEXT, t) => {
                    assert_eq!(t, b"eof");
                    break;
                }
                f => panic!("unexpected frame {f:?}"),
            }
        }
        assert_eq!(got, big);
        assert!(c.write_all(b"x").await.is_err(), "no data after a half-close");

        hub.send(OP_BINARY, b"back").await;
        hub.send(OP_PING, b"").await; // not answered, and harmless
        hub.send(OP_PONG, b"").await; // ignored
        hub.send(OP_TEXT, b"something else").await; // ignored
        hub.send(OP_TEXT, b"eof").await;
        let mut back = Vec::new();
        c.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"back");
        assert!(conn.info().read_eof);
        assert!(conn.info().wrote_eof);

        let closing = tokio::spawn(async move {
            let (op, _) = hub.recv_data().await;
            assert_eq!(op, OP_CLOSE, "both eofs exchanged: a close frame");
            hub.send(OP_CLOSE, &CLOSE_NORMAL).await;
            hub
        });
        conn.close().await.unwrap();
        closing.await.unwrap();
        assert!(conn.err().is_none());
        let st = reg.stats();
        assert_eq!((st.opened, st.active, st.failed, st.sent, st.received), (1, 0, 0, 100_000, 4));
    }

    #[tokio::test]
    async fn a_reason_after_the_half_close() {
        let (conn, mut hub, reg) = pair();
        hub.send(OP_BINARY, b"partial").await;
        hub.send(OP_TEXT, b"eof").await;
        hub.send(OP_TEXT, b"err:the target reset its connection\x07").await;
        hub.send(OP_CLOSE, &CLOSE_NORMAL).await;
        let mut got = Vec::new();
        (&conn).read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"partial");
        let err = conn.finished().await.expect("the reason after the eof");
        assert!(matches!(&err, Error::Remote(r) if r.reason == "the target reset its connection"), "{err:?}");
        conn.close().await.unwrap();
        assert_eq!(reg.stats().failed, 1);
    }

    #[tokio::test]
    async fn a_reason_instead_of_data() {
        let (conn, mut hub, _) = pair();
        hub.send(OP_TEXT, b"err:the serving side could not reach its target").await;
        let mut buf = [0u8; 8];
        let e = (&conn).read(&mut buf).await.unwrap_err();
        match Error::from_io(&e) {
            Some(Error::Remote(r)) => assert_eq!(r.reason, "the serving side could not reach its target"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_close_without_eofs_is_a_failure() {
        let (conn, mut hub, _) = pair();
        hub.send(OP_CLOSE, &CLOSE_NORMAL).await;
        let mut buf = [0u8; 8];
        assert!((&conn).read(&mut buf).await.is_err());
        // The close is answered.
        assert_eq!(hub.recv_data().await.0, OP_CLOSE);
        assert!(conn.err().is_some());
    }

    #[tokio::test]
    async fn a_link_that_ends_is_a_failure() {
        let (conn, hub, _) = pair();
        drop(hub);
        let mut buf = [0u8; 8];
        assert!((&conn).read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn fail_sends_the_reason() {
        let (conn, mut hub, reg) = pair();
        conn.fail("pf-client serve is stopping").await;
        assert_eq!(hub.recv_data().await, (OP_TEXT, b"err:pf-client serve is stopping".to_vec()));
        assert_eq!(hub.recv_data().await.0, OP_CLOSE);
        assert_eq!(reg.stats().failed, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn pings_on_its_own_timer() {
        let (_conn, mut hub, _) = pair();
        tokio::time::sleep(PING_EVERY + Duration::from_millis(100)).await;
        assert_eq!(hub.recv().await.0, OP_PING);
    }
}
