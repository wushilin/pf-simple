//! A QUIC stream as pfrelay's Conn wants it (PROTOCOL.md §13.5): bytes both
//! ways, FIN on shutdown, and every stream driven to its end in both
//! directions.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::AbortHandle;

use crate::transport::Hold;
use crate::wire::code;

/// How long an end keeps a stream after its FIN (after an err, an end, or
/// a refusal too), for the peer to end its own direction (§13.5).
pub const DELIVER_WAIT: Duration = Duration::from_secs(3);

type Send = Arc<Mutex<Option<SendStream>>>;

/// One bidirectional QUIC stream.
///
/// - `poll_shutdown` sends FIN.
/// - Dropped after FIN, it keeps reading (and discarding) until the peer
///   ends its direction, for at most [`DELIVER_WAIT`], then stops reading.
///   Dropped without FIN, it resets both directions (`cancelled`).
/// - A STOP_SENDING from the peer is answered with RESET_STREAM at once,
///   echoing its code, whether or not this end is writing: quinn only
///   records it (§13.5).
/// - It holds its QUIC connection open until it has ended, after its FIN
///   wait too: a Conn outlives its Client, as over WebSocket.
pub(crate) struct QStream {
    send: Send,
    recv: Option<RecvStream>,
    finished: bool,
    watcher: Option<AbortHandle>,
    hold: Option<Hold>,
}

fn varint(c: u32) -> VarInt {
    VarInt::from_u32(c)
}

/// Answers the peer's STOP_SENDING with RESET_STREAM.
async fn answer_stop(stopped: impl std::future::Future<Output = Result<Option<VarInt>, quinn::StoppedError>>, send: Weak<Mutex<Option<SendStream>>>) {
    if let Ok(Some(code)) = stopped.await {
        if let Some(s) = send.upgrade() {
            if let Some(s) = s.lock().unwrap().as_mut() {
                let _ = s.reset(code);
            }
        }
    }
}

impl QStream {
    pub(crate) fn new(send: SendStream, recv: RecvStream, hold: Hold) -> QStream {
        let stopped = send.stopped();
        let send = Arc::new(Mutex::new(Some(send)));
        let watcher = tokio::spawn(answer_stop(stopped, Arc::downgrade(&send))).abort_handle();
        QStream { send, recv: Some(recv), finished: false, watcher: Some(watcher), hold: Some(hold) }
    }

    /// Resets the stream: RESET_STREAM for this direction and STOP_SENDING
    /// for the other, both with `c` (§13.5).
    pub(crate) fn reset(&mut self, c: u32) {
        if let Some(s) = self.send.lock().unwrap().as_mut() {
            let _ = s.reset(varint(c));
        }
        if let Some(r) = self.recv.as_mut() {
            let _ = r.stop(varint(c));
        }
        self.finished = false;
        self.recv = None;
        *self.send.lock().unwrap() = None;
    }

    /// Ends this direction with RESET_STREAM only.
    pub(crate) fn reset_write(&mut self, c: u32) {
        if let Some(s) = self.send.lock().unwrap().as_mut() {
            let _ = s.reset(varint(c));
        }
    }

    /// Sends FIN.
    pub(crate) fn finish(&mut self) {
        if let Some(s) = self.send.lock().unwrap().as_mut() {
            let _ = s.finish();
        }
        self.finished = true;
    }
}

impl Drop for QStream {
    fn drop(&mut self) {
        if let Some(w) = self.watcher.take() {
            w.abort();
        }
        let send = self.send.lock().unwrap().take();
        let recv = self.recv.take();
        let (Some(mut send), Some(mut recv)) = (send, recv) else {
            return; // reset already
        };
        if !self.finished {
            let _ = send.reset(varint(code::CANCELLED));
            let _ = recv.stop(varint(code::CANCELLED));
            return;
        }
        // After FIN: give the peer a little time to end its direction, so
        // what was sent last is not dropped, and still answer its
        // STOP_SENDING. Then stop reading.
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let hold = self.hold.take();
        rt.spawn(async move {
            let stopped = send.stopped();
            tokio::pin!(stopped);
            let mut watching = true;
            {
                let drain = tokio::time::timeout(DELIVER_WAIT, async {
                    let mut buf = vec![0u8; 16 << 10];
                    while let Ok(Some(_)) = recv.read(&mut buf).await {}
                });
                tokio::pin!(drain);
                loop {
                    tokio::select! {
                        _ = &mut drain => break,
                        r = &mut stopped, if watching => {
                            watching = false;
                            if let Ok(Some(code)) = r {
                                let _ = send.reset(code);
                            }
                        }
                    }
                }
            }
            let _ = recv.stop(varint(code::CANCELLED));
            drop(hold); // the connection may close now, if it is retired
        });
    }
}

impl AsyncRead for QStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().recv.as_mut() {
            Some(r) => Pin::new(r).poll_read(cx, buf),
            None => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "the stream was reset"))),
        }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "the stream was reset")
}

impl AsyncWrite for QStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut g = self.send.lock().unwrap();
        match g.as_mut() {
            Some(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
            None => Poll::Ready(Err(closed())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        let r = match this.send.lock().unwrap().as_mut() {
            Some(s) => s.finish().map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e)),
            None => Err(closed()),
        };
        if r.is_ok() {
            this.finished = true;
        }
        Poll::Ready(r)
    }
}
