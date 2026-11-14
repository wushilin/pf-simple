//! Serving a tunnel: the registration, its control channel (PROTOCOL.md §7)
//! and the retry loop (§9).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::client::{Client, H_ERROR};
use crate::conn::{Conn, Side};
use crate::error::{Error, Result};
use crate::http::Upgraded;
use crate::proto::Endpoint;
use crate::ws::{self, FrameReader, CONTROL_LIMITS, OP_CLOSE, OP_PING, OP_PONG, OP_TEXT};

/// How many connections may wait for [`Listener::accept`]. More are
/// refused, and their connecting side is told why.
pub const LISTEN_BACKLOG: usize = 128;
/// The serving side pings its control channel this often.
pub const CONTROL_PING: Duration = Duration::from_secs(20);
/// A control channel that hears nothing for this long is dead.
pub const CONTROL_SILENCE: Duration = Duration::from_secs(60);

// Retry timing (PROTOCOL.md §9).
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
/// A control channel that lasted this long resets the pause.
const SETTLED: Duration = Duration::from_secs(60);

type Pending = (Conn, OwnedSemaphorePermit);

struct Shared {
    cancel: CancellationToken,
    up: AtomicBool,
    slots: Arc<Semaphore>,
    /// Why serving stopped on its own, if it did.
    end: Mutex<Option<Error>>,
}

/// Serves the tunnel and hands each connection to [`Listener::accept`].
///
/// It keeps itself registered: a lost hub is registered with again, with a
/// growing pause, until [`Listener::close`]. Connections that were open end
/// when the hub is lost. Dropping the listener closes it.
pub struct Listener {
    client: Client,
    shared: Arc<Shared>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Pending>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").field("client", &self.client).field("up", &self.is_up()).finish()
    }
}

impl Client {
    /// Registers the tunnel with the hub and returns once it is registered.
    ///
    /// A refusal that waiting cannot cure is returned as an error: 403 as
    /// [`Error::AccessDenied`], other final 4xx as [`Error::Status`] (such
    /// as 409, a word of another tenant), a hub too old for what was asked
    /// as [`Error::Proto`]. Anything else, including a hub that cannot be
    /// reached, is retried with a pause of 1 second doubling up to 30.
    pub async fn listen(&self) -> Result<Listener> {
        let shared = Arc::new(Shared {
            cancel: CancellationToken::new(),
            up: AtomicBool::new(false),
            slots: Arc::new(Semaphore::new(LISTEN_BACKLOG)),
            end: Mutex::new(None),
        });
        // Should this future be dropped while waiting, serving stops.
        let guard = shared.cancel.clone().drop_guard();
        let (tx, rx) = mpsc::channel(LISTEN_BACKLOG);
        let (reg_tx, reg_rx) = oneshot::channel();
        tokio::spawn(serve_loop(self.clone(), shared.clone(), tx, reg_tx));
        match reg_rx.await {
            Ok(Ok(())) => {
                guard.disarm();
                Ok(Listener { client: self.clone(), shared, rx: tokio::sync::Mutex::new(rx) })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::Closed),
        }
    }
}

impl Listener {
    /// Waits for the next connection.
    ///
    /// Fails with [`Error::Closed`] once the listener is closed, or with
    /// the reason serving stopped on its own (a hub that became too old).
    pub async fn accept(&self) -> Result<Conn> {
        let mut rx = self.rx.lock().await;
        tokio::select! {
            biased;
            _ = self.shared.cancel.cancelled() => {
                Err(self.shared.end.lock().unwrap().take().unwrap_or(Error::Closed))
            }
            p = rx.recv() => match p {
                Some((conn, _slot)) => Ok(conn),
                None => Err(Error::Closed),
            },
        }
    }

    /// Whether the tunnel is registered with the hub right now.
    pub fn is_up(&self) -> bool {
        self.shared.up.load(Ordering::Acquire)
    }

    /// The client this listener serves for.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Stops serving: the registration ends, and connections not yet
    /// accepted are dropped. Accepted connections stay open until the hub
    /// link they use ends, or they are closed.
    pub fn close(&self) {
        self.shared.cancel.cancel();
        if let Ok(mut rx) = self.rx.try_lock() {
            while let Ok((conn, _slot)) = rx.try_recv() {
                drop_pending(conn);
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.close();
    }
}

fn drop_pending(conn: Conn) {
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(async move { conn.fail("the serving side stopped listening").await });
    }
}

async fn sleep(cancel: &CancellationToken, d: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(d) => true,
    }
}

/// Keeps a control channel registered, and answers each open on its own
/// task. The first registration's outcome goes to `registered`.
async fn serve_loop(c: Client, sh: Arc<Shared>, tx: mpsc::Sender<Pending>, registered: oneshot::Sender<Result<()>>) {
    let mut registered = Some(registered);
    let mut backoff = RETRY_MIN;
    let mut served = false;
    let mut attempt = 0u32;
    let headers = c.serve_headers();
    let label = c.word_label();
    loop {
        attempt += 1;
        let result = tokio::select! {
            _ = sh.cancel.cancelled() => return,
            r = c.upgrade(Endpoint::Serve, headers.clone()) => r,
        };
        match result {
            Err(e) if matches!(e, Error::Proto(_)) || (!served && e.is_final()) => {
                // Waiting will not change it.
                c.log(&format!("cannot register with {}: {e}", c.server()));
                stop(&sh, registered.take(), e);
                return;
            }
            Err(e) => {
                c.log(&format!(
                    "cannot register with {} ({e}); attempt {attempt}, trying again in {}s",
                    c.server(),
                    backoff.as_secs()
                ));
            }
            Ok(up) => {
                if served {
                    c.log(&format!("registered again with {} after {attempt} attempt(s): tunnel {label}", c.server()));
                } else {
                    c.log(&format!("registered with {}: tunnel {label}", c.server()));
                }
                served = true;
                attempt = 0;
                sh.up.store(true, Ordering::Release);
                if let Some(r) = registered.take() {
                    let _ = r.send(Ok(()));
                }
                let started = Instant::now();
                let why = control(&c, &sh, &tx, up).await;
                sh.up.store(false, Ordering::Release);
                if sh.cancel.is_cancelled() {
                    return;
                }
                if started.elapsed() >= SETTLED {
                    backoff = RETRY_MIN;
                }
                c.log(&format!(
                    "lost the server ({why}); its connections are closed; registering again in {}s",
                    backoff.as_secs()
                ));
            }
        }
        if !sleep(&sh.cancel, backoff).await {
            return;
        }
        backoff = (backoff * 2).min(RETRY_MAX);
    }
}

fn stop(sh: &Shared, registered: Option<oneshot::Sender<Result<()>>>, e: Error) {
    match registered {
        Some(r) => {
            let _ = r.send(Err(e));
        }
        None => {
            *sh.end.lock().unwrap() = Some(e);
        }
    }
    sh.cancel.cancel();
}

/// The connection id in an open message, if it is one (PROTOCOL.md §7).
pub(crate) fn parse_open(payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let id = v.as_object()?.get("open")?.as_str()?;
    (!id.is_empty() && id.bytes().all(|b| (0x21..=0x7e).contains(&b))).then(|| id.to_string())
}

/// Runs one control channel until it ends, and says why.
async fn control(c: &Client, sh: &Arc<Shared>, tx: &mpsc::Sender<Pending>, up: Upgraded) -> String {
    let (r, mut w) = tokio::io::split(up.stream);
    let mut frames = FrameReader::new(r, up.leftover, CONTROL_LIMITS, CONTROL_SILENCE);
    let mut ping = tokio::time::interval_at(Instant::now() + CONTROL_PING, CONTROL_PING);
    loop {
        tokio::select! {
            _ = sh.cancel.cancelled() => {
                let _ = tokio::time::timeout(Duration::from_secs(3), ws::write_frame(&mut w, OP_CLOSE, &[0x03, 0xE8])).await;
                return "stopped".into();
            }
            _ = ping.tick() => {
                if let Err(e) = write(&mut w, OP_PING, &[]).await {
                    return format!("cannot ping it: {e}");
                }
            }
            f = frames.next() => match f {
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return format!("silent for {}s", CONTROL_SILENCE.as_secs());
                }
                Err(e) => return e.to_string(),
                Ok(f) => match f.op {
                    OP_TEXT if f.fin => {
                        if let Some(id) = parse_open(&f.payload) {
                            tokio::spawn(open(c.clone(), sh.clone(), tx.clone(), id));
                        }
                    }
                    OP_PING => {
                        if let Err(e) = write(&mut w, OP_PONG, &f.payload).await {
                            return e.to_string();
                        }
                    }
                    OP_CLOSE => {
                        let code = &f.payload[..f.payload.len().min(2)];
                        let _ = write(&mut w, OP_CLOSE, code).await;
                        return "it closed the control channel".into();
                    }
                    _ => {}
                },
            },
        }
    }
}

async fn write<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, op: u8, payload: &[u8]) -> std::io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), ws::write_frame(w, op, payload))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out")))
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Answers the hub's open message for connection `id`.
async fn open(c: Client, sh: Arc<Shared>, tx: mpsc::Sender<Pending>, id: String) {
    let slot = match sh.slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            c.log(&format!(
                "connection {} refused: {LISTEN_BACKLOG} connections are waiting to be accepted",
                short(&id)
            ));
            let mut h = c.accept_headers(&id);
            h.push((H_ERROR, "the serving side is not accepting connections fast enough".into()));
            let _ = c.get(Endpoint::Accept, h).await;
            return;
        }
    };
    let up = match c.upgrade(Endpoint::Accept, c.accept_headers(&id)).await {
        Ok(up) => up,
        Err(e) => {
            c.log(&format!("connection {} failed: cannot bring it to the server: {e}", short(&id)));
            return;
        }
    };
    let conn = Conn::start(up, id, Side::Serve, c.inner.registry.clone());
    if sh.cancel.is_cancelled() {
        conn.fail("the serving side stopped listening").await;
        return;
    }
    if let Err(mpsc::error::SendError((conn, _))) = tx.send((conn, slot)).await {
        conn.fail("the serving side stopped listening").await;
    }
}

#[cfg(test)]
mod tests {
    use super::parse_open;

    #[test]
    fn open_messages() {
        assert_eq!(parse_open(br#"{"open":"8f14e45fceea167a"}"#).as_deref(), Some("8f14e45fceea167a"));
        assert_eq!(parse_open(br#"{"open":"8f14e45fceea167a","more":1}"#).as_deref(), Some("8f14e45fceea167a"));
        for ignored in [&br#"{"open":""}"#[..], br#"{"close":"x"}"#, b"[1]", b"not json", br#"{"open":1}"#, br#"{"open":"a b"}"#] {
            assert_eq!(parse_open(ignored), None);
        }
    }
}
