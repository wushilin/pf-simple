//! Serving over an attached transport (see [`crate::transport`]): the same
//! retry loop, backlog, refusals and forwarder as over WebSocket, with the
//! transport's registrations and opens in place of the control channel and
//! `accept`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::client::Client;
use crate::conn::{Conn, Side};
use crate::error::{Error, Result};
use crate::events::ConnId;
use crate::forward::{bridge, SERVE, TARGET_DIAL_TIMEOUT, TARGET_UNREACHABLE};
use crate::listener::{short, sleep, Handler, Shared, BACKLOG_FULL, LISTEN_BACKLOG, STOPPED_LISTENING};
use crate::reuse::Registration;
use crate::transport::{Open, Params, Transport};

/// Keeps a registration over `t`, and carries each connection the hub asks
/// for on its own task, until `sh.cancel`. As `listener::serve_loop`.
pub(crate) async fn serve_loop(
    c: Client,
    t: Arc<dyn Transport>,
    sh: Arc<Shared>,
    handler: Handler,
    target: String,
    registered: Option<oneshot::Sender<Result<()>>>,
) -> Result<()> {
    let timing = c.inner.timing;
    let mut registered = registered;
    let mut backoff = timing.retry_min;
    let mut served = false;
    let mut attempt = 0u32;
    let label = c.word_label();
    loop {
        attempt += 1;
        let result = tokio::select! {
            _ = sh.cancel.cancelled() => return Ok(()),
            r = t.register(Params::new(&c), &target) => r,
        };
        match result {
            Err(e) if matches!(e, Error::Proto(_)) || (!served && e.is_final()) => {
                c.log(&format!("cannot register with {}: {e}", c.server()));
                let out = match registered.take() {
                    Some(r) => {
                        let _ = r.send(Err(e));
                        Err(Error::Closed)
                    }
                    None if served => {
                        *sh.end.lock().unwrap() = Some(Error::Protocol(e.to_string()));
                        Err(e)
                    }
                    None => Err(e),
                };
                sh.cancel.cancel();
                sh.drain_queue();
                return out;
            }
            Err(e) => {
                c.log(&format!(
                    "cannot register with {} ({e}); attempt {attempt}, trying again in {backoff:?}",
                    c.server()
                ));
            }
            Ok(mut alt) => {
                if served {
                    c.log(&format!(
                        "registered again with {} after {attempt} attempt(s): tunnel {label} -> {target}",
                        c.server()
                    ));
                } else {
                    c.log(&format!("registered with {}: tunnel {label} -> {target}", c.server()));
                }
                served = true;
                attempt = 0;
                sh.up.store(true, Ordering::Release);
                if let Some(r) = registered.take() {
                    let _ = r.send(Ok(()));
                }
                c.events().serving(true);
                let started = Instant::now();
                let reg = Registration::new(c.clone(), sh.clone(), handler.clone(), None);
                let why = loop {
                    tokio::select! {
                        _ = sh.cancel.cancelled() => break "stopped".to_string(),
                        o = alt.next() => match o {
                            Ok(open) => {
                                tokio::spawn(carry(c.clone(), reg.clone(), open));
                            }
                            Err(e) => break e.to_string(),
                        },
                    }
                };
                alt.close();
                reg.cancel.cancel();
                sh.up.store(false, Ordering::Release);
                c.events().serving(false);
                if sh.cancel.is_cancelled() {
                    return Ok(());
                }
                if started.elapsed() >= timing.settled {
                    backoff = timing.retry_min;
                }
                c.log(&format!(
                    "lost the server ({why}); its connections are closed; registering again in {backoff:?}"
                ));
            }
        }
        if !sleep(&sh.cancel, backoff).await {
            return Ok(());
        }
        backoff = timing.next(backoff);
    }
}

/// Refuses an open, telling the far end `reason`.
async fn refuse(c: &Client, open: Box<dyn Open>, id: &str, reason: &str) {
    c.events().refused(&ConnId::new(id), reason);
    open.refuse(reason).await;
}

/// Carries one connection the hub asked for: to the listener's queue, or
/// to the forwarder's target.
async fn carry(c: Client, reg: Arc<Registration>, open: Box<dyn Open>) {
    let id = open.id().to_string();
    let sh = &reg.sh;
    match &reg.handler {
        Handler::Forward(target) => {
            // The target first: the far end hears at once when it cannot be
            // reached (PROTOCOL.md §9).
            let tcp = match tokio::time::timeout(TARGET_DIAL_TIMEOUT, TcpStream::connect(&**target)).await {
                Ok(Ok(tcp)) => tcp,
                failed => {
                    let why = match failed {
                        Ok(Err(e)) => e.to_string(),
                        _ => "it did not answer".to_string(),
                    };
                    c.log(&format!("connection {} failed: cannot reach the target {target}: {why}", short(&id)));
                    return refuse(&c, open, &id, TARGET_UNREACHABLE).await;
                }
            };
            let stream = match open.accept().await {
                Ok(s) => s,
                Err(e) => {
                    c.log(&format!("connection {} failed: cannot bring it to the server: {e}", short(&id)));
                    return;
                }
            };
            let conn = Conn::start_framed(stream, &id, Side::Serve, c.inner.registry.clone());
            c.log(&format!("connection {} open: tunnel -> {target}", short(&id)));
            bridge(&c, conn, tcp, &SERVE, &sh.cancel).await;
        }
        Handler::Listen(tx) => {
            let slot = match sh.slots.clone().try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    c.log(&format!(
                        "connection {} refused: {LISTEN_BACKLOG} connections are waiting to be accepted",
                        short(&id)
                    ));
                    return refuse(&c, open, &id, BACKLOG_FULL).await;
                }
            };
            let stream = match open.accept().await {
                Ok(s) => s,
                Err(e) => {
                    c.log(&format!("connection {} failed: cannot bring it to the server: {e}", short(&id)));
                    return;
                }
            };
            let conn = Conn::start_framed(stream, &id, Side::Serve, c.inner.registry.clone());
            if sh.cancel.is_cancelled() {
                conn.fail(STOPPED_LISTENING).await;
                return;
            }
            if let Err(mpsc::error::SendError((conn, _))) = tx.send((conn, slot)).await {
                conn.fail(STOPPED_LISTENING).await;
            }
        }
    }
}
