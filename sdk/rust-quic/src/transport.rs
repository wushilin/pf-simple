//! The QUIC transport (PROTOCOL.md §13), plugged into pfrelay's Client:
//! discovery over HTTPS, one QUIC connection to the hub made again when it
//! is lost, and `serve`, `connect` and `check` as requests on its streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pfrelay::transport::{self, BoxFuture, Params, Stream};
use pfrelay::{Error, Result};
use quinn::{ConnectionError, TransportErrorCode, VarInt};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::time::Instant;

use crate::pin::{quic_config, Pin};
use crate::stream::QStream;
use crate::wire::{self, code, Answer, Discovery, End, MsgError, OpenAnswer, Request};
use crate::PROTO;

/// How long the client waits for the hub's answer to a request (§13.4).
pub const ANSWER_WAIT: Duration = Duration::from_secs(15);
/// How long a serving side waits for the open on a stream the hub opened,
/// and for the answer to its own serve before it refuses an open (§13.4).
pub const REQUEST_WAIT: Duration = Duration::from_secs(10);
/// Bounds the QUIC handshake.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// Bounds writing an answer to an open.
const WRITE_WAIT: Duration = Duration::from_secs(10);
/// Opens queued for a registration, beyond the listener's backlog.
const OPEN_QUEUE: usize = 128;

const PATH: &str = "/pf/api/tunnel/quic";
const H_VERSION: &str = "X-PF-Version";
const H_OP: &str = "X-PF-Tunnel-Op";
const H_SERVE: &str = "X-PF-Serve-Token";
const H_WORD: &str = "X-PF-Tunnel-Word";
const H_CLIENT_TOKEN: &str = "X-PF-Client-Token";

/// What a hub without QUIC means (§13.2).
pub const NO_QUIC: &str = "this hub does not offer QUIC: it is older than pf-simple 0.16.0, or its relay hub is off; upgrade it, or use pf-client (WebSocket)";
/// A hub certificate that is not one of the discovered fingerprints, twice.
pub const PIN_MISMATCH: &str = "the hub's QUIC certificate does not match what its HTTPS endpoint announced";

/// What a run is for, as discovery asks it (§13.2). A check counts as
/// connect.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Serve,
    Connect,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Serve => "serve",
            Op::Connect => "connect",
        }
    }
}

/// Reaches the hub over one QUIC connection, made again when it is lost.
#[derive(Default)]
pub(crate) struct Quic {
    conn: tokio::sync::Mutex<Option<Arc<QConn>>>,
}

impl Drop for Quic {
    fn drop(&mut self) {
        self.close();
    }
}

impl Quic {
    /// Asks the hub's HTTPS endpoint where its QUIC listener is.
    async fn discover(&self, p: &Params, op: Op) -> Result<Discovery> {
        let mut h = vec![("User-Agent", p.agent().to_string()), (H_VERSION, p.agent().to_string()), (H_OP, op.as_str().into())];
        match op {
            Op::Serve => {
                if let Some(t) = p.serve_token() {
                    h.push((H_SERVE, t.to_string()));
                }
            }
            Op::Connect => {
                h.push((H_WORD, p.word().to_string()));
                if let Some(t) = p.client_token() {
                    h.push((H_CLIENT_TOKEN, t.to_string()));
                }
            }
        }
        let a = p.get(PATH, &h).await?;
        match a.status {
            200 => {}
            // A hub without QUIC does not know the endpoint.
            404 => return Err(Error::Status { code: 404, message: NO_QUIC.into() }),
            _ => return Err(a.refusal()),
        }
        let d: Discovery = serde_json::from_slice(&a.body)
            .map_err(|_| Error::Protocol("the hub's answer to QUIC discovery is not understood".into()))?;
        d.check().map_err(Error::Protocol)?;
        Ok(d)
    }

    /// The QUIC connection to the hub, made if there is none: discovery,
    /// then a handshake that pins the certificate, with one more discovery
    /// after a mismatch (§13.3).
    async fn get(&self, p: &Params, op: Op) -> Result<Arc<QConn>> {
        let mut slot = self.conn.lock().await;
        if let Some(qc) = slot.as_ref().filter(|qc| qc.conn.close_reason().is_none()) {
            return Ok(qc.clone());
        }
        *slot = None;
        for _ in 0..2 {
            let d = self.discover(p, op).await?;
            match dial(&d).await {
                Ok(qc) => {
                    *slot = Some(qc.clone());
                    return Ok(qc);
                }
                Err(Dial::Mismatch) => continue,
                Err(Dial::Failed(e)) => return Err(e),
            }
        }
        Err(Error::Tls(PIN_MISMATCH.into()))
    }

    /// Forgets `qc` as the connection to use, if it still is.
    async fn forget(&self, qc: &Arc<QConn>) {
        let mut slot = self.conn.lock().await;
        if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, qc)) {
            *slot = None;
        }
    }

    /// Opens a stream, sends `req`, and reads the hub's answer. A refusal
    /// comes back as an error, after this direction is ended.
    async fn request(&self, p: &Params, op: Op, mut req: Request) -> Result<(Arc<QConn>, QStream, Answer)> {
        let qc = self.get(p, op).await?;
        req.proto = PROTO.to_string();
        req.version = p.agent().to_string();
        req.word = p.word().to_string();
        let (send, recv) = match qc.conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                self.forget(&qc).await;
                return Err(Error::Link(format!("the QUIC connection to the hub was lost ({e})")));
            }
        };
        let mut s = QStream::new(send, recv);
        let answered = tokio::time::timeout(ANSWER_WAIT, async {
            wire::write_message(&mut s, &req).await.map_err(|e| e.to_string())?;
            wire::read_message::<_, Answer>(&mut s).await.map_err(|e| e.to_string())
        })
        .await;
        let a = match answered {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                s.reset(code::REQUEST_TIMEOUT);
                return Err(Error::Link(format!("the hub did not answer ({e})")));
            }
            Err(_) => {
                s.reset(code::REQUEST_TIMEOUT);
                return Err(Error::Link("the hub did not answer in time".into()));
            }
        };
        if a.proto != 0 && a.proto != PROTO {
            s.reset(code::PROTOCOL);
            return Err(Error::Protocol(format!(
                "the hub answered in QUIC protocol {}; this client speaks {PROTO}",
                a.proto
            )));
        }
        if a.status != 200 && a.status != 204 {
            // The hub sends FIN and STOP_SENDING; end this direction too.
            s.reset_write(code::REFUSED);
            drop(s);
            if a.status == 429 && a.scope == "connection" {
                self.forget(&qc).await; // the next request opens a new connection (§13.8)
            }
            return Err(transport::refused(a.status, &a.error));
        }
        Ok((qc, s, a))
    }

    fn close(&self) {
        if let Ok(mut slot) = self.conn.try_lock() {
            if let Some(qc) = slot.take() {
                qc.conn.close(VarInt::from_u32(code::NONE), b"done");
            }
        }
    }
}

/// Why a QUIC handshake failed.
enum Dial {
    Mismatch,
    Failed(Error),
}

/// Opens a QUIC connection to the discovered listener.
async fn dial(d: &Discovery) -> std::result::Result<Arc<QConn>, Dial> {
    let fail = |e: Error| Dial::Failed(e);
    let addr: SocketAddr = tokio::net::lookup_host((d.host.as_str(), d.port as u16))
        .await
        .map_err(|e| fail(unreachable(&e.to_string())))?
        .next()
        .ok_or_else(|| fail(unreachable(&format!("{} has no address", d.host))))?;
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let endpoint = quinn::Endpoint::client(bind).map_err(|e| fail(unreachable(&e.to_string())))?;
    let pin = Arc::new(Pin::new(d.pins()));
    let mismatch = pin.mismatch.clone();
    let cfg = quic_config(pin).map_err(|e| fail(Error::Tls(e)))?;
    let connecting = endpoint
        .connect_with(cfg, addr, &d.host)
        .map_err(|e| fail(Error::Config(format!("cannot connect to {}: {e}", d.host))))?;
    let conn = match tokio::time::timeout(HANDSHAKE_WAIT, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            if mismatch.load(std::sync::atomic::Ordering::Acquire) {
                return Err(Dial::Mismatch);
            }
            return Err(fail(dial_error(e)));
        }
        Err(_) => return Err(fail(unreachable("the handshake timed out"))),
    };
    let qc = Arc::new(QConn {
        conn,
        _endpoint: endpoint,
        state: Mutex::new(ConnState::default()),
        changed: Notify::new(),
    });
    tokio::spawn(accept_opens(qc.clone()));
    Ok(qc)
}

fn unreachable(why: &str) -> Error {
    Error::Link(format!(
        "cannot reach the hub over QUIC (UDP may be blocked on the way; pf-client over WebSocket works where QUIC does not): {why}"
    ))
}

/// Words a failed handshake.
fn dial_error(e: ConnectionError) -> Error {
    match e {
        ConnectionError::VersionMismatch => {
            Error::Protocol("the hub's QUIC listener does not speak QUIC version 1".into())
        }
        ConnectionError::ConnectionClosed(c) if c.error_code == TransportErrorCode::CONNECTION_REFUSED => {
            Error::Status { code: 429, message: "the hub refused the QUIC connection; trying again later".into() }
        }
        e => unreachable(&e.to_string()),
    }
}

// ---------- the connection, and the streams the hub opens ----------

/// One QUIC connection to the hub, and its registrations.
struct QConn {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    state: Mutex<ConnState>,
    /// Notified when registrations or outstanding serves change.
    changed: Notify,
}

#[derive(Default)]
struct ConnState {
    regs: HashMap<String, mpsc::Sender<QOpen>>,
    /// Serve requests not yet answered.
    serves: usize,
}

impl QConn {
    fn change(&self, f: impl FnOnce(&mut ConnState)) {
        f(&mut self.state.lock().unwrap());
        self.changed.notify_waiters();
    }

    /// The registration `reg` names. An open can arrive before the answer
    /// to its serve, streams not being ordered with one another, so it
    /// waits while serves are outstanding, up to REQUEST_WAIT (§13.4).
    async fn find(&self, reg: &str) -> Option<mpsc::Sender<QOpen>> {
        let deadline = Instant::now() + REQUEST_WAIT;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let st = self.state.lock().unwrap();
                if let Some(tx) = st.regs.get(reg) {
                    return Some(tx.clone());
                }
                if st.serves == 0 {
                    return None;
                }
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => return None,
            }
        }
    }
}

/// Counts a serve request as outstanding while it lives.
struct Serving(Arc<QConn>);

impl Serving {
    fn new(qc: Arc<QConn>) -> Serving {
        qc.change(|st| st.serves += 1);
        Serving(qc)
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.change(|st| st.serves -= 1);
    }
}

/// Reads each stream the hub opens: an open for one of this connection's
/// registrations.
async fn accept_opens(qc: Arc<QConn>) {
    loop {
        let Ok((send, recv)) = qc.conn.accept_bi().await else { return };
        tokio::spawn(take_open(qc.clone(), QStream::new(send, recv)));
    }
}

async fn take_open(qc: Arc<QConn>, mut s: QStream) {
    let o = match tokio::time::timeout(REQUEST_WAIT, wire::read_message::<_, wire::Open>(&mut s)).await {
        Ok(Ok(o)) if !o.open.is_empty() => o,
        Ok(_) => return s.reset(code::PROTOCOL),
        Err(_) => return s.reset(code::REQUEST_TIMEOUT),
    };
    let open = QOpen { s, id: o.open };
    let refused = match qc.find(&o.reg).await {
        Some(tx) => match tx.try_send(open) {
            Ok(()) => return,
            Err(e) => e.into_inner(),
        },
        None => open,
    };
    refused.answer_and_finish(410, "no such registration").await;
}

// ---------- registrations ----------

/// One registration over QUIC, until its serve stream ends.
struct QReg {
    opens: mpsc::Receiver<QOpen>,
    ended: watch::Receiver<Option<String>>,
    close: Option<oneshot::Sender<()>>,
}

impl transport::Registration for QReg {
    fn next(&mut self) -> BoxFuture<'_, Result<Box<dyn transport::Open>>> {
        Box::pin(async move {
            let QReg { opens, ended, .. } = self;
            tokio::select! {
                biased;
                Some(o) = opens.recv() => return Ok(Box::new(o) as Box<dyn transport::Open>),
                _ = ended.wait_for(|e| e.is_some()) => {}
            }
            let why = ended.borrow().clone().unwrap_or_else(|| "the registration ended".into());
            Err(Error::Link(why))
        })
    }

    fn close(&mut self) {
        if let Some(c) = self.close.take() {
            let _ = c.send(());
        }
    }
}

impl Drop for QReg {
    fn drop(&mut self) {
        transport::Registration::close(self);
    }
}

/// Reads the serve stream until it ends: the hub's end message, its FIN, a
/// lost connection, or this side unregistering (FIN).
async fn watch_serve(
    qc: Arc<QConn>,
    reg: String,
    mut s: QStream,
    ended: watch::Sender<Option<String>>,
    mut close: oneshot::Receiver<()>,
) {
    let why = loop {
        let m = tokio::select! {
            _ = &mut close => {
                s.finish(); // unregister; the hub answers with FIN
                break "unregistered".to_string();
            }
            m = wire::read_raw(&mut s) => m,
        };
        match m {
            Ok(body) => {
                let Ok(e) = serde_json::from_slice::<End>(&body) else { continue };
                if e.end.is_empty() {
                    continue; // other messages are ignored
                }
                s.finish(); // the hub's FIN follows; answer with ours
                break end_reason(&e);
            }
            Err(MsgError::Fin) => {
                s.finish();
                break "the server ended the registration".to_string();
            }
            Err(MsgError::Malformed) => {
                s.reset(code::PROTOCOL);
                break "the server broke the protocol on the serve stream".to_string();
            }
            Err(MsgError::Io(e)) => break format!("the link to the server was lost ({e})"),
        }
    };
    qc.change(|st| {
        st.regs.remove(&reg);
    });
    let _ = ended.send(Some(why));
}

/// The hub's end of a registration, as the user should read it. Nothing is
/// decided from it: every end is followed by registering again.
fn end_reason(e: &End) -> String {
    let mut why = wire::clean_text(&e.error, 200);
    if why.is_empty() {
        why = "the server ended the registration".into();
    }
    if e.end == wire::END_TAKEOVER {
        why.push_str(" (another serving side registered the same word)");
    }
    why
}

// ---------- opens ----------

/// The hub asking for one connection, on a stream it opened.
struct QOpen {
    s: QStream,
    id: String,
}

impl QOpen {
    async fn answer(&mut self, status: u16, error: &str) -> std::io::Result<()> {
        let a = OpenAnswer { status, error };
        tokio::time::timeout(WRITE_WAIT, wire::write_message(&mut self.s, &a))
            .await
            .unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out")))
    }

    /// Refuses: the answer, then FIN (§13.5).
    async fn answer_and_finish(mut self, status: u16, error: &str) {
        if self.answer(status, error).await.is_ok() {
            self.s.finish();
        }
    }
}

impl transport::Open for QOpen {
    fn id(&self) -> &str {
        &self.id
    }

    fn accept(mut self: Box<Self>) -> BoxFuture<'static, Result<Stream>> {
        Box::pin(async move {
            if let Err(e) = self.answer(200, "").await {
                self.s.reset(code::BROKEN);
                return Err(Error::Link(format!("cannot answer the server ({e})")));
            }
            let QOpen { s, .. } = *self;
            Ok(Box::new(s) as Stream)
        })
    }

    fn refuse(self: Box<Self>, reason: &str) -> BoxFuture<'static, ()> {
        let mut reason = wire::clean_text(reason, 128);
        if reason.is_empty() {
            reason = "the serving side refused the connection".into();
        }
        Box::pin(async move { self.answer_and_finish(502, &reason).await })
    }
}

// ---------- the requests ----------

impl transport::Transport for Quic {
    fn register<'a>(&'a self, p: Params, target: &'a str) -> BoxFuture<'a, Result<Box<dyn transport::Registration>>> {
        Box::pin(async move {
            let req = Request {
                op: "serve",
                serve_token: p.serve_token().map(str::to_string),
                name: Some(p.name().to_string()),
                target: Some(target.to_string()),
                client_token_sha256: p.client_token().map(|t| hex::encode(Sha256::digest(t.as_bytes()))),
                ..Request::default()
            };
            let qc = self.get(&p, Op::Serve).await?;
            let serving = Serving::new(qc); // an open may arrive before the answer (§13.4)
            let (qc, s, a) = self.request(&p, Op::Serve, req).await?;
            let (tx, rx) = mpsc::channel(OPEN_QUEUE);
            qc.change(|st| {
                st.regs.insert(a.reg.clone(), tx);
            });
            drop(serving);
            let (ended_tx, ended_rx) = watch::channel(None);
            let (close_tx, close_rx) = oneshot::channel();
            tokio::spawn(watch_serve(qc, a.reg, s, ended_tx, close_rx));
            Ok(Box::new(QReg { opens: rx, ended: ended_rx, close: Some(close_tx) }) as Box<dyn transport::Registration>)
        })
    }

    fn connect(&self, p: Params) -> BoxFuture<'_, Result<(Stream, String)>> {
        Box::pin(async move {
            let req = Request { op: "connect", client_token: p.client_token().map(str::to_string), ..Request::default() };
            let (_, s, a) = self.request(&p, Op::Connect, req).await?;
            Ok((Box::new(s) as Stream, a.conn))
        })
    }

    fn check(&self, p: Params) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let req = Request { op: "check", client_token: p.client_token().map(str::to_string), ..Request::default() };
            let (_, mut s, _) = self.request(&p, Op::Connect, req).await?;
            s.finish(); // the hub sends FIN after its answer
            Ok(())
        })
    }

    fn close(&self) {
        Quic::close(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A QUIC listener with a self-signed certificate, as the hub's, and
    /// its fingerprint.
    fn listener() -> (quinn::Endpoint, String) {
        let c = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = c.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(c.key_pair.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        tls.alpn_protocols = vec![wire::ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let accepting = ep.clone();
        tokio::spawn(async move {
            while let Some(inc) = accepting.accept().await {
                tokio::spawn(async move {
                    if let Ok(c) = inc.await {
                        let _ = c.closed().await;
                    }
                });
            }
        });
        (ep, crate::pin::fingerprint(der.as_ref()))
    }

    fn discovery(ep: &quinn::Endpoint, fp: &str) -> Discovery {
        let port = ep.local_addr().unwrap().port();
        Discovery { host: "127.0.0.1".into(), port: port.into(), fingerprints: vec![fp.into()] }
    }

    #[tokio::test]
    async fn the_handshake_pins_the_certificate() {
        let (ep, fp) = listener();
        let qc = match dial(&discovery(&ep, &fp)).await {
            Ok(qc) => qc,
            Err(Dial::Mismatch) => panic!("the pinned certificate was refused"),
            Err(Dial::Failed(e)) => panic!("{e}"),
        };
        assert_eq!(qc.conn.handshake_data().unwrap().downcast::<quinn::crypto::rustls::HandshakeData>().unwrap().protocol.unwrap(), wire::ALPN);
        let other = "00".repeat(32);
        assert!(matches!(dial(&discovery(&ep, &other)).await, Err(Dial::Mismatch)), "another certificate is refused");
    }

    #[test]
    fn end_reasons() {
        let e = End { end: "takeover".into(), error: "another registration of this word took over\x07".into() };
        assert_eq!(
            end_reason(&e),
            "another registration of this word took over (another serving side registered the same word)"
        );
        assert_eq!(end_reason(&End { end: "off".into(), error: String::new() }), "the server ended the registration");
    }
}
