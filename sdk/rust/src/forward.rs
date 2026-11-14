//! The forwarders: a tunnel served to a TCP target, and a local TCP
//! listener connected through the tunnel. Both carry each connection with
//! [`bridge`], which passes half-closes on and tells the far end why when
//! this side is where it broke.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::client::Client;
use crate::conn::{Conn, Side, LINK_SILENCE};
use crate::error::{Error, Result};
use crate::events::ConnId;
use crate::listener::{refuse, serve_loop, short, Handler, Shared};
use crate::reuse::{fail_leg, Leg, Registration, REASON_LEG_LOST};
use crate::ws::CHUNK;

/// How long the forwarder gives the target to answer.
pub const TARGET_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// The reason the far end hears when the target cannot be reached.
pub const TARGET_UNREACHABLE: &str = "the serving side could not reach its target";

impl Client {
    /// Serves the tunnel to the TCP `target` (`host:port`) for as long as
    /// the future runs: each connection the hub offers is carried to a new
    /// TCP connection to the target.
    ///
    /// The target is dialed before the hub is answered: when it cannot be
    /// reached, the connection is refused through `accept` with
    /// [`TARGET_UNREACHABLE`], so the far end hears it on its first read,
    /// and [`Events::on_refuse`](crate::Events::on_refuse) is called.
    ///
    /// It registers and retries as [`Client::listen`] does, and returns
    /// only on a refusal that waiting cannot cure. Drop the future to stop
    /// serving; the connections it carries are then failed with a reason.
    pub async fn serve_tcp(&self, target: impl Into<String>) -> Result<()> {
        let target: String = target.into();
        let sh = Shared::new();
        let _stop = sh.cancel.clone().drop_guard();
        serve_loop(self.clone(), sh, Handler::Forward(Arc::from(target.as_str())), target, None).await
    }

    /// Forwards every connection accepted on `listener` through the tunnel,
    /// for as long as the future runs. A connection that cannot be opened
    /// through the tunnel is closed at once. Returns only when accepting
    /// fails. Drop the future to stop; the connections it carries are then
    /// failed with a reason.
    pub async fn connect_tcp(&self, listener: TcpListener) -> Result<()> {
        let cancel = CancellationToken::new();
        let _stop = cancel.clone().drop_guard();
        loop {
            let (tcp, from) = listener.accept().await?;
            let (c, cancel) = (self.clone(), cancel.clone());
            tokio::spawn(async move {
                match c.dial().await {
                    Ok(conn) => {
                        c.log(&format!("connection {} open: {from} -> tunnel {}", conn.id().short(), c.word_label()));
                        bridge(&c, conn, tcp, &CONNECT, &cancel).await;
                    }
                    Err(e) => c.log(&format!("connection from {from} refused: {e}")), // dropping tcp closes it
                }
            });
        }
    }
}

/// Carries connection `id` of a forwarding tunnel to `target`. `leg` is
/// its stream when it arrived on a reused leg, which has already answered
/// `bound`; `None` when this side brings a leg to `accept`.
pub(crate) async fn serve_one(c: &Client, reg: &Arc<Registration>, id: &str, target: &str, mut leg: Option<Leg>) {
    let dialed = tokio::time::timeout(TARGET_DIAL_TIMEOUT, TcpStream::connect(target)).await;
    let tcp = match dialed {
        Ok(Ok(tcp)) => tcp,
        failed => {
            let why = match failed {
                Ok(Err(e)) => e.to_string(),
                _ => "it did not answer".to_string(),
            };
            c.log(&format!("connection {} failed: cannot reach the target {target}: {why}", short(id)));
            return match leg {
                Some(leg) => {
                    // After "bound", a refusal is an err: (§12.7).
                    c.events().refused(&ConnId::new(id), TARGET_UNREACHABLE);
                    fail_leg(leg, TARGET_UNREACHABLE).await
                }
                None => refuse(c, id, TARGET_UNREACHABLE).await,
            };
        }
    };
    if let Some(leg) = leg.take_if(|_| reg.abandoned(id)) {
        // Asked for again while this side was dialing: the new attempt
        // carries it, and this one never opened.
        drop(tcp);
        return fail_leg(leg, REASON_LEG_LOST).await;
    }
    let bound = leg.is_some();
    let conn = match leg {
        Some(leg) => Conn::on_leg(leg, id, Side::Serve, c.inner.registry.clone(), Some(reg.clone())),
        None => match c.accept(id, reg.session.as_deref()).await {
            Ok((up, offered)) => Conn::start(up, id, Side::Serve, c.inner.registry.clone(), offered.then(|| reg.clone())),
            Err(e) => {
                c.log(&format!("connection {} failed: cannot bring it to the server: {e}", short(id)));
                return;
            }
        },
    };
    if bound && reg.abandoned(id) {
        c.inner.registry.abandon(&ConnId::new(id)); // asked for again just as it opened
    }
    c.log(&format!("connection {} open: tunnel -> {target}", short(id)));
    bridge(c, conn, tcp, &SERVE, &reg.sh.cancel).await;
}

/// The ends of the chain as one side sees them, so that a reason can say
/// which hop broke:
///
/// `application -- connecting side == hub == serving side -- target`
pub(crate) struct Party {
    me: &'static str,
    local: &'static str,
    far: &'static str,
}

pub(crate) const SERVE: Party = Party { me: "pfrelay serve", local: "the target", far: "the application" };
pub(crate) const CONNECT: Party = Party { me: "pfrelay connect", local: "the application", far: "the target" };

/// Which hop broke one direction of a connection.
enum Broke {
    LocalRead(io::Error),
    LocalWrite(io::Error),
    TunnelRead(io::Error),
    TunnelWrite(io::Error),
    /// The far end, having half-closed, went away while this end still sent.
    Gone,
    /// This program stops forwarding.
    Stopping,
}

/// How one direction ended: `Ok` when its source finished cleanly.
type DirEnd = std::result::Result<(), Broke>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    /// local -> tunnel
    Out,
    /// tunnel -> local
    In,
}

impl Party {
    fn link_reason(&self, e: &io::Error) -> String {
        match Error::from_io(e) {
            Some(Error::Remote(r)) => r.reason.clone(),
            Some(Error::Dropped { reason }) => reason.clone(),
            _ if e.kind() == io::ErrorKind::TimedOut => format!(
                "the link between {} and the server was silent for {}s",
                self.me,
                LINK_SILENCE.as_secs()
            ),
            _ => format!("the link between {} and the server was lost ({e})", self.me),
        }
    }

    fn local_reason(&self, e: &io::Error) -> String {
        match e.kind() {
            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => {
                format!("{} reset its connection to {}", self.local, self.me)
            }
            _ => format!("the connection between {} and {} failed ({e})", self.me, self.local),
        }
    }

    /// Words a broken direction: the reason, whether the cause is on this
    /// side of the tunnel (which the far end cannot see for itself), and
    /// the error the connection ends with.
    fn describe(&self, b: Broke, conn: &Conn) -> (String, bool, Error) {
        match b {
            Broke::LocalRead(e) | Broke::LocalWrite(e) => (self.local_reason(&e), true, Error::Io(e)),
            Broke::TunnelWrite(e) => (self.link_reason(&e), false, Error::Io(e)),
            Broke::TunnelRead(e) => {
                // A silent link may still carry what this end sends, so say so.
                let silent = e.kind() == io::ErrorKind::TimedOut;
                (self.link_reason(&e), silent, Error::Io(e))
            }
            Broke::Gone => match conn.err() {
                Some(Error::Remote(r)) => (r.reason.clone(), false, Error::Remote(r)),
                _ => {
                    let why = "the server closed the connection";
                    (why.to_string(), false, Error::Link(why.to_string()))
                }
            },
            Broke::Stopping => {
                let why = format!("{} is stopping", self.me);
                (why.clone(), true, Error::Link(why))
            }
        }
    }
}

async fn local_to_tunnel<R: AsyncRead + Unpin>(local: &mut R, conn: &Conn) -> DirEnd {
    let mut buf = vec![0u8; CHUNK];
    let mut w = conn;
    loop {
        let n = local.read(&mut buf).await.map_err(Broke::LocalRead)?;
        if n == 0 {
            return w.shutdown().await.map_err(Broke::TunnelWrite);
        }
        w.write_all(&buf[..n]).await.map_err(Broke::TunnelWrite)?;
    }
}

async fn tunnel_to_local<W: AsyncWrite + Unpin>(conn: &Conn, local: &mut W) -> DirEnd {
    let mut buf = vec![0u8; CHUNK];
    let mut r = conn;
    loop {
        let n = r.read(&mut buf).await.map_err(Broke::TunnelRead)?;
        if n == 0 {
            let _ = local.shutdown().await;
            return Ok(());
        }
        local.write_all(&buf[..n]).await.map_err(Broke::LocalWrite)?;
    }
}

/// Copies both ways until both directions finish cleanly or either fails,
/// then ends the connection. When this side is where it broke, the far end
/// is told why.
pub(crate) async fn bridge(c: &Client, conn: Conn, tcp: TcpStream, p: &Party, cancel: &CancellationToken) {
    let _ = tcp.set_nodelay(true);
    let (mut tr, mut tw) = tcp.into_split();
    let (reason, outcome) = {
        let out = local_to_tunnel(&mut tr, &conn);
        let inn = tunnel_to_local(&conn, &mut tw);
        tokio::pin!(out, inn);
        let (dir, first) = tokio::select! {
            r = &mut out => (Dir::Out, r),
            r = &mut inn => (Dir::In, r),
            _ = cancel.cancelled() => (Dir::Out, Err(Broke::Stopping)),
        };
        let result = match first {
            Err(b) => Err(b),
            Ok(()) => {
                let second = async {
                    if dir == Dir::Out {
                        (&mut inn).await
                    } else {
                        // The far end has half-closed: watch for it going
                        // away while this end still has the floor.
                        tokio::select! {
                            r = &mut out => r,
                            _ = conn.finished() => {
                                // After a clean finish the far end's close and
                                // our own last result arrive together.
                                tokio::time::timeout(Duration::from_millis(200), &mut out)
                                    .await
                                    .unwrap_or(Err(Broke::Gone))
                            }
                        }
                    }
                };
                tokio::select! {
                    r = second => r,
                    _ = cancel.cancelled() => Err(Broke::Stopping),
                }
            }
        };
        match result {
            Ok(()) => {
                // Both finished; the reason is who closed first.
                let who = if dir == Dir::Out { p.local } else { p.far };
                (format!("{who} closed the connection"), None)
            }
            Err(b) => {
                let (why, mine, err) = p.describe(b, &conn);
                (why, Some((mine, err)))
            }
        }
    };
    let id = conn.id().short().to_string();
    match outcome {
        None => {
            let _ = conn.close().await;
        }
        // This side broke it: tell the far end why.
        Some((true, err)) => conn.end_with(Some(&reason), err).await,
        // The far end, or the link, broke it, and knows: just cut.
        Some((false, err)) => conn.end_with(None, err).await,
    }
    let info = conn.info();
    c.log(&format!(
        "connection {id} closed: sent {} B, received {} B; {reason}",
        info.sent, info.received
    ));
}
