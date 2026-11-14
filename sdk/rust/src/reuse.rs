//! Reusing the serving side's accept legs: tunnel protocol 2, PROTOCOL.md
//! §12.
//!
//! A registration with a protocol 2 hub brings a session secret. Each
//! `accept` sends it back, and the hub may offer reuse. When a connection on
//! an offered leg finishes cleanly, the hub says `idle`; this side answers
//! `idle` to keep the leg (see `conn.rs`), which then waits here for the
//! hub's `bind <id>`: the next connection, answered at once with
//! `bound <id>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{ReadHalf, WriteHalf};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::client::{Client, H_KEEP_ALIVE, H_PROTO, H_SESSION};
use crate::conn::PING_EVERY;
use crate::http::{Head, Stream};
use crate::listener::{self, Handler};
use crate::ws::{self, FrameReader, OP_CLOSE, OP_PING, OP_PONG, OP_TEXT};

pub(crate) const MSG_IDLE: &[u8] = b"idle";
pub(crate) const MSG_BIND: &str = "bind ";
pub(crate) const MSG_BOUND: &str = "bound ";
/// How an attempt ends whose leg died before the hub heard `bound`: the
/// hub asks again with an open message (§12.7).
pub const REASON_LEG_LOST: &str = "the leg was lost before the server took the connection";
/// How long a registration remembers the ids it answered `bound` to and
/// the ids that came with an open message: well past the hub's 10 seconds
/// to answer a connection.
pub(crate) const RECALL: Duration = Duration::from_secs(30);
/// Bounds one frame write on an idle leg.
const LEG_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(3);

/// A WebSocket to `/accept` between connections: its reader (with what it
/// has buffered) and its writer.
pub(crate) struct Leg {
    pub(crate) frames: FrameReader<ReadHalf<Stream>>,
    pub(crate) w: WriteHalf<Stream>,
}

/// Whether the hub's answer to an accept offered reuse: a protocol 2 answer
/// with a keep-alive of 1 to 3600 seconds, digits only (§12.3).
pub(crate) fn offered(head: &Head) -> bool {
    if crate::proto::server_proto(head.get(H_PROTO)) < 2 {
        return false;
    }
    match head.get(H_KEEP_ALIVE) {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            v.parse::<u32>().is_ok_and(|n| (1..=3600).contains(&n))
        }
        _ => false,
    }
}

/// The session secret in a serve 101, when the hub negotiated protocol 2 and
/// this client takes part in reuse.
pub(crate) fn session_of(c: &Client, head: &Head) -> Option<String> {
    if !c.inner.reuse || crate::proto::server_proto(head.get(H_PROTO)) < 2 {
        return None;
    }
    head.get(H_SESSION)
        .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
}

/// One control channel's life: its session secret, and the idle legs that
/// belong to it. Its token is cancelled when the control channel ends, which
/// closes them.
pub(crate) struct Registration {
    pub(crate) c: Client,
    pub(crate) sh: Arc<listener::Shared>,
    pub(crate) handler: Handler,
    pub(crate) session: Option<String>,
    pub(crate) cancel: CancellationToken,
    idle: Mutex<usize>,
    ids: Mutex<Ids>,
}

/// The ids a registration answered `bound` to (and whether that attempt was
/// abandoned), and those that came with an open message, with when.
#[derive(Default)]
struct Ids {
    bound: HashMap<String, (Instant, bool)>,
    opened: HashMap<String, Instant>,
}

impl Ids {
    fn prune(&mut self) {
        let now = Instant::now();
        self.bound.retain(|_, (at, _)| now.duration_since(*at) <= RECALL);
        self.opened.retain(|_, at| now.duration_since(*at) <= RECALL);
    }
}

impl Registration {
    pub(crate) fn new(c: Client, sh: Arc<listener::Shared>, handler: Handler, session: Option<String>) -> Arc<Self> {
        let cancel = sh.cancel.child_token();
        Arc::new(Registration { c, sh, handler, session, cancel, idle: Mutex::new(0), ids: Mutex::default() })
    }

    /// Records a bind of `id`. It refuses one for an id that already came
    /// with an open message: a bind that arrives after the hub fell back.
    pub(crate) fn take_bind(&self, id: &str) -> bool {
        let mut ids = self.ids.lock().unwrap();
        ids.prune();
        if ids.opened.contains_key(id) {
            return false;
        }
        ids.bound.insert(id.to_string(), (Instant::now(), false));
        true
    }

    /// Records an open message for `id`, and reports whether it is for an
    /// id bound here: a new attempt, the old one being abandoned (§12.7).
    pub(crate) fn took_open(&self, id: &str) -> bool {
        let mut ids = self.ids.lock().unwrap();
        ids.prune();
        ids.opened.insert(id.to_string(), Instant::now());
        match ids.bound.get_mut(id) {
            Some((_, abandoned)) => {
                *abandoned = true;
                true
            }
            None => false,
        }
    }

    /// Whether the attempt at `id` on a reused leg was given up because the
    /// hub asked for it again.
    pub(crate) fn abandoned(&self, id: &str) -> bool {
        self.ids.lock().unwrap().bound.get(id).is_some_and(|(_, a)| *a)
    }

    pub(crate) fn verdict_wait(&self) -> Duration {
        self.c.inner.timing.verdict_wait
    }

    /// Reserves room for one more idle leg.
    pub(crate) fn keep(&self) -> bool {
        let mut n = self.idle.lock().unwrap();
        if self.cancel.is_cancelled() || *n >= self.c.inner.max_idle_legs {
            return false;
        }
        *n += 1;
        true
    }

    pub(crate) fn release(&self) {
        let mut n = self.idle.lock().unwrap();
        *n = n.saturating_sub(1);
    }

    /// Takes over a leg this side answered `idle` on: it waits there for the
    /// hub's `bind`, keeping the leg alive, until the leg or the
    /// registration ends.
    pub(crate) fn adopt(self: &Arc<Self>, leg: Leg) {
        tokio::spawn(idle_leg(self.clone(), leg));
    }
}

async fn write(w: &mut WriteHalf<Stream>, op: u8, payload: &[u8]) -> bool {
    matches!(tokio::time::timeout(LEG_WRITE_TIMEOUT, ws::write_frame(w, op, payload)).await, Ok(Ok(())))
}

/// A place among the registration's idle legs, given back when dropped: on
/// every way an idle leg ends, bound or not, even if its task is aborted.
struct Place(Arc<Registration>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// How an idle leg's wait ended.
enum Exit {
    /// The hub's "bind <id>".
    Bind(String),
    /// The hub's close, to be answered.
    Closed(Vec<u8>),
    /// Dead, a violation, or the registration ended.
    Gone,
}

async fn idle_leg(reg: Arc<Registration>, leg: Leg) {
    let place = Place(reg.clone());
    let Leg { mut frames, mut w } = leg;
    let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
    let exit = loop {
        tokio::select! {
            _ = reg.cancel.cancelled() => break Exit::Gone,
            _ = ping.tick() => {
                if !write(&mut w, OP_PING, &[]).await {
                    break Exit::Gone;
                }
            }
            f = frames.next() => match f {
                Err(_) => break Exit::Gone, // closed, or silent for LINK_SILENCE
                Ok(f) if f.op == OP_PING || f.op == OP_PONG => {}
                Ok(f) if f.op == OP_TEXT && f.fin => {
                    // Only "bind <id>" may come now. A known frame in the
                    // wrong state is a violation, which closes the leg;
                    // unknown text is ignored, as on any stream (§12.4).
                    let text = String::from_utf8_lossy(&f.payload);
                    match text.strip_prefix(MSG_BIND) {
                        Some(id) if !id.is_empty() => break Exit::Bind(id.to_string()),
                        _ if known_leg_frame(&text) => break Exit::Gone,
                        _ => {}
                    }
                }
                Ok(f) if f.op == OP_CLOSE => break Exit::Closed(f.payload),
                Ok(_) => break Exit::Gone, // data on an idle leg: a violation
            },
        }
    };
    drop(place); // the leg is no longer idle, however it ended
    let id = match exit {
        Exit::Bind(id) => id,
        Exit::Closed(payload) => {
            let _ = write(&mut w, OP_CLOSE, &payload[..payload.len().min(2)]).await;
            return;
        }
        Exit::Gone => return,
    };
    if reg.cancel.is_cancelled() {
        return; // the registration ended: its legs go with it
    }
    if !reg.take_bind(&id) {
        return; // already asked for with an open message: the hub gave this leg up
    }
    // "bound" first, before anything else, such as dialing a target.
    if !write(&mut w, OP_TEXT, format!("{MSG_BOUND}{id}").as_bytes()).await {
        return;
    }
    listener::open(reg.c.clone(), reg.clone(), id, Some(Leg { frames, w })).await;
}

/// Whether `msg` is one of the text frames of streams and reused legs
/// (§8.1, §12): such a frame where it does not belong is a violation, while
/// any other text is ignored.
pub(crate) fn known_leg_frame(msg: &str) -> bool {
    let bind = MSG_BIND.trim_end();
    let bound = MSG_BOUND.trim_end();
    msg == "eof"
        || msg.as_bytes() == MSG_IDLE
        || msg == bind
        || msg == bound
        || msg.starts_with("err:")
        || msg.starts_with(MSG_BIND)
        || msg.starts_with(MSG_BOUND)
}

/// Refuses the connection on a leg that answered `bound`: `err:<reason>`
/// and a close (§12.7).
pub(crate) async fn fail_leg(leg: Leg, reason: &str) {
    let Leg { frames, mut w } = leg;
    let msg = format!("err:{reason}");
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, ws::write_frame(&mut w, OP_TEXT, msg.as_bytes())).await;
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, ws::write_frame(&mut w, OP_CLOSE, &[0x03, 0xE8])).await;
    drop(frames);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::parse_head;

    #[test]
    fn known_frames() {
        for known in ["eof", "idle", "bind", "bind 1", "bound", "bound 1", "err:", "err:why"] {
            assert!(known_leg_frame(known), "{known}");
        }
        for unknown in ["something from a later protocol", "binder", "idle2", "Eof", ""] {
            assert!(!known_leg_frame(unknown), "{unknown}");
        }
    }

    #[test]
    fn offers() {
        let head = |s: &str| parse_head(format!("HTTP/1.1 101 X\r\n{s}\r\n\r\n").as_bytes()).unwrap();
        assert!(offered(&head("X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: 60")));
        assert!(offered(&head("X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: 3600")));
        for bad in [
            "X-Pf-Tunnel-Proto: 1\r\nX-Pf-Tunnel-Keep-Alive: 60",
            "X-Pf-Tunnel-Keep-Alive: 60",
            "X-Pf-Tunnel-Proto: 2",
            "X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: 0",
            "X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: 3601",
            "X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: +60",
            "X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: 6 0",
            "X-Pf-Tunnel-Proto: 2\r\nX-Pf-Tunnel-Keep-Alive: 99999999999999999999",
        ] {
            assert!(!offered(&head(bad)), "{bad}");
        }
    }
}
