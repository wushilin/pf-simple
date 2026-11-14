//! The serving side's half of reusing accept legs (protocol 2,
//! PROTOCOL.md §12), against a scripted hub whose every frame the test
//! writes. These mirror pfrelay/reuse_test.go.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::testhub::{recv, scripted, send, upgrade, Script, SERVE_TOKEN};
use crate::ws::{OP_BINARY, OP_CLOSE, OP_TEXT};
use crate::{Client, ClientBuilder, Error, Events, Timing, REASON_LEG_LOST, TARGET_UNREACHABLE};

const SESSION: &str = "3f9a0c7e5b2d4e8f1a6c9b0d7e2f4a1c";

fn id(n: u32) -> String {
    format!("{n:016x}")
}

/// What the event handlers heard, one line per event.
#[derive(Clone, Default)]
struct Heard(Arc<Mutex<Vec<String>>>);

impl Heard {
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn events(&self) -> Events {
        let (a, b, c) = (self.clone(), self.clone(), self.clone());
        Events::new()
            .on_open(move |ci| a.0.lock().unwrap().push(format!("open {}", ci.id)))
            .on_close(move |ci, err| {
                let how = match err {
                    None => "ok".to_string(),
                    Some(Error::Dropped { reason }) => format!("dropped: {reason}"),
                    Some(Error::Remote(r)) => format!("remote: {}", r.reason),
                    Some(e) => format!("failed: {e}"),
                };
                b.0.lock().unwrap().push(format!("close {} {} {} {how}", ci.id, ci.sent, ci.received))
            })
            .on_refuse(move |id, reason| c.0.lock().unwrap().push(format!("refuse {id} {reason}")))
    }
    async fn until(&self, n: usize) -> Vec<String> {
        for _ in 0..500 {
            if self.all().len() >= n {
                return self.all();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{} events, want {n}: {:?}", self.all().len(), self.all());
    }
}

fn configure(heard: &Heard, more: impl FnOnce(ClientBuilder) -> ClientBuilder) -> impl FnOnce(ClientBuilder) -> ClientBuilder {
    let events = heard.events();
    move |b| more(b.serve_token(SERVE_TOKEN).events(events))
}

/// Registers as a protocol 2 hub does, with a session.
async fn register(sc: &mut Script) -> DuplexStream {
    let (req, mut s) = sc.next("serve").await;
    assert_eq!(req.get("X-PF-Tunnel-Proto"), Some("0-2"));
    upgrade(&mut s, &req, &[("X-Pf-Tunnel-Proto", "2"), ("X-PF-Tunnel-Session", SESSION)]).await;
    s
}

async fn offer_open(ctl: &mut DuplexStream, conn: &str) {
    send(ctl, OP_TEXT, format!(r#"{{"open":"{conn}"}}"#).as_bytes()).await;
}

/// Takes the next accept, which must bring the session, and answers it
/// with the offer of reuse or without. Returns its connection id.
async fn take_accept(sc: &mut Script, offer: bool) -> (String, DuplexStream) {
    let (req, mut s) = sc.next("accept").await;
    assert_eq!(req.get("X-PF-Tunnel-Session"), Some(SESSION), "the accept brings the session");
    let conn = req.get("X-PF-Tunnel-Conn").unwrap().to_string();
    let mut h = vec![("X-Pf-Tunnel-Proto", "2")];
    if offer {
        h.push(("X-PF-Tunnel-Keep-Alive", "60"));
    }
    upgrade(&mut s, &req, &h).await;
    (conn, s)
}

async fn expect(leg: &mut DuplexStream, op: u8, payload: &[u8]) {
    let got = tokio::time::timeout(Duration::from_secs(10), recv(leg)).await.expect("a frame in time");
    assert_eq!(got, Some((op, payload.to_vec())), "want {op} {:?}", String::from_utf8_lossy(payload));
}

/// Runs one connection on a leg from the hub's side, against an echo on
/// the client's: data, the hub's half-close, then the echo and the client's
/// half-close.
async fn exchange(leg: &mut DuplexStream, msg: &[u8]) {
    send(leg, OP_BINARY, msg).await;
    send(leg, OP_TEXT, b"eof").await;
    expect(leg, OP_BINARY, msg).await;
    expect(leg, OP_TEXT, b"eof").await;
}

/// The hub's verdict "idle", answered with "idle": the client keeps the leg.
async fn keep(leg: &mut DuplexStream) {
    send(leg, OP_TEXT, b"idle").await;
    expect(leg, OP_TEXT, b"idle").await;
}

async fn bind(leg: &mut DuplexStream, conn: &str) {
    send(leg, OP_TEXT, format!("bind {conn}").as_bytes()).await;
    expect(leg, OP_TEXT, format!("bound {conn}").as_bytes()).await;
}

/// Serves with listen, echoing every connection.
fn listen_echo(c: &Client) -> JoinHandle<()> {
    let c = c.clone();
    tokio::spawn(async move {
        let l = c.listen().await.unwrap();
        while let Ok(mut conn) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                if conn.read_to_end(&mut buf).await.is_ok() && conn.write_all(&buf).await.is_ok() {
                    let _ = conn.close().await;
                }
            });
        }
    })
}

/// An echo target over TCP, and the task that owns its listener.
async fn echo_target() -> (String, JoinHandle<()>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = ln.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                let _ = s.write_all(&buf).await;
            });
        }
    });
    (addr, task)
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Listen,
    Forward,
}

async fn serve(c: &Client, mode: Mode) -> Vec<JoinHandle<()>> {
    match mode {
        Mode::Listen => vec![listen_echo(c)],
        Mode::Forward => {
            let (addr, target) = echo_target().await;
            let c = c.clone();
            vec![target, tokio::spawn(async move { c.serve_tcp(addr).await.unwrap() })]
        }
    }
}

#[tokio::test]
async fn keeps_and_binds_legs() {
    for mode in [Mode::Listen, Mode::Forward] {
        let heard = Heard::default();
        let (c, mut sc) = scripted(configure(&heard, |b| b));
        let tasks = serve(&c, mode).await;
        let mut ctl = register(&mut sc).await;
        offer_open(&mut ctl, &id(1)).await;
        let (conn, mut leg) = take_accept(&mut sc, true).await;
        assert_eq!(conn, id(1));
        exchange(&mut leg, b"one").await;
        keep(&mut leg).await;
        // The hub binds the idle leg: answered at once, and carried as a
        // connection of its own, with no new accept.
        bind(&mut leg, &id(2)).await;
        exchange(&mut leg, b"second").await;
        keep(&mut leg).await;
        bind(&mut leg, &id(3)).await;
        exchange(&mut leg, b"3").await;
        keep(&mut leg).await;
        sc.none_within(Duration::from_millis(200)).await;
        let events = heard.until(6).await;
        assert_eq!(
            events,
            [
                format!("open {}", id(1)),
                format!("close {} 3 3 ok", id(1)),
                format!("open {}", id(2)),
                format!("close {} 6 6 ok", id(2)),
                format!("open {}", id(3)),
                format!("close {} 1 1 ok", id(3)),
            ],
            "{mode:?}"
        );
        assert_eq!(c.stats().opened, 3);
        tasks.iter().for_each(JoinHandle::abort);
        drop(ctl);
    }
}

#[tokio::test]
async fn the_verdict_times_out_or_fails() {
    let heard = Heard::default();
    let wait = Duration::from_millis(300);
    let (c, mut sc) = scripted(configure(&heard, |b| b.timing(Timing { verdict_wait: wait, ..Timing::default() })));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;

    // No verdict in time: the client closes as in protocol 1.
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    exchange(&mut leg, b"one").await;
    let start = Instant::now();
    expect(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    assert!(start.elapsed() >= wait - Duration::from_millis(50), "it waited {:?}", start.elapsed());
    send(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    assert_eq!(heard.until(2).await[1], format!("close {} 3 3 ok", id(1)));

    // err: as the verdict: the connection failed, with that reason.
    offer_open(&mut ctl, &id(2)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    exchange(&mut leg, b"two").await;
    send(&mut leg, OP_TEXT, b"err:the application's side failed").await;
    send(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    expect(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    assert_eq!(heard.until(4).await[3], format!("close {} 3 3 remote: the application's side failed", id(2)));
    tasks.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn without_the_offer_nothing_waits() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, false).await;
    exchange(&mut leg, b"one").await;
    let start = Instant::now();
    expect(&mut leg, OP_CLOSE, &[3, 0xE8]).await; // at once, not after a verdict
    assert!(start.elapsed() < Duration::from_secs(1), "it waited {:?}", start.elapsed());
    send(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    assert_eq!(heard.until(2).await[1], format!("close {} 3 3 ok", id(1)));
    tasks.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn without_a_session_nothing_is_offered() {
    // A protocol 1 registration brings no session, and accepts send none.
    let (c, mut sc) = scripted(|b| b.serve_token(SERVE_TOKEN));
    let tasks = serve(&c, Mode::Listen).await;
    let (req, mut ctl) = sc.next("serve").await;
    upgrade(&mut ctl, &req, &[("X-Pf-Tunnel-Proto", "1"), ("X-PF-Tunnel-Session", SESSION)]).await;
    offer_open(&mut ctl, &id(1)).await;
    let (req, _leg) = sc.next("accept").await;
    assert_eq!(req.get("X-PF-Tunnel-Session"), None);
    tasks.iter().for_each(JoinHandle::abort);

    // Nor with no_reuse, or a client limited to protocol 1.
    for limit in [None, Some(crate::ProtoLimit::UpTo(1))] {
        let (c, mut sc) = scripted(|b| {
            let b = b.serve_token(SERVE_TOKEN);
            match limit {
                Some(l) => b.max_proto(l),
                None => b.no_reuse(),
            }
        });
        let tasks = serve(&c, Mode::Listen).await;
        let mut ctl = register_any(&mut sc).await;
        offer_open(&mut ctl, &id(1)).await;
        let (req, _leg) = sc.next("accept").await;
        assert_eq!(req.get("X-PF-Tunnel-Session"), None, "{limit:?}");
        tasks.iter().for_each(JoinHandle::abort);
    }
}

async fn register_any(sc: &mut Script) -> DuplexStream {
    let (req, mut s) = sc.next("serve").await;
    upgrade(&mut s, &req, &[("X-Pf-Tunnel-Proto", "2"), ("X-PF-Tunnel-Session", SESSION)]).await;
    s
}

#[tokio::test]
async fn the_idle_cap_and_losing_the_registration() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b.max_idle_legs(1)));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    offer_open(&mut ctl, &id(2)).await;
    let (a, mut leg_a) = take_accept(&mut sc, true).await;
    let (b, mut leg_b) = take_accept(&mut sc, true).await;
    assert_ne!(a, b);
    exchange(&mut leg_a, b"a").await;
    exchange(&mut leg_b, b"b").await;
    keep(&mut leg_a).await;
    // Past max_idle_legs, the hub's idle is answered with a close.
    send(&mut leg_b, OP_TEXT, b"idle").await;
    expect(&mut leg_b, OP_CLOSE, &[3, 0xE8]).await;
    let events = heard.until(4).await;
    assert!(events.iter().filter(|e| e.ends_with(" ok")).count() == 2, "{events:?}");

    // The registration ends: its idle leg is closed.
    drop(ctl);
    let end = tokio::time::timeout(Duration::from_secs(5), recv(&mut leg_a)).await.expect("the leg closes");
    assert!(matches!(end, None | Some((OP_CLOSE, _))), "{end:?}");
    tasks.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn a_reopened_id_is_a_new_attempt() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    exchange(&mut leg, b"one").await;
    keep(&mut leg).await;
    bind(&mut leg, &id(2)).await;
    heard.until(3).await; // connection 2 is open here
    // The hub never heard bound, and asks again for the same id.
    offer_open(&mut ctl, &id(2)).await;
    expect(&mut leg, OP_TEXT, format!("err:{REASON_LEG_LOST}").as_bytes()).await;
    let (conn, mut leg2) = take_accept(&mut sc, true).await;
    assert_eq!(conn, id(2));
    exchange(&mut leg2, b"again").await;
    keep(&mut leg2).await;
    let events = heard.until(6).await;
    assert_eq!(
        events,
        [
            format!("open {}", id(1)),
            format!("close {} 3 3 ok", id(1)),
            format!("open {}", id(2)),
            format!("close {} 0 0 dropped: {REASON_LEG_LOST}", id(2)),
            format!("open {}", id(2)),
            format!("close {} 5 5 ok", id(2)),
        ]
    );
    tasks.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn a_forwarder_refuses_after_bound_with_err() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let (addr, target) = echo_target().await;
    let fwd = {
        let c = c.clone();
        tokio::spawn(async move { c.serve_tcp(addr).await.unwrap() })
    };
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    exchange(&mut leg, b"one").await;
    keep(&mut leg).await;
    // The target goes away.
    target.abort();
    let _ = target.await;
    // "bound" comes first, then the refusal as err: and a close.
    bind(&mut leg, &id(2)).await;
    expect(&mut leg, OP_TEXT, format!("err:{TARGET_UNREACHABLE}").as_bytes()).await;
    expect(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    let events = heard.until(3).await;
    assert_eq!(events[2], format!("refuse {} {TARGET_UNREACHABLE}", id(2)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(heard.all().len(), 3, "a refused connection is never opened: {:?}", heard.all());
    fwd.abort();
}

#[tokio::test]
async fn idle_leg_frames() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    exchange(&mut leg, b"one").await;
    keep(&mut leg).await;
    // Unknown text on an idle leg is ignored: a bind still works after it.
    send(&mut leg, OP_TEXT, b"something from a later protocol").await;
    bind(&mut leg, &id(2)).await;
    exchange(&mut leg, b"two").await;
    keep(&mut leg).await;
    // A known frame in the wrong state closes the leg.
    send(&mut leg, OP_TEXT, b"eof").await;
    let end = tokio::time::timeout(Duration::from_secs(5), recv(&mut leg)).await.expect("the leg closes");
    assert!(matches!(end, None | Some((OP_CLOSE, _))), "a known frame in the wrong state was answered with {end:?}");
    tasks.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn an_idle_leg_gives_its_place_back() {
    // With room for one idle leg, a leg the hub lets go must free its
    // place, or the next one would not be kept.
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b.max_idle_legs(1)));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;
    for n in 1..=3 {
        offer_open(&mut ctl, &id(n)).await;
        let (_, mut leg) = take_accept(&mut sc, true).await;
        exchange(&mut leg, b"x").await;
        keep(&mut leg).await; // fails if the client has no place left
        send(&mut leg, OP_CLOSE, &[3, 0xE8]).await; // the hub lets the idle leg go
        let end = tokio::time::timeout(Duration::from_secs(5), recv(&mut leg)).await.expect("the leg closes");
        assert!(matches!(end, None | Some((OP_CLOSE, _))), "leg {n}: {end:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tasks.iter().for_each(JoinHandle::abort);
}

/// Serves with listen, and hands every connection to the test untouched.
fn listen_hold(c: &Client) -> (JoinHandle<()>, tokio::sync::mpsc::UnboundedReceiver<crate::Conn>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let c = c.clone();
    let task = tokio::spawn(async move {
        let l = c.listen().await.unwrap();
        while let Ok(conn) = l.accept().await {
            if tx.send(conn).is_err() {
                return;
            }
        }
    });
    (task, rx)
}

async fn held(rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::Conn>) -> crate::Conn {
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("a connection in time").unwrap()
}

/// An echo of one held connection: back what came, then close.
fn echo_held(mut conn: crate::Conn) {
    tokio::spawn(async move {
        let mut buf = Vec::new();
        if conn.read_to_end(&mut buf).await.is_ok() && conn.write_all(&buf).await.is_ok() {
            let _ = conn.close().await;
        }
    });
}

#[tokio::test]
async fn an_abandoned_attempt_is_failed() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let (task, mut rx) = listen_hold(&c);
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    echo_held(held(&mut rx).await);
    exchange(&mut leg, b"one").await;
    keep(&mut leg).await;
    bind(&mut leg, &id(2)).await;
    let old = held(&mut rx).await; // the application holds it, neither reading nor writing
    // The hub never heard bound, and asks again for the same id.
    offer_open(&mut ctl, &id(2)).await;
    let (conn, _leg2) = take_accept(&mut sc, true).await;
    assert_eq!(conn, id(2));
    let new = held(&mut rx).await;
    assert_eq!(new.id().to_string(), id(2));
    old.close().await.unwrap();
    let closes: Vec<String> = heard.until(4).await.into_iter().filter(|e| e.starts_with("close")).collect();
    assert_eq!(closes[1], format!("close {} 0 0 dropped: {REASON_LEG_LOST}", id(2)), "{closes:?}");
    assert_eq!(c.conns().len(), 1, "the new attempt goes on");
    task.abort();
}

#[tokio::test]
async fn an_open_does_not_drop_this_clients_connecting_side() {
    // One client that serves the word and dials it too: its connecting
    // connection has the id the serving side then gets with an open
    // message. That id was never bound here, so nothing is abandoned.
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let (task, mut rx) = listen_hold(&c);
    let mut ctl = register(&mut sc).await;
    let dialing = {
        let c = c.clone();
        tokio::spawn(async move { c.dial().await.unwrap() })
    };
    let (req, mut connect_leg) = sc.next("connect").await;
    upgrade(&mut connect_leg, &req, &[("X-Pf-Tunnel-Proto", "2"), ("X-PF-Tunnel-Conn", id(7).as_str())]).await;
    let dialed = dialing.await.unwrap();
    offer_open(&mut ctl, &id(7)).await;
    let (_, _serve_leg) = take_accept(&mut sc, true).await;
    let served = held(&mut rx).await;
    assert_eq!((dialed.id(), served.id()), (served.id(), dialed.id()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(dialed.err().is_none(), "{:?}", dialed.err());
    assert_eq!(c.conns().len(), 2);
    assert!(!heard.all().iter().any(|e| e.starts_with("close")), "{:?}", heard.all());
    task.abort();
}

#[tokio::test]
async fn a_late_bind_is_refused() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let tasks = serve(&c, Mode::Listen).await;
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    exchange(&mut leg, b"one").await;
    keep(&mut leg).await;
    offer_open(&mut ctl, &id(2)).await;
    let (_, _leg2) = take_accept(&mut sc, true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The hub fell back already; a bind for that id is refused.
    send(&mut leg, OP_TEXT, format!("bind {}", id(2)).as_bytes()).await;
    let end = tokio::time::timeout(Duration::from_secs(5), recv(&mut leg)).await.expect("the leg closes");
    assert!(matches!(end, None | Some((OP_CLOSE, _))), "a late bind was answered with {end:?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let opened = heard.all().iter().filter(|e| **e == format!("open {}", id(2))).count();
    assert_eq!(opened, 1, "{:?}", heard.all());
    tasks.iter().for_each(JoinHandle::abort);
}

#[tokio::test]
async fn finished_resolves_on_the_verdict() {
    let (c, mut sc) = scripted(|b| b.serve_token(SERVE_TOKEN));
    let (task, mut rx) = listen_hold(&c);
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    let mut conn = held(&mut rx).await;
    send(&mut leg, OP_TEXT, b"eof").await;
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).await.unwrap();
    conn.shutdown().await.unwrap();
    expect(&mut leg, OP_TEXT, b"eof").await;
    send(&mut leg, OP_TEXT, b"idle").await;
    let r = tokio::time::timeout(Duration::from_secs(2), conn.finished()).await;
    assert!(matches!(r, Ok(None)), "finished() after the hub's idle: {r:?}");
    conn.close().await.unwrap();
    expect(&mut leg, OP_TEXT, b"idle").await; // and the leg is kept
    task.abort();
}

#[tokio::test]
async fn a_cancelled_close_still_ends_and_reports() {
    let heard = Heard::default();
    let wait = Duration::from_millis(300);
    let (c, mut sc) = scripted(configure(&heard, |b| b.timing(Timing { verdict_wait: wait, ..Timing::default() })));
    let (task, mut rx) = listen_hold(&c);
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    let conn = held(&mut rx).await;
    send(&mut leg, OP_TEXT, b"eof").await;
    let mut buf = Vec::new();
    (&conn).read_to_end(&mut buf).await.unwrap();
    // The close waits for the hub's verdict, and its future is dropped.
    assert!(tokio::time::timeout(Duration::from_millis(50), conn.close()).await.is_err());
    expect(&mut leg, OP_TEXT, b"eof").await;
    // No verdict: after verdict_wait it closes, and is reported, though
    // the Conn is still held.
    expect(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    send(&mut leg, OP_CLOSE, &[3, 0xE8]).await;
    assert_eq!(heard.until(2).await[1], format!("close {} 0 0 ok", id(1)));
    assert_eq!(c.stats().active, 0);
    assert!(c.conns().is_empty());
    drop(conn);
    task.abort();
}

#[tokio::test]
async fn idle_before_this_sides_eof_is_a_violation() {
    let heard = Heard::default();
    let (c, mut sc) = scripted(configure(&heard, |b| b));
    let (task, mut rx) = listen_hold(&c);
    let mut ctl = register(&mut sc).await;
    offer_open(&mut ctl, &id(1)).await;
    let (_, mut leg) = take_accept(&mut sc, true).await;
    let conn = held(&mut rx).await; // the application has not half-closed
    send(&mut leg, OP_TEXT, b"eof").await;
    send(&mut leg, OP_TEXT, b"idle").await;
    let end = tokio::time::timeout(Duration::from_secs(5), recv(&mut leg)).await.expect("the leg is cut");
    assert!(matches!(end, None | Some((OP_CLOSE, _))), "{end:?}");
    let events = heard.until(2).await;
    assert!(events[1].starts_with(&format!("close {} 0 0 failed: ", id(1))), "{events:?}");
    assert!(events[1].contains("idle"), "{events:?}");
    assert!(conn.err().is_some());
    task.abort();
}

#[test]
fn zero_idle_legs_means_the_default() {
    let c = Client::builder("https://127.0.0.1:1/", "k3f9-x2mq-7hpa").max_idle_legs(0).build().unwrap();
    assert_eq!(c.inner.max_idle_legs, crate::DEFAULT_MAX_IDLE_LEGS);
    assert!(c.inner.reuse);
    let c = Client::builder("https://127.0.0.1:1/", "k3f9-x2mq-7hpa").no_reuse().build().unwrap();
    assert!(!c.inner.reuse);
}
