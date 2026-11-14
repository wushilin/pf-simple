//! Tests of the client against the fake hub of `testhub`: the retry
//! schedule, the backlog, events, drop, stats and conns, the forwarders and
//! watch. Time is paused where timing matters, so it is exact.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::testhub::{client, hold, recv, reply, send, upgrade, Req, SERVE_TOKEN};
use crate::ws::{OP_BINARY, OP_CLOSE, OP_TEXT};
use crate::{ConnId, Error, Events, Side, Timing};

/// What the event handlers heard, one line per event.
#[derive(Clone, Default)]
struct Heard(Arc<Mutex<Vec<String>>>);

impl Heard {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn starting(&self, prefix: &str) -> Vec<String> {
        self.all().into_iter().filter(|l| l.starts_with(prefix)).collect()
    }
    fn events(&self) -> Events {
        let (a, b, c, d, e) = (self.clone(), self.clone(), self.clone(), self.clone(), self.clone());
        Events::new()
            .on_serving(move |up| a.push(format!("serving {up}")))
            .on_tunnel(move |up, _| b.push(format!("tunnel {up}")))
            .on_open(move |ci| c.push(format!("open {} {}", ci.id, ci.side)))
            .on_close(move |ci, err| {
                let how = match err {
                    None => "ok".to_string(),
                    Some(Error::Dropped { reason }) => format!("dropped:{reason}"),
                    Some(e) => format!("failed:{e}"),
                };
                d.push(format!("close {} {} {} {how}", ci.id, ci.sent, ci.received))
            })
            .on_refuse(move |id, reason| e.push(format!("refuse {id} {reason}")))
    }
}

/// Waits (in paused or real time) until `f` holds.
async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn gaps(times: &[Instant]) -> Vec<Duration> {
    times.windows(2).map(|w| w[1] - w[0]).collect()
}

fn near(got: &[Duration], want: &[Duration]) -> bool {
    got.len() >= want.len()
        && got.iter().zip(want).all(|(g, w)| g.abs_diff(*w) < Duration::from_millis(20))
}

/// A hub whose `serve` refuses `refusals` times with `status`, then
/// registers and holds the control channel; it records when each
/// registration came.
fn serve_hub(
    refusals: usize,
    status: u16,
    times: Arc<Mutex<Vec<Instant>>>,
) -> impl Fn(Req, tokio::io::DuplexStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync
{
    move |req, mut s| {
        let times = times.clone();
        Box::pin(async move {
            if req.endpoint() != "serve" {
                return reply(&mut s, 404, &[]).await;
            }
            let n = {
                let mut t = times.lock().unwrap();
                t.push(Instant::now());
                t.len()
            };
            if n <= refusals {
                reply(&mut s, status, &[]).await;
            } else {
                upgrade(&mut s, &req, &[]).await;
                hold(s).await;
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn retries_with_a_doubling_pause() {
    let times = Arc::new(Mutex::new(Vec::new()));
    let heard = Heard::default();
    let c = client(serve_hub(3, 503, times.clone()), |b| b.serve_token(SERVE_TOKEN).events(heard.events()));
    let l = c.listen().await.unwrap();
    assert!(l.is_up());
    let t = times.lock().unwrap().clone();
    assert_eq!(t.len(), 4);
    let want = [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)];
    assert!(near(&gaps(&t), &want), "pauses {:?}", gaps(&t));
    assert_eq!(heard.starting("serving"), ["serving true"]);
}

#[tokio::test(start_paused = true)]
async fn the_timing_is_injectable_and_capped() {
    let times = Arc::new(Mutex::new(Vec::new()));
    let timing = Timing { retry_min: Duration::from_millis(100), retry_max: Duration::from_millis(250), ..Timing::default() };
    let c = client(serve_hub(5, 429, times.clone()), |b| b.serve_token(SERVE_TOKEN).timing(timing));
    let _l = c.listen().await.unwrap();
    let ms = |n| Duration::from_millis(n);
    let t = times.lock().unwrap().clone();
    assert!(near(&gaps(&t), &[ms(100), ms(200), ms(250), ms(250), ms(250)]), "pauses {:?}", gaps(&t));
    assert_eq!(timing.next(ms(200)), ms(250));
}

#[tokio::test(start_paused = true)]
async fn a_final_refusal_ends_the_first_registration() {
    for (status, want) in [(403u16, "access denied"), (409, "409")] {
        let times = Arc::new(Mutex::new(Vec::new()));
        let c = client(serve_hub(usize::MAX, status, times.clone()), |b| b.serve_token(SERVE_TOKEN));
        let err = c.listen().await.unwrap_err();
        assert!(err.is_final() && err.to_string().contains(want), "{status}: {err}");
        assert_eq!(times.lock().unwrap().len(), 1, "{status} is not retried");
    }
}

#[tokio::test(start_paused = true)]
async fn registers_again_after_losing_the_hub() {
    let times = Arc::new(Mutex::new(Vec::new()));
    let t2 = times.clone();
    let heard = Heard::default();
    let c = client(
        move |req: Req, mut s| {
            let times = t2.clone();
            async move {
                let n = {
                    let mut t = times.lock().unwrap();
                    t.push(Instant::now());
                    t.len()
                };
                upgrade(&mut s, &req, &[]).await;
                if n == 1 {
                    send(&mut s, OP_CLOSE, &[3, 0xE8]).await; // the hub ends the first one
                    let _ = recv(&mut s).await;
                } else {
                    hold(s).await;
                }
            }
        },
        |b| b.serve_token(SERVE_TOKEN).events(heard.events()),
    );
    let l = c.listen().await.unwrap();
    until("the second registration", || times.lock().unwrap().len() == 2).await;
    until("serving again", || heard.starting("serving").len() == 3).await;
    assert_eq!(heard.starting("serving"), ["serving true", "serving false", "serving true"]);
    assert!(near(&gaps(&times.lock().unwrap()), &[Duration::from_secs(1)]));
    assert!(l.is_up());
}

/// A hub that serves, offers `opens` connections on the control channel,
/// carries each `accept` upgrade (holding it open), and counts the
/// refusals it gets through `accept`.
fn offering_hub(
    opens: usize,
    refusals: Arc<Mutex<Vec<(String, String)>>>,
) -> impl Fn(Req, tokio::io::DuplexStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync
{
    move |req, mut s| {
        let refusals = refusals.clone();
        Box::pin(async move {
            match req.endpoint() {
                "serve" => {
                    upgrade(&mut s, &req, &[]).await;
                    for i in 0..opens {
                        send(&mut s, OP_TEXT, format!(r#"{{"open":"{:016x}"}}"#, 0xa00 + i).as_bytes()).await;
                    }
                    hold(s).await;
                }
                "accept" => {
                    let id = req.get("X-PF-Tunnel-Conn").unwrap().to_string();
                    match req.get("X-PF-Tunnel-Error") {
                        Some(reason) => {
                            assert!(!req.is_upgrade(), "a refusal is a plain GET");
                            refusals.lock().unwrap().push((id, reason.to_string()));
                            reply(&mut s, 204, &[]).await;
                        }
                        None => {
                            upgrade(&mut s, &req, &[]).await;
                            hold(s).await;
                        }
                    }
                }
                _ => reply(&mut s, 404, &[]).await,
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_full_backlog_refuses_with_a_reason() {
    let refusals = Arc::new(Mutex::new(Vec::new()));
    let heard = Heard::default();
    let c = client(offering_hub(crate::LISTEN_BACKLOG + 2, refusals.clone()), |b| {
        b.serve_token(SERVE_TOKEN).events(heard.events())
    });
    let l = c.listen().await.unwrap();
    until("the refusals", || refusals.lock().unwrap().len() == 2).await;
    until("the waiting connections", || c.stats().active == crate::LISTEN_BACKLOG as u64).await;
    for (_, reason) in refusals.lock().unwrap().iter() {
        assert!(reason.contains("not accepting connections fast enough"), "{reason}");
    }
    assert_eq!(heard.starting("refuse").len(), 2);
    assert_eq!(heard.starting("open").len(), crate::LISTEN_BACKLOG);
    // Accepting one frees a slot.
    let conn = l.accept().await.unwrap();
    assert_eq!(conn.side(), Side::Serve);
}

/// A hub whose `connect` hands out ids 0..., echoes data and half-closes,
/// and records the reasons it hears.
fn echo_hub(
    reasons: Arc<Mutex<Vec<String>>>,
) -> impl Fn(Req, tokio::io::DuplexStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync
{
    let next = Arc::new(AtomicUsize::new(1));
    move |req, mut s| {
        let (reasons, next) = (reasons.clone(), next.clone());
        Box::pin(async move {
            if req.endpoint() != "connect" {
                return reply(&mut s, 403, &[]).await;
            }
            let id = format!("{:016x}", next.fetch_add(1, Ordering::SeqCst));
            upgrade(&mut s, &req, &[("X-PF-Tunnel-Conn", id.as_str())]).await;
            while let Some((op, payload)) = recv(&mut s).await {
                match op {
                    OP_BINARY => send(&mut s, OP_BINARY, &payload).await,
                    OP_TEXT if payload == b"eof" => send(&mut s, OP_TEXT, b"eof").await,
                    OP_TEXT => {
                        reasons.lock().unwrap().push(String::from_utf8_lossy(&payload).into_owned());
                    }
                    OP_CLOSE => {
                        send(&mut s, OP_CLOSE, &[3, 0xE8]).await;
                        return;
                    }
                    _ => {}
                }
            }
        })
    }
}

#[tokio::test]
async fn events_stats_conns_and_drop() {
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let heard = Heard::default();
    let c = client(echo_hub(reasons.clone()), |b| b.events(heard.events()));

    // A clean connection: opened and closed once each, with its figures.
    let mut conn = c.dial().await.unwrap();
    assert_eq!(conn.id().to_string(), "0000000000000001");
    conn.write_all(b"hello").await.unwrap();
    conn.shutdown().await.unwrap();
    let mut back = Vec::new();
    conn.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"hello");
    conn.close().await.unwrap();
    conn.close().await.unwrap(); // a second close says nothing more
    drop(conn);
    assert_eq!(heard.all(), ["open 0000000000000001 connect", "close 0000000000000001 5 5 ok"]);

    // One held open shows in conns and stats.
    let mut conn = c.dial().await.unwrap();
    conn.write_all(b"abc").await.unwrap();
    let mut three = [0u8; 3];
    conn.read_exact(&mut three).await.unwrap();
    let list = c.conns();
    assert_eq!(list.len(), 1);
    assert_eq!((&list[0].id, list[0].side, list[0].sent, list[0].received), (conn.id(), Side::Connect, 3, 3));
    let st = c.stats();
    assert_eq!((st.opened, st.active, st.failed, st.sent, st.received), (2, 1, 0, 8, 8));

    // Dropping it by id reaches the far end with the reason.
    assert!(!c.drop_conn(&ConnId::new("0000000000000000"), "nothing"));
    let id = conn.id().clone();
    assert!(c.drop_conn(&id, "dropped by a test"));
    until("the reason at the hub", || !reasons.lock().unwrap().is_empty()).await;
    assert_eq!(reasons.lock().unwrap()[0], "err:dropped by a test");
    let err = conn.read(&mut three).await.unwrap_err();
    assert!(matches!(Error::from_io(&err), Some(Error::Dropped { .. })), "{err}");
    conn.close().await.unwrap();
    drop(conn);
    assert!(!c.drop_conn(&id, "again"), "a closed connection cannot be dropped");
    assert_eq!(heard.starting("close"), [
        "close 0000000000000001 5 5 ok".to_string(),
        "close 0000000000000002 3 3 dropped:dropped by a test".to_string(),
    ]);
    assert_eq!(heard.starting("open").len(), 2);
    let st = c.stats();
    assert_eq!((st.opened, st.active, st.failed), (2, 0, 1));
    assert!(c.conns().is_empty());
}

#[tokio::test]
async fn a_dropped_conn_closes_once() {
    let heard = Heard::default();
    let c = client(echo_hub(Default::default()), |b| b.events(heard.events()));
    let conn = c.dial().await.unwrap();
    drop(conn); // closing in the background still reports, once
    until("the close", || heard.starting("close").len() == 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(heard.starting("close").len(), 1);
    let conn = c.dial().await.unwrap();
    conn.fail("a test fails it").await;
    conn.fail("twice").await;
    drop(conn);
    assert_eq!(heard.starting("close")[1], "close 0000000000000002 0 0 dropped:a test fails it");
    assert_eq!(heard.starting("close").len(), 2);
}

#[tokio::test]
async fn the_forwarder_refuses_an_unreachable_target() {
    let closed = {
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ln.local_addr().unwrap().to_string()
    };
    let refusals = Arc::new(Mutex::new(Vec::new()));
    let heard = Heard::default();
    let c = client(offering_hub(1, refusals.clone()), |b| b.serve_token(SERVE_TOKEN).events(heard.events()));
    let task = tokio::spawn({
        let c = c.clone();
        async move { c.serve_tcp(closed).await }
    });
    until("the refusal", || !refusals.lock().unwrap().is_empty()).await;
    let (id, reason) = refusals.lock().unwrap()[0].clone();
    assert_eq!(id, "0000000000000a00");
    assert_eq!(reason, crate::TARGET_UNREACHABLE);
    until("the event", || !heard.starting("refuse").is_empty()).await;
    assert_eq!(heard.starting("refuse"), [format!("refuse {id} {}", crate::TARGET_UNREACHABLE)]);
    assert!(heard.starting("open").is_empty(), "a refused connection is never opened");
    task.abort();
}

#[tokio::test]
async fn the_forwarder_carries_to_its_target() {
    // An echo target.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = target.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                let _ = s.write_all(&buf).await;
            });
        }
    });
    let frames = Arc::new(Mutex::new(Vec::new()));
    let f2 = frames.clone();
    let heard = Heard::default();
    let c = client(
        move |req: Req, mut s| {
            let frames = f2.clone();
            async move {
                match req.endpoint() {
                    "serve" => {
                        upgrade(&mut s, &req, &[]).await;
                        send(&mut s, OP_TEXT, br#"{"open":"00000000000000b1"}"#).await;
                        hold(s).await;
                    }
                    _ => {
                        upgrade(&mut s, &req, &[]).await;
                        send(&mut s, OP_BINARY, b"ping").await;
                        send(&mut s, OP_TEXT, b"eof").await;
                        while let Some((op, payload)) = recv(&mut s).await {
                            frames.lock().unwrap().push((op, payload));
                            if op == OP_CLOSE {
                                send(&mut s, OP_CLOSE, &[3, 0xE8]).await;
                                return;
                            }
                        }
                    }
                }
            }
        },
        |b| b.serve_token(SERVE_TOKEN).events(heard.events()),
    );
    let task = tokio::spawn({
        let c = c.clone();
        async move { c.serve_tcp(addr).await }
    });
    until("the close", || !heard.starting("close").is_empty()).await;
    assert_eq!(
        frames.lock().unwrap().clone(),
        [(OP_BINARY, b"ping".to_vec()), (OP_TEXT, b"eof".to_vec()), (OP_CLOSE, vec![3, 0xE8])]
    );
    assert_eq!(heard.starting("open"), ["open 00000000000000b1 serve"]);
    assert_eq!(heard.starting("close"), ["close 00000000000000b1 4 4 ok"]);
    assert_eq!(c.stats().active, 0);
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn watch_reports_the_first_result_and_every_change() {
    let checks = Arc::new(AtomicUsize::new(0));
    let ch = checks.clone();
    let start = Instant::now();
    let at = Arc::new(Mutex::new(Vec::new()));
    let a2 = at.clone();
    let c = client(
        move |_req: Req, mut s| {
            let n = ch.fetch_add(1, Ordering::SeqCst) + 1;
            async move { reply(&mut s, if n == 3 { 204 } else { 403 }, &[]).await }
        },
        |b| b.events(Events::new().on_tunnel(move |up, err| {
            assert_eq!(up, err.is_none());
            a2.lock().unwrap().push((up, start.elapsed()))
        })),
    );
    let task = tokio::spawn(async move { c.watch().await });
    tokio::time::sleep(Duration::from_secs(40)).await;
    task.abort();
    let got = at.lock().unwrap().clone();
    let s = Duration::from_secs;
    // Down at once; checked again after 1s (still down) and 2s more (up);
    // then after 30s, down again.
    assert_eq!(got.iter().map(|(u, _)| *u).collect::<Vec<_>>(), [false, true, false]);
    assert!(near(&got.iter().map(|(_, t)| *t).collect::<Vec<_>>(), &[s(0), s(3), s(33)]), "{got:?}");
    // Checked at 0, 1, 3 and 33s; then down again, so sooner: 34 and 36s.
    assert_eq!(checks.load(Ordering::SeqCst), 6);
}
