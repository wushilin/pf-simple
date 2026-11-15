//! Connection leaks: each test counts the client's ends of the streams it
//! opened that are still open (`Script::live`).

use std::time::Duration;

use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::testhub::{recv, scripted, send, upgrade, Script, SERVE_TOKEN};
use crate::ws::{OP_BINARY, OP_CLOSE, OP_TEXT};
use crate::{Error, Timing};

const SESSION: &str = "3f9a0c7e5b2d4e8f1a6c9b0d7e2f4a1c";
const STOPPED: &[u8] = b"err:the serving side stopped listening";

fn fast() -> Timing {
    Timing {
        retry_min: Duration::from_millis(30),
        retry_max: Duration::from_millis(100),
        verdict_wait: Duration::from_millis(200),
        ..Timing::default()
    }
}

fn id(n: u32) -> String {
    format!("{n:016x}")
}

async fn register(sc: &mut Script) -> DuplexStream {
    let (req, mut s) = sc.next("serve").await;
    upgrade(&mut s, &req, &[("X-Pf-Tunnel-Proto", "2"), ("X-PF-Tunnel-Session", SESSION)]).await;
    s
}

async fn open(ctl: &mut DuplexStream, conn: &str) {
    send(ctl, OP_TEXT, format!(r#"{{"open":"{conn}"}}"#).as_bytes()).await;
}

async fn take_accept(sc: &mut Script, offer: bool) -> DuplexStream {
    let (req, mut s) = sc.next("accept").await;
    let mut h = vec![("X-Pf-Tunnel-Proto", "2")];
    if offer {
        h.push(("X-PF-Tunnel-Keep-Alive", "60"));
    }
    upgrade(&mut s, &req, &h).await;
    s
}

/// The next frame that is not a ping, within 5 s; `None` if the client
/// closed its end.
async fn next_frame(leg: &mut DuplexStream) -> Option<(u8, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(5), recv(leg)).await.expect("a frame or the end in time")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_waiting_for_accept_close_when_serving_gives_up() {
    // A client token, so a hub that announces no protocol is final.
    let (c, mut sc) = scripted(|b| b.serve_token(SERVE_TOKEN).client_token("clienttoken123").timing(fast()));
    let listening = tokio::spawn({
        let c = c.clone();
        async move { c.listen().await.unwrap() }
    });
    let mut ctl = register(&mut sc).await;
    let l = listening.await.unwrap();
    let mut legs = Vec::new();
    for n in 0..3 {
        open(&mut ctl, &id(n)).await;
        legs.push(take_accept(&mut sc, false).await);
    }
    assert_eq!(sc.settle(4).await, 4, "the control channel and 3 waiting connections");
    // The hub goes away and comes back as one from before protocols.
    drop(ctl);
    let (req, mut s) = sc.next("serve").await;
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        crate::ws::accept_key(req.get("Sec-WebSocket-Key").unwrap())
    );
    s.write_all(head.as_bytes()).await.unwrap();
    // With the Listener still held and nothing accepting, the waiting
    // connections are failed and closed.
    assert_eq!(sc.settle(0).await, 0, "streams left open");
    for leg in &mut legs {
        assert_eq!(next_frame(leg).await, Some((OP_TEXT, STOPPED.to_vec())));
    }
    assert!(matches!(l.accept().await, Err(Error::Protocol(_))));
    assert!(matches!(l.accept().await, Err(Error::Closed)));
    assert_eq!(c.stats().active, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_fails_the_connections_waiting_for_accept() {
    let (c, mut sc) = scripted(|b| b.serve_token(SERVE_TOKEN).timing(fast()));
    let listening = tokio::spawn({
        let c = c.clone();
        async move { c.listen().await.unwrap() }
    });
    let mut ctl = register(&mut sc).await;
    let l = listening.await.unwrap();
    let mut legs = Vec::new();
    for n in 0..2 {
        open(&mut ctl, &id(n)).await;
        legs.push(take_accept(&mut sc, true).await);
    }
    assert_eq!(sc.settle(3).await, 3);
    l.close();
    for leg in &mut legs {
        assert_eq!(next_frame(leg).await, Some((OP_TEXT, STOPPED.to_vec())));
    }
    assert_eq!(sc.settle(0).await, 0, "streams left open");
    assert!(matches!(l.accept().await, Err(Error::Closed)));
    assert_eq!(c.stats().active, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_that_crosses_the_close_leaves_nothing_open() {
    let (c, mut sc) = scripted(|b| b.serve_token(SERVE_TOKEN).timing(fast()));
    let serving = {
        let c = c.clone();
        tokio::spawn(async move {
            let l = c.listen().await.unwrap();
            while let Ok(mut conn) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    use tokio::io::AsyncReadExt;
                    if conn.read_to_end(&mut buf).await.is_ok() && conn.write_all(&buf).await.is_ok() {
                        let _ = conn.close().await;
                    }
                });
            }
        })
    };
    let mut ctl = register(&mut sc).await;
    for n in 1..=5 {
        open(&mut ctl, &id(n)).await;
        let mut leg = take_accept(&mut sc, true).await;
        send(&mut leg, OP_BINARY, b"x").await;
        send(&mut leg, OP_TEXT, b"eof").await;
        assert_eq!(next_frame(&mut leg).await, Some((OP_BINARY, b"x".to_vec())));
        assert_eq!(next_frame(&mut leg).await, Some((OP_TEXT, b"eof".to_vec())));
        // No verdict in time: the client closes. The hub's late "idle"
        // crosses that close, and the hub keeps its end open.
        assert_eq!(next_frame(&mut leg).await, Some((OP_CLOSE, vec![3, 0xE8])));
        send(&mut leg, OP_TEXT, b"idle").await;
        assert_eq!(sc.settle(1).await, 1, "connection {n}: only the control channel stays open");
        drop(leg);
    }
    assert_eq!(c.stats().active, 0);
    serving.abort();
}
