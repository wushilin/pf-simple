//! Regression tests for the findings of a review of 0.16.0, through the
//! public API against a fake hub: HTTPS discovery, and a bare quinn
//! listener whose streams each test drives by hand (PROTOCOL.md §13).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pfrelay_quic::{Client, Error};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Hub {
    url: String,
    ca: String,
    quic: quinn::Endpoint,
    /// Holds each discovery answer back this many milliseconds.
    delay: Arc<AtomicU64>,
    /// The path of each discovery request, in order.
    paths: Arc<Mutex<Vec<String>>>,
}

async fn hub() -> Hub {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let qc = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let qder = qc.cert.der().clone();
    let qkey = rustls::pki_types::PrivateKeyDer::Pkcs8(qc.key_pair.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![qder.clone()], qkey)
        .unwrap();
    tls.alpn_protocols = vec![b"pf-tunnel".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut tr = quinn::TransportConfig::default();
    tr.max_concurrent_bidi_streams(1000u32.into());
    tr.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    cfg.transport_config(Arc::new(tr));
    let quic = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let qport = quic.local_addr().unwrap().port();
    let fp = pfrelay_quic::fingerprint(qder.as_ref());

    let hc = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let ca = hc.cert.pem();
    let hkey = rustls::pki_types::PrivateKeyDer::Pkcs8(hc.key_pair.serialize_der().into());
    let htls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![hc.cert.der().clone()], hkey)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(htls));
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://127.0.0.1:{}", ln.local_addr().unwrap().port());
    let delay = Arc::new(AtomicU64::new(0));
    let held = delay.clone();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let seen = paths.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = ln.accept().await.unwrap();
            let (acceptor, fp, held, seen) = (acceptor.clone(), fp.clone(), held.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut buf = Vec::new();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut b = [0u8; 1024];
                    let Ok(n) = s.read(&mut b).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&b[..n]);
                }
                let line = String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_string();
                seen.lock().unwrap().push(line.split(' ').nth(1).unwrap_or_default().to_string());
                tokio::time::sleep(Duration::from_millis(held.load(Ordering::Relaxed))).await;
                let body = json!({"host":"127.0.0.1","port":qport,"fingerprints":[fp]}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Hub { url, ca, quic, delay, paths }
}

fn client(h: &Hub) -> Client {
    Client::builder(h.url.clone(), "k3f9-x2mq-7hpa")
        .ca_pem(h.ca.clone())
        .logger(|m| eprintln!("  [client] {m}"))
        .build()
        .unwrap()
}

async fn read_msg(r: &mut quinn::RecvStream) -> Option<Value> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut body).await.ok()?;
    serde_json::from_slice(&body).ok()
}

async fn write_msg(w: &mut quinn::SendStream, v: Value) {
    let body = v.to_string().into_bytes();
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend(body);
    w.write_all(&out).await.unwrap();
}

fn frame(typ: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![typ];
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// How a direction of a stream ended, as the hub read it.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Fin,
    Error(String),
    Nothing,
}

/// The frames on a stream, read until it ends.
#[derive(Debug)]
struct Read {
    frames: Vec<(u8, Vec<u8>)>,
    ended: Ended,
}

impl Read {
    fn data(&self) -> Vec<u8> {
        self.frames.iter().filter(|f| f.0 == 0).flat_map(|f| f.1.clone()).collect()
    }
    fn types(&self) -> Vec<u8> {
        self.frames.iter().map(|f| f.0).collect()
    }
    fn err(&self) -> Option<String> {
        self.frames.iter().find(|f| f.0 == 2).map(|f| String::from_utf8_lossy(&f.1).into_owned())
    }
}

/// Reads frames until the stream ends, or nothing comes for `wait`. With
/// `on_err`, the hub ends its own direction (FIN) once it reads an err, as
/// §13.5 asks of the end that receives one, after that pause.
async fn read_frames(r: &mut quinn::RecvStream, w: &mut quinn::SendStream, wait: Duration, on_err: Option<Duration>) -> Read {
    let mut buf = Vec::new();
    let mut frames = Vec::new();
    let mut chunk = [0u8; 8192];
    let ended = loop {
        while buf.len() >= 3 {
            let n = u16::from_be_bytes([buf[1], buf[2]]) as usize;
            if buf.len() < 3 + n {
                break;
            }
            let f: Vec<u8> = buf.drain(..3 + n).collect();
            frames.push((f[0], f[3..].to_vec()));
            if f[0] == 2 {
                if let Some(pause) = on_err {
                    tokio::time::sleep(pause).await;
                    let _ = w.finish();
                }
            }
        }
        match tokio::time::timeout(wait, r.read(&mut chunk)).await {
            Ok(Ok(Some(n))) => buf.extend_from_slice(&chunk[..n]),
            Ok(Ok(None)) => break Ended::Fin,
            Ok(Err(e)) => break Ended::Error(e.to_string()),
            Err(_) => break Ended::Nothing,
        }
    };
    Read { frames, ended }
}

/// Accepts the client's QUIC connection and its first stream, answers its
/// request with `answer`, and hands over the connection and the stream.
async fn accept_request(ep: &quinn::Endpoint, answer: Value) -> (quinn::Connection, quinn::SendStream, quinn::RecvStream) {
    let conn = ep.accept().await.unwrap().await.unwrap();
    let (mut w, mut r) = conn.accept_bi().await.unwrap();
    let _req = read_msg(&mut r).await;
    write_msg(&mut w, answer).await;
    (conn, w, r)
}

const CONNECTED: fn() -> Value = || json!({"status":200,"proto":3,"conn":"8f14e45fceea167a"});

// ---------- 1. stalled streams do not freeze the connection ----------

/// 40 connections whose application never reads, each pushed 2 MiB, must
/// not hold up the opens that come after them (§13.3: a stalled stream
/// holds up only itself). 0.16.0 froze the whole connection from 16 on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_streams_do_not_freeze_the_connection() {
    const STALLED: usize = 40;
    let h = hub().await;
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let conn = ep.accept().await.unwrap().await.unwrap();
        let (mut sw, mut sr) = conn.accept_bi().await.unwrap();
        let _req = read_msg(&mut sr).await;
        write_msg(&mut sw, json!({"status":200,"proto":3,"reg":"5b2d4e8f1a6c9b0d"})).await;
        let mut keep = Vec::new();
        for i in 0..STALLED {
            let (mut w, mut r) = conn.open_bi().await.unwrap();
            let open = json!({"open": format!("{i:016x}"), "reg":"5b2d4e8f1a6c9b0d"});
            if tokio::time::timeout(Duration::from_secs(10), write_msg(&mut w, open)).await.is_err() {
                return Err(format!("open {i}, after {i} stalled streams, could not be written in 10 s"));
            }
            match tokio::time::timeout(Duration::from_secs(10), read_msg(&mut r)).await {
                Ok(Some(a)) if a["status"] == 200 => {}
                other => return Err(format!("open {i}, after {i} stalled streams, was answered {other:?}")),
            }
            keep.push(tokio::spawn(async move {
                let data = frame(0, &[7u8; 65535]);
                for _ in 0..32 {
                    if w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                let _keep = r;
                std::future::pending::<()>().await;
            }));
        }
        tokio::time::sleep(Duration::from_secs(2)).await; // let them fill up
        let (mut w, mut r) = conn.open_bi().await.unwrap();
        let answered = tokio::time::timeout(Duration::from_secs(10), async {
            write_msg(&mut w, json!({"open": "ffffffffffffffff", "reg":"5b2d4e8f1a6c9b0d"})).await;
            read_msg(&mut r).await
        })
        .await;
        let _keep = (sw, sr, keep);
        match answered {
            Ok(Some(a)) if a["status"] == 200 => Ok(()),
            other => Err(format!("with {STALLED} stalled streams, the next open was answered {other:?}")),
        }
    });
    let c = client(&h);
    let l = c.listen().await.unwrap();
    let mut held = Vec::new();
    let r = tokio::select! {
        r = hubtask => r.unwrap(),
        _ = async { loop { held.push(l.accept().await.unwrap()); } } => unreachable!(),
    };
    r.unwrap();
}

// ---------- 2. a Conn outlives its Client ----------

/// Over WebSocket a Conn outlives its Client; over QUIC, 0.16.0 closed the
/// connection under it when the last Client went. Once the Conn ends, the
/// connection is closed (none).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conn_outlives_its_client() {
    let h = hub().await;
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let (conn, mut w, mut r) = accept_request(&ep, CONNECTED()).await;
        // The client's data and eof.
        let mut want = frame(0, b"hello");
        want.extend(frame(1, b""));
        let mut got = vec![0u8; want.len()];
        let read = tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut got)).await;
        assert!(matches!(read, Ok(Ok(()))), "the client's data did not arrive: {read:?}");
        assert_eq!(got, want);
        tokio::time::sleep(Duration::from_millis(300)).await; // the client is dropped meanwhile
        let mut back = frame(0, b"bye");
        back.extend(frame(1, b""));
        w.write_all(&back).await.unwrap();
        let _ = w.finish();
        let rest = tokio::time::timeout(Duration::from_secs(5), r.read_to_end(1 << 10)).await;
        assert!(matches!(rest, Ok(Ok(ref b)) if b.is_empty()), "the client's FIN: {rest:?}");
        // Nothing holds the connection any more: it is closed, code none.
        let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        match closed {
            Ok(quinn::ConnectionError::ApplicationClosed(c)) => assert_eq!(c.error_code, quinn::VarInt::from_u32(0)),
            other => panic!("the connection was not closed (none) after its last stream: {other:?}"),
        }
    });
    let c = client(&h);
    let mut conn = c.dial().await.unwrap();
    conn.write_all(b"hello").await.unwrap();
    conn.shutdown().await.unwrap();
    drop(c);
    let mut back = Vec::new();
    conn.read_to_end(&mut back).await.expect("the connection outlives its client");
    assert_eq!(back, b"bye");
    conn.close().await.unwrap();
    assert!(conn.err().is_none(), "{:?}", conn.err());
    hubtask.await.unwrap();
}

// ---------- 3. a 426 is a final refusal ----------

/// A 426 carries the hub's protocol in `proto`; 0.16.0 checked `proto`
/// first, and reported it as a protocol error, retried for ever.
#[tokio::test]
async fn a_426_is_a_final_refusal() {
    let h = hub().await;
    let ep = h.quic.clone();
    tokio::spawn(async move {
        let conn = ep.accept().await.unwrap().await.unwrap();
        while let Ok((mut w, mut r)) = conn.accept_bi().await {
            let _ = read_msg(&mut r).await;
            write_msg(&mut w, json!({"status":426,"proto":4,"error":"this hub speaks QUIC protocol 4 only; upgrade the client"})).await;
            let _ = w.finish();
            let _ = r.stop(2u32.into());
        }
    });
    let e = client(&h).dial().await.unwrap_err();
    match &e {
        Error::Status { code: 426, message } => assert!(message.contains("protocol 4"), "{message}"),
        other => panic!("426 is not reported as the hub's refusal: {other:?}"),
    }
    assert!(e.is_final());
}

/// Discovery goes under the prefix the server URL gave (PROTOCOL.md §2,
/// §13.2), and `/pf` when it gave none.
#[tokio::test]
async fn discovery_uses_the_prefix() {
    for (suffix, path) in [("/xzfe-aeeg-e2da/", "/xzfe-aeeg-e2da/api/tunnel/quic"), ("", "/pf/api/tunnel/quic")] {
        let h = hub().await;
        let ep = h.quic.clone();
        tokio::spawn(async move {
            let conn = ep.accept().await.unwrap().await.unwrap();
            while let Ok((mut w, mut r)) = conn.accept_bi().await {
                let _ = read_msg(&mut r).await;
                write_msg(&mut w, json!({"status":403,"proto":3,"error":"refused by the test hub"})).await;
                let _ = w.finish();
            }
        });
        let c = Client::builder(format!("{}{suffix}", h.url), "k3f9-x2mq-7hpa").ca_pem(h.ca.clone()).build().unwrap();
        assert!(c.dial().await.is_err());
        assert_eq!(h.paths.lock().unwrap().clone(), [path]);
    }
}

/// An accepted answer in another QUIC protocol is final too.
#[tokio::test]
async fn an_accepted_answer_in_another_protocol_is_final() {
    let h = hub().await;
    let ep = h.quic.clone();
    tokio::spawn(async move {
        let (_conn, _w, _r) = accept_request(&ep, json!({"status":200,"proto":4,"conn":"8f14e45fceea167a"})).await;
        std::future::pending::<()>().await;
    });
    let e = client(&h).dial().await.unwrap_err();
    assert!(matches!(e, Error::Status { code: 426, .. }), "{e:?}");
    assert!(e.is_final());
}

// ---------- 4. a connection given up after a 429 is closed ----------

/// After a 429 for the connection, the client moves to a new connection
/// and closes the old one (none) once it holds nothing (§13.8). 0.16.0
/// left it open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_given_up_after_a_429_is_closed() {
    let h = hub().await;
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let (first, mut w, mut r) = accept_request(
            &ep,
            json!({"status":429,"proto":3,"error":"too many refused requests on this connection","retryAfter":60,"scope":"connection"}),
        )
        .await;
        let _ = w.finish();
        let _ = r.stop(2u32.into());
        let (second, mut w2, _r2) = accept_request(&ep, json!({"status":204,"proto":3})).await;
        let _ = w2.finish();
        (tokio::time::timeout(Duration::from_secs(5), first.closed()).await, second)
    });
    let c = client(&h);
    let e = c.check().await.unwrap_err();
    assert_eq!(e.status(), Some(429), "{e:?}");
    c.check().await.unwrap();
    match hubtask.await.unwrap().0 {
        Ok(quinn::ConnectionError::ApplicationClosed(c)) => assert_eq!(c.error_code, quinn::VarInt::from_u32(0)),
        other => panic!("the client never closed the connection it gave up: {other:?}"),
    }
}

// ---------- 5. a failed write still reports the reason ----------

/// The far end sends more data than the application reads, then err, then
/// stops this side's direction. The application's write fails; the reason
/// must still be read (§13.5), past the data queued ahead of it. 0.16.0's
/// reader stayed parked behind the unread data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_write_still_reports_the_reason() {
    let h = hub().await;
    let ep = h.quic.clone();
    tokio::spawn(async move {
        let (_conn, mut w, mut r) = accept_request(&ep, CONNECTED()).await;
        let mut out = Vec::new();
        for _ in 0..12 {
            out.extend(frame(0, &[1u8; 1000]));
        }
        out.extend(frame(2, b"the target went away"));
        w.write_all(&out).await.unwrap();
        let _ = w.finish();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = r.stop(5u32.into());
        std::future::pending::<()>().await;
    });
    let c = client(&h);
    let mut conn = c.dial().await.unwrap();
    let chunk = vec![0u8; 16 << 10];
    let failed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Err(e) = conn.write_all(&chunk).await {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the write never failed");
    eprintln!("the write failed: {failed}");
    let why = tokio::time::timeout(Duration::from_secs(5), conn.finished()).await.expect("the reason was never read");
    match why {
        Some(Error::Remote(r)) => assert_eq!(r.reason, "the target went away"),
        other => panic!("{other:?}"),
    }
}

// ---------- 6. fail returns once the reason is delivered ----------

/// `fail` keeps the stream until the far end has ended its direction (up
/// to 3 s), so a program that exits next does not lose the reason (§13.5).
/// 0.16.0 returned at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fail_waits_for_the_far_end() {
    let h = hub().await;
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let (_conn, mut w, mut r) = accept_request(&ep, CONNECTED()).await;
        read_frames(&mut r, &mut w, Duration::from_secs(5), Some(Duration::from_millis(700))).await
    });
    let c = client(&h);
    let conn = c.dial().await.unwrap();
    let t = Instant::now();
    conn.fail("the application gave up").await;
    let took = t.elapsed();
    c.close();
    let seen = hubtask.await.unwrap();
    assert_eq!(seen.err().as_deref(), Some("the application gave up"), "{seen:?}");
    assert_eq!(seen.ended, Ended::Fin, "{seen:?}");
    assert!(took >= Duration::from_millis(600), "fail returned before the far end ended its direction ({took:?})");
    assert!(took < Duration::from_secs(3), "{took:?}");
}

// ---------- write, then close ----------

/// Writing, half-closing and closing before the far end's eof delivers
/// what was written, then err and FIN, as over WebSocket the data arrives
/// before the cut. 0.16.0 reset the stream, which drops what is unsent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_then_close_delivers_the_data() {
    let h = hub().await;
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let (_conn, mut w, mut r) = accept_request(&ep, CONNECTED()).await;
        read_frames(&mut r, &mut w, Duration::from_secs(5), Some(Duration::ZERO)).await
    });
    let c = client(&h);
    let mut conn = c.dial().await.unwrap();
    let big = vec![9u8; 300_000];
    conn.write_all(&big).await.unwrap();
    conn.shutdown().await.unwrap();
    conn.close().await.unwrap();
    let seen = hubtask.await.unwrap();
    assert_eq!(seen.data().len(), big.len(), "the data was not all delivered: {:?}", seen.ended);
    let types = seen.types();
    assert_eq!(&types[types.len() - 2..], &[1, 2], "eof, then err");
    assert_eq!(seen.err().as_deref(), Some("the connection was closed before the far end finished"));
    assert_eq!(seen.ended, Ended::Fin);
}

/// But an end that received err does not answer with one (§13.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_after_the_far_ends_err_sends_no_err() {
    let h = hub().await;
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let (_conn, mut w, mut r) = accept_request(&ep, CONNECTED()).await;
        w.write_all(&frame(2, b"the target went away")).await.unwrap();
        let _ = w.finish();
        read_frames(&mut r, &mut w, Duration::from_secs(5), None).await
    });
    let c = client(&h);
    let mut conn = c.dial().await.unwrap();
    conn.write_all(b"hello").await.unwrap();
    conn.shutdown().await.unwrap();
    let mut buf = [0u8; 8];
    let e = conn.read(&mut buf).await.unwrap_err();
    assert!(matches!(Error::from_io(&e), Some(Error::Remote(r)) if r.reason == "the target went away"), "{e:?}");
    conn.close().await.unwrap();
    let seen = hubtask.await.unwrap();
    assert!(seen.err().is_none(), "answered an err with an err: {seen:?}");
    assert_ne!(seen.ended, Ended::Nothing, "{seen:?}");
}

// ---------- 8. close while a connection is being made ----------

/// `Client::close` while another request is discovering: 0.16.0's close
/// did nothing then, and the request went on to keep a new connection.
/// Now the request fails as closed, and its connection is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_while_a_connection_is_being_made() {
    let h = hub().await;
    h.delay.store(500, Ordering::Relaxed);
    let ep = h.quic.clone();
    let hubtask = tokio::spawn(async move {
        let Some(inc) = ep.accept().await else { return None };
        let Ok(conn) = inc.await else { return None };
        if let Ok((mut w, mut r)) = conn.accept_bi().await {
            let _ = read_msg(&mut r).await;
            write_msg(&mut w, json!({"status":204,"proto":3})).await;
            let _ = w.finish();
        }
        Some(tokio::time::timeout(Duration::from_secs(5), conn.closed()).await.is_ok())
    });
    let c = client(&h);
    let checking = tokio::spawn({
        let c = c.clone();
        async move { c.check().await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    c.close();
    let r = checking.await.unwrap();
    assert!(matches!(r, Err(Error::Closed)), "a request made across close: {r:?}");
    let abort = hubtask.abort_handle();
    match tokio::time::timeout(Duration::from_secs(2), hubtask).await {
        Ok(r) => assert_ne!(r.unwrap(), Some(false), "the connection made across close was left open"),
        Err(_) => abort.abort(), // no connection was made
    }
    // The next request opens a new connection.
    h.delay.store(0, Ordering::Relaxed);
    let ep = h.quic.clone();
    tokio::spawn(async move {
        let (_conn, mut w, _r) = accept_request(&ep, json!({"status":204,"proto":3})).await;
        let _ = w.finish();
        std::future::pending::<()>().await;
    });
    c.check().await.unwrap();
}
