//! A fake hub for unit tests: the client talks to it over in-memory pipes
//! through its connector, and each test says how it answers.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::client::{Client, ClientBuilder};
use crate::http::{Connector, Stream};

pub(crate) const WORD: &str = "k3f9-x2mq-7hpa";
pub(crate) const SERVE_TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// One request as the hub read it.
#[derive(Debug, Clone)]
pub(crate) struct Req {
    pub path: String,
    headers: Vec<(String, String)>,
}

impl Req {
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub(crate) fn endpoint(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or_default()
    }

    pub(crate) fn is_upgrade(&self) -> bool {
        self.get("Upgrade").is_some()
    }
}

type Handler = Arc<dyn Fn(Req, DuplexStream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A client for `WORD` whose hub is `handler`, called on its own task for
/// each request.
pub(crate) fn client<F, Fut>(handler: F, configure: impl FnOnce(ClientBuilder) -> ClientBuilder) -> Client
where
    F: Fn(Req, DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    counted_client(handler, configure, Arc::default())
}

/// `client`, counting in `live` the client's ends of the streams it opened
/// that are still open.
pub(crate) fn counted_client<F, Fut>(
    handler: F,
    configure: impl FnOnce(ClientBuilder) -> ClientBuilder,
    live: Arc<AtomicIsize>,
) -> Client
where
    F: Fn(Req, DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let handler: Handler = Arc::new(move |r, s| Box::pin(handler(r, s)));
    let connector: Connector = Arc::new(move || {
        let (handler, live) = (handler.clone(), live.clone());
        Box::pin(async move {
            let (ours, mut theirs) = tokio::io::duplex(1 << 20);
            tokio::spawn(async move {
                if let Some(req) = read_request(&mut theirs).await {
                    handler(req, theirs).await;
                }
            });
            Ok(Box::new(Counted::new(ours, live)) as Stream)
        })
    });
    configure(Client::builder("https://127.0.0.1:1/", WORD).connector(connector))
        .build()
        .unwrap()
}

async fn read_request(s: &mut DuplexStream) -> Option<Req> {
    let mut raw = Vec::new();
    let mut b = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.ok()? == 0 {
            return None;
        }
        raw.push(b[0]);
    }
    let text = String::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    Some(Req { path, headers })
}

/// Answers with a status, the hub's protocol, and a JSON error for a refusal.
pub(crate) async fn reply(s: &mut DuplexStream, status: u16, extra: &[(&str, &str)]) {
    let body = if status >= 400 { r#"{"error":"refused by the test hub"}"# } else { "" };
    let mut head = format!("HTTP/1.1 {status} X\r\nX-Pf-Tunnel-Proto: 1\r\nContent-Length: {}\r\n", body.len());
    for (n, v) in extra {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str("\r\n");
    head.push_str(body);
    let _ = s.write_all(head.as_bytes()).await;
}

/// Accepts a WebSocket upgrade.
pub(crate) async fn upgrade(s: &mut DuplexStream, req: &Req, extra: &[(&str, &str)]) {
    let key = req.get("Sec-WebSocket-Key").unwrap();
    let mut head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        crate::ws::accept_key(key)
    );
    if !extra.iter().any(|(n, _)| n.eq_ignore_ascii_case("X-Pf-Tunnel-Proto")) {
        head.push_str("X-Pf-Tunnel-Proto: 1\r\n");
    }
    for (n, v) in extra {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
}

/// Sends a frame as the hub does: unmasked.
pub(crate) async fn send(s: &mut DuplexStream, op: u8, payload: &[u8]) {
    let mut f = vec![0x80 | op];
    let n = payload.len();
    if n < 126 {
        f.push(n as u8);
    } else {
        f.push(126);
        f.extend_from_slice(&(n as u16).to_be_bytes());
    }
    f.extend_from_slice(payload);
    let _ = s.write_all(&f).await;
}

/// The next frame from the client that is not a ping, unmasked; `None` when
/// the client went away.
pub(crate) async fn recv(s: &mut DuplexStream) -> Option<(u8, Vec<u8>)> {
    loop {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await.ok()?;
        assert_eq!(h[1] & 0x80, 0x80, "the client masks its frames");
        let len = match h[1] & 0x7F {
            126 => {
                let mut b = [0u8; 2];
                s.read_exact(&mut b).await.ok()?;
                u16::from_be_bytes(b) as usize
            }
            127 => {
                let mut b = [0u8; 8];
                s.read_exact(&mut b).await.ok()?;
                u64::from_be_bytes(b) as usize
            }
            n => n as usize,
        };
        let mut mask = [0u8; 4];
        s.read_exact(&mut mask).await.ok()?;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.ok()?;
        for (i, b) in body.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        if h[0] & 0x0F != crate::ws::OP_PING {
            return Some((h[0] & 0x0F, body));
        }
    }
}

/// The hub's side of a run where the test writes every frame: each request
/// arrives here, and the test answers it.
pub(crate) struct Script(tokio::sync::mpsc::UnboundedReceiver<(Req, DuplexStream)>, Arc<AtomicIsize>);

/// A client for `WORD` whose hub is the test itself.
pub(crate) fn scripted(configure: impl FnOnce(ClientBuilder) -> ClientBuilder) -> (Client, Script) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let live = Arc::new(AtomicIsize::new(0));
    let c = counted_client(
        move |req, s| {
            let tx = tx.clone();
            async move {
                let _ = tx.send((req, s));
            }
        },
        configure,
        live.clone(),
    );
    (c, Script(rx, live))
}

impl Script {
    /// How many of the client's streams are open now.
    pub(crate) fn live(&self) -> isize {
        self.1.load(Ordering::SeqCst)
    }

    /// Waits up to 8 s for `want` open client streams; returns how many
    /// there are.
    pub(crate) async fn settle(&self, want: isize) -> isize {
        for _ in 0..400 {
            if self.live() == want {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.live()
    }

    /// The next request, which must be to `endpoint`.
    pub(crate) async fn next(&mut self, endpoint: &str) -> (Req, DuplexStream) {
        let got = tokio::time::timeout(std::time::Duration::from_secs(10), self.0.recv())
            .await
            .expect("a request in time")
            .expect("the client is gone");
        assert_eq!(got.0.endpoint(), endpoint, "{:?}", got.0);
        got
    }

    /// No request comes within `d`.
    pub(crate) async fn none_within(&mut self, d: std::time::Duration) {
        if let Ok(Some((req, _))) = tokio::time::timeout(d, self.0.recv()).await {
            panic!("an unexpected request: {req:?}");
        }
    }
}

/// Holds a stream open until the client leaves.
pub(crate) async fn hold(mut s: DuplexStream) {
    let mut buf = [0u8; 4096];
    while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
}

/// The client's end of a pipe, counted while it is open.
struct Counted(DuplexStream, Arc<AtomicIsize>);

impl Counted {
    fn new(s: DuplexStream, live: Arc<AtomicIsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Counted(s, live)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.1.fetch_sub(1, Ordering::SeqCst);
    }
}

impl tokio::io::AsyncRead for Counted {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Counted {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
