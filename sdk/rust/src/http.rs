//! HTTP/1.1 over TLS, just enough for the hub's endpoints: a WebSocket
//! upgrade, and a plain GET.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rand::Rng;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};
use crate::values::Base;

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const HANDSHAKE_LIMIT: Duration = Duration::from_secs(15);
const MAX_HEAD: usize = 16 << 10;
const MAX_BODY: usize = 4096;

pub(crate) type Tls = TlsStream<TcpStream>;

/// What a WebSocket runs over: TLS to the hub, or a pipe in tests.
pub(crate) use crate::transport::Stream;

/// Opens a stream to the hub: TLS over TCP, or a pipe to a fake hub in
/// tests.
pub(crate) type Connector =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Stream>> + Send>> + Send + Sync>;

/// The connector to a real hub.
pub(crate) fn tls_connector(base: Base, tls: Arc<ClientConfig>) -> Connector {
    Arc::new(move || {
        let (base, tls) = (base.clone(), tls.clone());
        Box::pin(async move { Ok(Box::new(connect_tls(&base, &tls).await?) as Stream) })
    })
}

/// A response's status and headers.
#[derive(Debug, Default)]
pub(crate) struct Head {
    pub status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    /// The first value of a header; names are case-insensitive.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A WebSocket that the hub accepted: the TLS stream, and what was read
/// past the 101.
pub(crate) struct Upgraded {
    pub stream: Stream,
    pub leftover: Vec<u8>,
    pub head: Head,
}

/// What a request came back with.
pub(crate) enum Answer {
    Upgraded(Box<Upgraded>),
    /// Anything but a 101 to an upgrade, or the answer to a plain GET.
    Plain { head: Head, body: Vec<u8> },
}

pub(crate) async fn connect_tls(base: &Base, tls: &Arc<ClientConfig>) -> Result<Tls> {
    let tcp = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect((base.host.as_str(), base.port)))
        .await
        .map_err(|_| Error::Link(format!("cannot reach {}: timed out", base.url())))?
        .map_err(|e| Error::Link(format!("cannot reach {}: {e}", base.url())))?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(base.host.clone())
        .map_err(|e| Error::Config(format!("invalid server name {:?}: {e}", base.host)))?;
    TlsConnector::from(tls.clone())
        .connect(name, tcp)
        .await
        .map_err(|e| match e.get_ref() {
            Some(inner) => Error::Tls(inner.to_string()),
            None => Error::Tls(e.to_string()),
        })
}

/// Sends a request to `path` with `headers`, as a WebSocket upgrade or as
/// a plain GET, and reads the answer, all within the handshake limit.
pub(crate) async fn request(
    base: &Base,
    connect: &Connector,
    path: &str,
    headers: &[(&str, String)],
    upgrade: bool,
) -> Result<Answer> {
    tokio::time::timeout(HANDSHAKE_LIMIT, request_inner(base, connect, path, headers, upgrade))
        .await
        .map_err(|_| Error::Link(format!("{} did not answer in time", base.url())))?
}

async fn request_inner(
    base: &Base,
    connect: &Connector,
    path: &str,
    headers: &[(&str, String)],
    upgrade: bool,
) -> Result<Answer> {
    let mut stream = connect().await?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\n", base.authority);
    for (name, value) in headers {
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(Error::Config(format!("the value of {name} may not contain line breaks")));
        }
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    let key = if upgrade {
        let nonce: [u8; 16] = rand::rng().random();
        let key = base64::engine::general_purpose::STANDARD.encode(nonce);
        req.push_str(&format!(
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        ));
        Some(key)
    } else {
        req.push_str("Connection: close\r\n");
        None
    };
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.map_err(link)?;
    stream.flush().await.map_err(link)?;

    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(Error::Protocol("the server's response headers are too long".into()));
        }
        let n = stream.read_buf(&mut buf).await.map_err(link)?;
        if n == 0 {
            return Err(Error::Link("the server closed the connection before answering".into()));
        }
    };
    let head = parse_head(&buf[..head_end])?;
    let rest = buf.split_off(head_end);

    if let (Some(key), 101) = (&key, head.status) {
        if head.get("Sec-WebSocket-Accept") != Some(crate::ws::accept_key(key).as_str()) {
            return Err(Error::Protocol("the server's websocket handshake is invalid".into()));
        }
        return Ok(Answer::Upgraded(Box::new(Upgraded { stream, leftover: rest, head })));
    }
    let body = read_body(&mut stream, &head, rest).await;
    Ok(Answer::Plain { head, body })
}

fn link(e: std::io::Error) -> Error {
    Error::Link(format!("the link to the server failed ({e})"))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn parse_head(raw: &[u8]) -> Result<Head> {
    let text = std::str::from_utf8(raw).map_err(|_| Error::Protocol("the server's response is not text".into()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let status = parts.next().and_then(|s| s.parse::<u16>().ok());
    let status = match (version.starts_with("HTTP/1."), status) {
        (true, Some(s)) => s,
        _ => return Err(Error::Protocol(format!("not an HTTP/1.1 response: {status_line:?}"))),
    };
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(Head { status, headers })
}

/// Reads up to MAX_BODY of a response body: by its length, chunked, or up
/// to the end of the connection. Whatever fails just ends the body.
async fn read_body(stream: &mut Stream, head: &Head, mut buf: Vec<u8>) -> Vec<u8> {
    if head.status == 204 || head.status == 304 || (100..200).contains(&head.status) {
        return Vec::new();
    }
    let chunked = head.get("Transfer-Encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = head.get("Content-Length").and_then(|v| v.parse::<usize>().ok());
    let want = |buf: &Vec<u8>| -> bool {
        if let Some(n) = length {
            return buf.len() < n.min(MAX_BODY);
        }
        if chunked {
            return dechunk(buf).is_none() && buf.len() < MAX_BODY + 1024;
        }
        buf.len() < MAX_BODY
    };
    while want(&buf) {
        match tokio::time::timeout(Duration::from_secs(5), stream.read_buf(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => break,
        }
    }
    let mut body = if chunked { dechunk(&buf).unwrap_or_default() } else { buf };
    if let Some(n) = length {
        body.truncate(n);
    }
    body.truncate(MAX_BODY);
    body
}

/// Decodes a complete chunked body, or `None` while it is incomplete.
fn dechunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = find(raw, b"\r\n")?;
        let size_text = std::str::from_utf8(&raw[..eol]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        raw = &raw[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if raw.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
        if out.len() > MAX_BODY {
            return Some(out);
        }
    }
}

/// The message of an error response: the hub's `{"error": "..."}`, or a
/// short plain-text body, or nothing.
pub(crate) fn error_text(body: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(e) = v.get("error").and_then(|e| e.as_str()).filter(|e| !e.is_empty()) {
            return e.to_string();
        }
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.len() < 200 && !text.contains('<') {
        return text.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads() {
        let h = parse_head(b"HTTP/1.1 101 Switching Protocols\r\nX-Pf-Tunnel-Proto: 1\r\nX-PF-Tunnel-Conn:  abc \r\n\r\n").unwrap();
        assert_eq!(h.status, 101);
        assert_eq!(h.get("x-pf-tunnel-proto"), Some("1"));
        assert_eq!(h.get("X-PF-Tunnel-Conn"), Some("abc"));
        assert!(parse_head(b"SSH-2.0\r\n\r\n").is_err());
    }

    #[test]
    fn bodies() {
        assert_eq!(dechunk(b"5\r\nhello\r\n0\r\n\r\n").unwrap(), b"hello");
        assert!(dechunk(b"5\r\nhel").is_none());
        assert_eq!(error_text(br#"{"error":"word bound to another tenant"}"#), "word bound to another tenant");
        assert_eq!(error_text(b" plain refusal \n"), "plain refusal");
        assert_eq!(error_text(b"<html>no</html>"), "");
        assert_eq!(error_text(b""), "");
    }
}
