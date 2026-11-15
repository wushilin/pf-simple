//! What travels on protocol 3's streams before the frames: the messages
//! (PROTOCOL.md §13.4), the discovery answer (§13.2), and the error codes
//! (§13.7).

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The one ALPN protocol of the hub's QUIC listener (§13.3).
pub const ALPN: &[u8] = b"pf-tunnel";

/// The longest message, in bytes, after its 2-byte length.
pub const MAX_MESSAGE: usize = 4096;

/// Error codes on RESET_STREAM, STOP_SENDING and CONNECTION_CLOSE (§13.7).
/// They are for logs: nothing is decided from them.
pub mod code {
    pub const NONE: u32 = 0x0;
    pub const BROKEN: u32 = 0x1;
    pub const REFUSED: u32 = 0x2;
    pub const PROTOCOL: u32 = 0x3;
    pub const REQUEST_TIMEOUT: u32 = 0x4;
    pub const CANCELLED: u32 = 0x5;
    pub const GOING_AWAY: u32 = 0x6;
    pub const LIMIT: u32 = 0x7;
}

/// The ends of a registration, in the hub's `end` message (§13.4).
pub const END_TAKEOVER: &str = "takeover";

/// A client's request on a stream it opens.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Request {
    pub op: &'static str,
    pub proto: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub word: String,
    #[serde(rename = "serveToken", skip_serializing_if = "Option::is_none")]
    pub serve_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "clientTokenSHA256", skip_serializing_if = "Option::is_none")]
    pub client_token_sha256: Option<String>,
    #[serde(rename = "clientToken", skip_serializing_if = "Option::is_none")]
    pub client_token: Option<String>,
}

/// The hub's answer to a request.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Answer {
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub proto: u32,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub reg: String,
    #[serde(default)]
    pub conn: String,
    #[serde(default)]
    pub scope: String,
}

/// The serving side's answer to an open.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OpenAnswer<'a> {
    pub status: u16,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub error: &'a str,
}

/// The hub's first message on a stream it opens to a serving side.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Open {
    #[serde(default)]
    pub open: String,
    #[serde(default)]
    pub reg: String,
}

/// The hub's last message on a serve stream.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct End {
    #[serde(default)]
    pub end: String,
    #[serde(default)]
    pub error: String,
}

/// What went wrong reading a message.
#[derive(Debug)]
pub(crate) enum MsgError {
    /// The stream's FIN before the message began.
    Fin,
    /// Too long, cut short, or not a JSON object: the peer broke the
    /// protocol.
    Malformed,
    Io(io::Error),
}

impl std::fmt::Display for MsgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MsgError::Fin => f.write_str("the stream ended"),
            MsgError::Malformed => f.write_str("a malformed message"),
            MsgError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Encodes `v` as one message: a 2-byte big-endian length, then JSON.
pub(crate) fn encode_message<T: Serialize>(v: &T) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(v).map_err(io::Error::other)?;
    if body.len() > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a message over 4096 bytes"));
    }
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Writes one message.
pub(crate) async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T) -> io::Result<()> {
    w.write_all(&encode_message(v)?).await?;
    w.flush().await
}

/// Reads one message without decoding it, reading exactly its bytes and
/// nothing after, so the frames that follow are left on the stream.
pub(crate) async fn read_raw<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, MsgError> {
    let mut len = [0u8; 2];
    match r.read(&mut len[..1]).await {
        Ok(0) => return Err(MsgError::Fin),
        Ok(_) => {}
        Err(e) => return Err(MsgError::Io(e)),
    }
    read_rest(r, &mut len[1..]).await?;
    let size = usize::from(u16::from_be_bytes(len));
    if size > MAX_MESSAGE {
        return Err(MsgError::Malformed);
    }
    let mut body = vec![0u8; size];
    read_rest(r, &mut body).await?;
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(MsgError::Malformed);
    }
    Ok(body)
}

async fn read_rest<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), MsgError> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(MsgError::Malformed),
        Err(e) => Err(MsgError::Io(e)),
    }
}

/// Reads one message as `T`.
pub(crate) async fn read_message<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<T, MsgError> {
    let body = read_raw(r).await?;
    serde_json::from_slice(&body).map_err(|_| MsgError::Malformed)
}

/// The answer of `GET /pf/api/tunnel/quic` (§13.2).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Discovery {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

impl Discovery {
    /// What is wrong with a discovery answer, if anything.
    pub(crate) fn check(&self) -> Result<(), String> {
        if self.host.is_empty() || self.host.contains(['[', ']', '/', ' ']) {
            return Err(format!("the hub advertised a bad QUIC host {:?}", self.host));
        }
        if !(1..=65535).contains(&self.port) {
            return Err(format!("the hub advertised a bad QUIC port {}", self.port));
        }
        if self.fingerprints.is_empty() || self.fingerprints.len() > 4 {
            return Err("the hub advertised no usable certificate fingerprints".into());
        }
        for f in &self.fingerprints {
            if f.len() != 64 || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("the hub advertised a bad certificate fingerprint {f:?}"));
            }
        }
        Ok(())
    }

    /// The fingerprints as bytes.
    pub(crate) fn pins(&self) -> Vec<[u8; 32]> {
        self.fingerprints
            .iter()
            .filter_map(|f| hex::decode(f.to_ascii_lowercase()).ok()?.try_into().ok())
            .collect()
    }
}

/// Keeps printable ASCII, cut to `max`, as reasons travel (§6.6).
pub(crate) fn clean_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| (' '..='~').contains(c)).take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_encode_as_the_spec_says() {
        let r = Request {
            op: "connect",
            proto: "3".into(),
            version: "pfrelay-quic-rs test".into(),
            word: "k3f9-x2mq-7hpa".into(),
            client_token: Some("secret".into()),
            ..Request::default()
        };
        let m = encode_message(&r).unwrap();
        let len = u16::from_be_bytes([m[0], m[1]]) as usize;
        assert_eq!(len, m.len() - 2);
        let v: serde_json::Value = serde_json::from_slice(&m[2..]).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"op":"connect","proto":"3","version":"pfrelay-quic-rs test","word":"k3f9-x2mq-7hpa","clientToken":"secret"})
        );
        let s = Request {
            op: "serve",
            proto: "3".into(),
            serve_token: Some("t".into()),
            name: Some("Mon service é".into()),
            target: Some("listener".into()),
            client_token_sha256: Some("ab".into()),
            ..Request::default()
        };
        let v: serde_json::Value = serde_json::from_slice(&encode_message(&s).unwrap()[2..]).unwrap();
        assert_eq!(v["serveToken"], "t");
        assert_eq!(v["name"], "Mon service é", "plain UTF-8, not escaped");
        assert_eq!(v["clientTokenSHA256"], "ab");
        assert!(v.get("clientToken").is_none());
    }

    #[test]
    fn messages_are_bounded() {
        let big = serde_json::json!({"x": "a".repeat(5000)});
        assert!(encode_message(&big).is_err());
    }

    #[tokio::test]
    async fn reading_messages() {
        let mut wire = encode_message(&serde_json::json!({"status":200,"proto":3,"reg":"5b2d4e8f1a6c9b0d","new":1})).unwrap();
        wire.extend_from_slice(&[0, 0, 1, b'x']); // a frame after it
        let mut r = &wire[..];
        let a: Answer = read_message(&mut r).await.unwrap();
        assert_eq!((a.status, a.proto, a.reg.as_str()), (200, 3, "5b2d4e8f1a6c9b0d"));
        assert_eq!(r, &[0, 0, 1, b'x'], "nothing after the message is read");

        let mut empty: &[u8] = &[];
        assert!(matches!(read_raw(&mut empty).await, Err(MsgError::Fin)));
        let mut cut: &[u8] = &[0, 10, b'{'];
        assert!(matches!(read_raw(&mut cut).await, Err(MsgError::Malformed)));
        let mut half: &[u8] = &[0];
        assert!(matches!(read_raw(&mut half).await, Err(MsgError::Malformed)));
        let mut long: &[u8] = &[0x10, 0x01];
        assert!(matches!(read_raw(&mut long).await, Err(MsgError::Malformed)));
        let arr = encode_message(&serde_json::json!([1])).unwrap();
        assert!(matches!(read_raw(&mut &arr[..]).await, Err(MsgError::Malformed)));
    }

    #[test]
    fn discovery_answers() {
        let fp = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let ok: Discovery =
            serde_json::from_str(&format!(r#"{{"host":"2001:db8::1","port":443,"fingerprints":["{fp}"],"more":true}}"#)).unwrap();
        assert!(ok.check().is_ok());
        assert_eq!(ok.pins().len(), 1);
        for bad in [
            format!(r#"{{"host":"","port":443,"fingerprints":["{fp}"]}}"#),
            format!(r#"{{"host":"[::1]","port":443,"fingerprints":["{fp}"]}}"#),
            format!(r#"{{"host":"h","port":0,"fingerprints":["{fp}"]}}"#),
            format!(r#"{{"host":"h","port":65536,"fingerprints":["{fp}"]}}"#),
            r#"{"host":"h","port":1,"fingerprints":[]}"#.to_string(),
            r#"{"host":"h","port":1,"fingerprints":["abc"]}"#.to_string(),
            format!(r#"{{"host":"h","port":1,"fingerprints":["{fp}","{fp}","{fp}","{fp}","{fp}"]}}"#),
        ] {
            let d: Discovery = serde_json::from_str(&bad).unwrap();
            assert!(d.check().is_err(), "{bad}");
        }
    }

    #[test]
    fn reasons_are_cleaned() {
        assert_eq!(clean_text("a\x07b\u{e9}c", 128), "abc");
        assert_eq!(clean_text(&"x".repeat(300), 128).len(), 128);
    }
}
