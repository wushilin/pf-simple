//! A minimal RFC 6455 client: the frames of PROTOCOL.md §7 and §8.

use std::io;
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

pub(crate) const OP_CONT: u8 = 0x0;
pub(crate) const OP_TEXT: u8 = 0x1;
pub(crate) const OP_BINARY: u8 = 0x2;
pub(crate) const OP_CLOSE: u8 = 0x8;
pub(crate) const OP_PING: u8 = 0x9;
pub(crate) const OP_PONG: u8 = 0xA;

/// What a sender puts in one data frame at most.
pub(crate) const CHUNK: usize = 64 << 10;
/// What a receiver accepts in one data frame at most.
pub(crate) const MAX_DATA_FRAME: u64 = 1 << 20;
/// Text frames on a stream.
pub(crate) const MAX_TEXT_FRAME: u64 = 1024;
/// Every frame on the control channel.
pub(crate) const MAX_CONTROL_FRAME: u64 = 4096;

/// One frame as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub fin: bool,
    pub op: u8,
    pub payload: Vec<u8>,
}

/// Limits on frames a reader accepts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub data: u64,
    pub text: u64,
}

pub(crate) const STREAM_LIMITS: Limits = Limits { data: MAX_DATA_FRAME, text: MAX_TEXT_FRAME };
pub(crate) const CONTROL_LIMITS: Limits = Limits { data: MAX_CONTROL_FRAME, text: MAX_CONTROL_FRAME };

fn violation(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Encodes one frame as a client sends it: FIN set, masked.
pub(crate) fn encode_frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mask: [u8; 4] = rand::rng().random();
    encode_frame_with(op, payload, mask)
}

pub(crate) fn encode_frame_with(op: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let n = payload.len();
    let mut buf = Vec::with_capacity(n + 14);
    buf.push(0x80 | op);
    if n < 126 {
        buf.push(0x80 | n as u8);
    } else if n <= 0xFFFF {
        buf.push(0x80 | 126);
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        buf.push(0x80 | 127);
        buf.extend_from_slice(&(n as u64).to_be_bytes());
    }
    buf.extend_from_slice(&mask);
    let at = buf.len();
    buf.extend_from_slice(payload);
    for (i, b) in buf[at..].iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    buf
}

/// Parses one frame from the front of `buf`, as the hub sends it
/// (unmasked). `Ok(None)` means more bytes are needed; on success, returns
/// the frame and how many bytes it took.
pub(crate) fn parse_frame(buf: &[u8], limits: Limits) -> io::Result<Option<(Frame, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    if buf[0] & 0x70 != 0 {
        return Err(violation("a frame with RSV bits set"));
    }
    let op = buf[0] & 0x0F;
    if buf[1] & 0x80 != 0 {
        return Err(violation("a masked frame from the server"));
    }
    let mut at = 2;
    let mut len = u64::from(buf[1] & 0x7F);
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
        at = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        len = u64::from_be_bytes(buf[2..10].try_into().unwrap());
        at = 10;
    }
    let max = match op {
        OP_BINARY | OP_CONT => limits.data,
        OP_TEXT => limits.text,
        OP_CLOSE | OP_PING | OP_PONG => {
            if !fin {
                return Err(violation("a fragmented control frame"));
            }
            125
        }
        _ => return Err(violation("a frame with an unknown opcode")),
    };
    if len > max {
        return Err(violation("frame too large"));
    }
    let end = at + len as usize;
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some((Frame { fin, op, payload: buf[at..end].to_vec() }, end)))
}

/// Reads frames. `next` is cancel-safe: what was read stays in the buffer.
pub(crate) struct FrameReader<R> {
    rd: R,
    buf: Vec<u8>,
    limits: Limits,
    /// None: no silence limit (a QUIC stream, kept alive by its connection).
    silence: Option<Duration>,
    last: Instant,
    /// Protocol 3's framing (PROTOCOL.md §13.5) instead of WebSocket frames.
    framed: bool,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// `leftover` is what was read past the handshake's response.
    pub(crate) fn new(rd: R, leftover: Vec<u8>, limits: Limits, silence: Duration) -> Self {
        FrameReader { rd, buf: leftover, limits, silence: Some(silence), last: Instant::now(), framed: false }
    }

    /// A reader of protocol 3 frames on a QUIC stream, after its request
    /// and answer. Each frame comes back as the WebSocket frame it stands
    /// for: data as binary, `eof` and `err` as text, and the stream's FIN
    /// at a frame boundary as a close. There is no silence limit: QUIC
    /// keeps the connection alive, not the stream.
    pub(crate) fn framed(rd: R) -> Self {
        FrameReader { rd, buf: Vec::new(), limits: STREAM_LIMITS, silence: None, last: Instant::now(), framed: true }
    }

    pub(crate) fn is_framed(&self) -> bool {
        self.framed
    }

    /// The next frame. A link that stays silent for the reader's silence
    /// limit is an error of kind `TimedOut`; one that ends is `UnexpectedEof`.
    pub(crate) async fn next(&mut self) -> io::Result<Frame> {
        loop {
            let parsed = if self.framed { parse_framed(&self.buf)? } else { parse_frame(&self.buf, self.limits)?.map(|(f, n)| (Some(f), n)) };
            if let Some((frame, used)) = parsed {
                self.buf.drain(..used);
                match frame {
                    Some(f) => return Ok(f),
                    None => continue, // an unknown framed type, skipped
                }
            }
            self.buf.reserve(16 << 10);
            let read = match self.silence {
                Some(silence) => {
                    match tokio::time::timeout_at(self.last + silence, self.rd.read_buf(&mut self.buf)).await {
                        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "silent link")),
                        Ok(r) => r,
                    }
                }
                None => self.rd.read_buf(&mut self.buf).await,
            };
            match read {
                Ok(0) if self.framed && self.buf.is_empty() => {
                    // FIN at a frame boundary: the stream's close.
                    return Ok(Frame { fin: true, op: OP_CLOSE, payload: Vec::new() });
                }
                Ok(0) if self.framed => return Err(violation("the stream ended inside a frame")),
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => self.last = Instant::now(),
                Err(e) => return Err(e),
            }
        }
    }
}

// ---------- protocol 3's framing (PROTOCOL.md §13.5) ----------
//
//   type (1 byte)  length (2 bytes, big-endian)  payload
//   0x00 data      0 to 65535                    the next bytes
//   0x01 eof       0                             the sender's half-close
//   0x02 err       1 to 1024                     why the stream is dropped
//
// A framed stream maps one to one onto a WebSocket stream: data, "eof",
// "err:why", and the stream's FIN in place of the close frame.

pub(crate) const FRAME_DATA: u8 = 0x00;
pub(crate) const FRAME_EOF: u8 = 0x01;
pub(crate) const FRAME_ERR: u8 = 0x02;
/// The most data one framed data frame carries.
pub(crate) const MAX_FRAMED_DATA: usize = 0xFFFF;
/// The longest reason of a framed err.
pub(crate) const MAX_FRAMED_ERR: usize = 1024;
/// What an empty reason becomes: a framed err is never empty.
pub(crate) const NO_REASON: &str = "the peer gave no reason";

/// Parses one framed frame from the front of `buf`: `Ok(None)` when more
/// bytes are needed; `Some((None, n))` for an unknown type, skipped by its
/// length.
pub(crate) fn parse_framed(buf: &[u8]) -> io::Result<Option<(Option<Frame>, usize)>> {
    if buf.len() < 3 {
        return Ok(None);
    }
    let (typ, len) = (buf[0], usize::from(u16::from_be_bytes([buf[1], buf[2]])));
    match typ {
        FRAME_EOF if len != 0 => return Err(violation("an eof frame with a payload")),
        FRAME_ERR if len == 0 || len > MAX_FRAMED_ERR => return Err(violation("an err frame of a bad length")),
        _ => {}
    }
    if buf.len() < 3 + len {
        return Ok(None);
    }
    let payload = &buf[3..3 + len];
    let frame = match typ {
        FRAME_DATA => Some(Frame { fin: true, op: OP_BINARY, payload: payload.to_vec() }),
        FRAME_EOF => Some(Frame { fin: true, op: OP_TEXT, payload: b"eof".to_vec() }),
        FRAME_ERR => {
            let mut text = b"err:".to_vec();
            text.extend_from_slice(payload);
            Some(Frame { fin: true, op: OP_TEXT, payload: text })
        }
        _ => None,
    };
    Ok(Some((frame, 3 + len)))
}

/// Encodes one framed frame.
pub(crate) fn encode_framed(typ: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + payload.len());
    buf.push(typ);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// The reason of an `err:` text, never empty, cut at a UTF-8 boundary to
/// fit a framed err.
pub(crate) fn framed_reason(text: &[u8]) -> Option<String> {
    let reason = text.strip_prefix(b"err:")?;
    let mut reason = String::from_utf8_lossy(reason).into_owned();
    if reason.is_empty() {
        reason = NO_REASON.to_string();
    }
    if reason.len() > MAX_FRAMED_ERR {
        let mut cut = MAX_FRAMED_ERR;
        while !reason.is_char_boundary(cut) {
            cut -= 1;
        }
        reason.truncate(cut);
    }
    Some(reason)
}

/// Writes what a WebSocket frame `op` says, in protocol 3's framing: data
/// in frames of at most 65535 bytes, `eof` and `err:` as their frames, a
/// close as the stream's FIN. Pings, pongs and other text are not said on a
/// framed stream: QUIC keeps the connection alive.
pub(crate) async fn write_framed<W: AsyncWrite + Unpin>(w: &mut W, op: u8, payload: &[u8]) -> io::Result<()> {
    match op {
        OP_BINARY | OP_CONT => {
            let mut buf = Vec::with_capacity(payload.len() + 3 * (payload.len() / MAX_FRAMED_DATA + 1));
            let mut chunks = payload.chunks(MAX_FRAMED_DATA).peekable();
            if chunks.peek().is_none() {
                return Ok(()); // an empty data frame carries nothing
            }
            for c in chunks {
                buf.extend_from_slice(&encode_framed(FRAME_DATA, c));
            }
            w.write_all(&buf).await?;
            w.flush().await
        }
        OP_TEXT if payload == b"eof" => {
            w.write_all(&encode_framed(FRAME_EOF, &[])).await?;
            w.flush().await
        }
        OP_TEXT => match framed_reason(payload) {
            Some(reason) => {
                w.write_all(&encode_framed(FRAME_ERR, reason.as_bytes())).await?;
                w.flush().await
            }
            None => Ok(()),
        },
        OP_CLOSE => w.shutdown().await,
        _ => Ok(()),
    }
}

/// Writes one frame.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, op: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&encode_frame(op, payload)).await?;
    w.flush().await
}

/// The `Sec-WebSocket-Accept` the hub must answer `key` with.
pub(crate) fn accept_key(key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unmask(frame: &[u8]) -> (u8, Vec<u8>) {
        assert_eq!(frame[0] & 0x80, 0x80, "FIN");
        assert_eq!(frame[1] & 0x80, 0x80, "masked");
        let (len, at) = match frame[1] & 0x7F {
            126 => (u16::from_be_bytes([frame[2], frame[3]]) as usize, 4),
            127 => (u64::from_be_bytes(frame[2..10].try_into().unwrap()) as usize, 10),
            n => (n as usize, 2),
        };
        let mask = &frame[at..at + 4];
        let body: Vec<u8> = frame[at + 4..].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        assert_eq!(body.len(), len);
        (frame[0] & 0x0F, body)
    }

    #[test]
    fn encodes_masked_frames() {
        for n in [0usize, 1, 125, 126, 127, 65535, 65536, 70000] {
            let payload: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let f = encode_frame(OP_BINARY, &payload);
            let (op, body) = unmask(&f);
            assert_eq!(op, OP_BINARY);
            assert_eq!(body, payload, "length {n}");
        }
        let f = encode_frame_with(OP_TEXT, b"eof", [1, 2, 3, 4]);
        assert_eq!(f, vec![0x81, 0x83, 1, 2, 3, 4, b'e' ^ 1, b'o' ^ 2, b'f' ^ 3]);
    }

    fn server_frame(b0: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![b0];
        let n = payload.len();
        if n < 126 {
            out.push(n as u8);
        } else if n <= 0xFFFF {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_server_frames() {
        let mut wire = server_frame(0x82, &[7; 300]);
        wire.extend(server_frame(0x81, b"eof"));
        let (f, used) = parse_frame(&wire, STREAM_LIMITS).unwrap().unwrap();
        assert_eq!((f.op, f.fin, f.payload.len()), (OP_BINARY, true, 300));
        let (f, _) = parse_frame(&wire[used..], STREAM_LIMITS).unwrap().unwrap();
        assert_eq!((f.op, f.payload.as_slice()), (OP_TEXT, &b"eof"[..]));
        // incomplete
        for cut in [0, 1, 3, 100] {
            assert!(parse_frame(&wire[..cut], STREAM_LIMITS).unwrap().is_none());
        }
        let big = server_frame(0x82, &vec![0; 70000]);
        assert_eq!(parse_frame(&big, STREAM_LIMITS).unwrap().unwrap().0.payload.len(), 70000);
    }

    #[test]
    fn refuses_bad_frames() {
        // masked from the server
        assert!(parse_frame(&[0x82, 0x81, 0, 0, 0, 0, 1], STREAM_LIMITS).is_err());
        // RSV bits
        assert!(parse_frame(&[0xC2, 0x00], STREAM_LIMITS).is_err());
        // too large: a text frame over 1024, a data frame over 1 MiB
        assert!(parse_frame(&server_frame(0x81, &[b'a'; 1025]), STREAM_LIMITS).is_err());
        let mut huge = vec![0x82, 127];
        huge.extend_from_slice(&((1u64 << 20) + 1).to_be_bytes());
        assert!(parse_frame(&huge, STREAM_LIMITS).is_err());
        assert!(parse_frame(&server_frame(0x82, &[0; 5000]), CONTROL_LIMITS).is_err());
        // fragmented ping
        assert!(parse_frame(&[0x09, 0x00], STREAM_LIMITS).is_err());
        // unknown opcode
        assert!(parse_frame(&[0x83, 0x00], STREAM_LIMITS).is_err());
    }

    #[tokio::test]
    async fn reader_reports_silence() {
        let (client, _server) = tokio::io::duplex(64);
        let mut r = FrameReader::new(client, Vec::new(), STREAM_LIMITS, Duration::from_millis(50));
        let err = r.next().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn reader_uses_leftover_and_stream() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let first = server_frame(0x81, br#"{"open":"8f14e45fceea167a"}"#);
        let second = server_frame(0x82, b"hello");
        let mut r = FrameReader::new(client, first, CONTROL_LIMITS, Duration::from_secs(5));
        server.write_all(&second[..3]).await.unwrap();
        let f = r.next().await.unwrap();
        assert_eq!(f.op, OP_TEXT);
        server.write_all(&second[3..]).await.unwrap();
        let f = r.next().await.unwrap();
        assert_eq!(f.payload, b"hello");
        drop(server);
        assert_eq!(r.next().await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn framed_frames() {
        assert_eq!(encode_framed(FRAME_DATA, b"hi"), vec![0, 0, 2, b'h', b'i']);
        assert_eq!(encode_framed(FRAME_EOF, b""), vec![1, 0, 0]);
        let mut wire = encode_framed(FRAME_DATA, &[7; 300]);
        wire.extend(encode_framed(0x7F, b"unknown, skipped"));
        wire.extend(encode_framed(FRAME_EOF, b""));
        wire.extend(encode_framed(FRAME_ERR, b"why"));
        let (f, used) = parse_framed(&wire).unwrap().unwrap();
        let f = f.unwrap();
        assert_eq!((f.op, f.payload.len()), (OP_BINARY, 300));
        let rest = &wire[used..];
        let (f, used2) = parse_framed(rest).unwrap().unwrap();
        assert!(f.is_none(), "unknown types are skipped");
        let rest = &rest[used2..];
        let (f, used3) = parse_framed(rest).unwrap().unwrap();
        assert_eq!(f.unwrap().payload, b"eof");
        let (f, _) = parse_framed(&rest[used3..]).unwrap().unwrap();
        assert_eq!(f.unwrap().payload, b"err:why");
        for cut in [0, 1, 2, 3, 302] {
            assert!(parse_framed(&wire[..cut]).unwrap().is_none(), "{cut}");
        }
        assert!(parse_framed(&[1, 0, 1, 0]).is_err(), "eof with a payload");
        assert!(parse_framed(&[2, 0, 0]).is_err(), "empty err");
        assert!(parse_framed(&[2, 4, 1]).is_err(), "err over 1024");
        assert!(parse_framed(&encode_framed(FRAME_DATA, &[0; 65535])).unwrap().is_some());
    }

    #[test]
    fn framed_reasons() {
        assert_eq!(framed_reason(b"err:"), Some(NO_REASON.to_string()));
        assert_eq!(framed_reason(b"eof"), None);
        let long = format!("err:{}", "é".repeat(600));
        let r = framed_reason(long.as_bytes()).unwrap();
        assert!(r.len() <= MAX_FRAMED_ERR && r.len() >= MAX_FRAMED_ERR - 1);
    }

    #[tokio::test]
    async fn framed_writer_and_reader() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut w, r) = (a, b);
        let big = vec![9u8; 70_000];
        write_framed(&mut w, OP_BINARY, &big).await.unwrap();
        write_framed(&mut w, OP_PING, b"").await.unwrap();
        write_framed(&mut w, OP_TEXT, b"something else").await.unwrap();
        write_framed(&mut w, OP_TEXT, b"eof").await.unwrap();
        write_framed(&mut w, OP_TEXT, b"err:gone").await.unwrap();
        write_framed(&mut w, OP_CLOSE, b"").await.unwrap();
        let mut fr = FrameReader::framed(r);
        let a = fr.next().await.unwrap();
        let b = fr.next().await.unwrap();
        assert_eq!((a.op, a.payload.len(), b.op, b.payload.len()), (OP_BINARY, 65535, OP_BINARY, 70_000 - 65535));
        assert_eq!(fr.next().await.unwrap().payload, b"eof");
        assert_eq!(fr.next().await.unwrap().payload, b"err:gone");
        assert_eq!(fr.next().await.unwrap().op, OP_CLOSE, "FIN at a boundary is the close");
    }

    #[tokio::test]
    async fn framed_fin_inside_a_frame() {
        let (mut w, r) = tokio::io::duplex(64);
        w.write_all(&[0, 0, 5, b'a']).await.unwrap();
        drop(w);
        let mut fr = FrameReader::framed(r);
        assert_eq!(fr.next().await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn accept_key_matches_rfc() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
