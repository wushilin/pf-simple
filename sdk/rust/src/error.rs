//! Errors of the SDK.

use std::fmt;
use std::io;

use crate::proto::Feature;

/// The reason the far end (the other client, or the hub) gave for dropping
/// a connection, as it arrived in an `err:` frame. It is cleaned before it
/// is stored: unprintable characters are stripped and it is cut to 200
/// characters (PROTOCOL.md §8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError {
    pub reason: String,
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for RemoteError {}

/// A hub that is too old for something this run depends on
/// (PROTOCOL.md §5.3). Waiting or retrying cannot help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError {
    /// The protocol the hub speaks (0 when it announces none).
    pub server: u32,
    /// What was asked for.
    pub need: Feature,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let speaks = if self.server == 0 {
            "it announces no tunnel protocol".to_string()
        } else {
            format!("it speaks tunnel protocol {}", self.server)
        };
        write!(
            f,
            "this server is too old for {}: {}, and that needs protocol {} (pf-simple {} or later). Upgrade the server, or do without it",
            self.need.name(),
            speaks,
            self.need.proto(),
            crate::proto::release_of(self.need.proto()),
        )
    }
}

impl std::error::Error for ProtoError {}

/// Everything that can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A setting of the client is not acceptable (PROTOCOL.md §2, §3).
    #[error("{0}")]
    Config(String),
    /// The hub refused a token or a word (403).
    #[error("access denied")]
    AccessDenied,
    /// The hub (or a proxy in front of it) refused the request with this
    /// status; `message` is the hub's `error` field, or a short plain-text
    /// body, or empty.
    #[error("{}", status_text(*.code, .message))]
    Status { code: u16, message: String },
    /// The server answered 404 with an empty body: no relay hub there.
    #[error("this server does not accept tunnels (its relay hub is off, or not configured)")]
    NoRelay,
    /// The server does not answer a version probe.
    #[error("this server does not answer a version probe: it is older than pf-simple 0.14.0, or its relay hub is off")]
    NoProbe,
    /// The hub is too old for what was asked.
    #[error(transparent)]
    Proto(#[from] ProtoError),
    /// The far end or the hub dropped the connection, and said why.
    #[error(transparent)]
    Remote(#[from] RemoteError),
    /// This side dropped the connection, with [`Conn::fail`](crate::Conn::fail)
    /// or [`Client::drop_conn`](crate::Client::drop_conn).
    #[error("dropped by this side: {reason}")]
    Dropped { reason: String },
    /// The link to the hub broke: it closed, went silent, or reset.
    #[error("{0}")]
    Link(String),
    /// The hub answered something that is not the protocol.
    #[error("{0}")]
    Protocol(String),
    /// TLS failed (a certificate that does not verify, for instance).
    #[error("TLS: {0}")]
    Tls(String),
    /// The listener or connection was closed by this side.
    #[error("closed")]
    Closed,
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn status_text(code: u16, message: &str) -> String {
    if message.is_empty() {
        format!("the server answered {code}")
    } else {
        format!("{message} ({code})")
    }
}

impl Error {
    /// Whether retrying cannot help (PROTOCOL.md §9): a 4xx refusal other
    /// than 408 and 429, a protocol error, or a bad setting.
    pub fn is_final(&self) -> bool {
        match self {
            Error::Config(_) | Error::AccessDenied | Error::NoRelay | Error::Proto(_) => true,
            Error::Status { code, .. } => (400..500).contains(code) && *code != 408 && *code != 429,
            _ => false,
        }
    }

    /// The status the hub answered with, for a refusal.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::AccessDenied => Some(403),
            Error::NoRelay => Some(404),
            Error::Status { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Turns an `io::Error` returned by a [`Conn`](crate::Conn)'s read or
    /// write back into the SDK's error, when it is one.
    pub fn from_io(err: &io::Error) -> Option<&Error> {
        err.get_ref().and_then(|e| e.downcast_ref::<Error>())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
