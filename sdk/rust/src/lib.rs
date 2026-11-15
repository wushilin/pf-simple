//! The Rust SDK for the pf-simple relay hub: serve a tunnel, or connect
//! through one, from your own program.
//!
//! The protocol is described in `docs/PROTOCOL.md` of the pf-simple
//! repository. This crate speaks tunnel protocols 0 and 1.
//!
//! ```no_run
//! # async fn demo() -> pfrelay::Result<()> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! // The serving side.
//! let server = pfrelay::Client::builder("https://hub.example/", "k3f9-x2mq-7hpa")
//!     .serve_token("0123456789abcdef0123456789abcdef")
//!     .name("My service")
//!     .build()?;
//! let listener = server.listen().await?;
//! tokio::spawn(async move {
//!     while let Ok(mut conn) = listener.accept().await {
//!         tokio::spawn(async move {
//!             let mut buf = Vec::new();
//!             let _ = conn.read_to_end(&mut buf).await;
//!             let _ = conn.write_all(&buf).await;
//!             let _ = conn.close().await;
//!         });
//!     }
//! });
//!
//! // The connecting side.
//! let client = pfrelay::Client::builder("https://hub.example/", "k3f9-x2mq-7hpa").build()?;
//! let mut conn = client.dial().await?;
//! conn.write_all(b"hello").await?;
//! conn.shutdown().await?; // half-close
//! let mut answer = Vec::new();
//! conn.read_to_end(&mut answer).await?;
//! conn.close().await?;
//! # Ok(()) }
//! ```

mod client;
mod conn;
mod error;
mod events;
mod forward;
mod http;
mod listener;
mod proto;
mod reuse;
mod values;
mod ws;

pub use client::{Client, ClientBuilder, ServerInfo, Timing, DEFAULT_AGENT, DEFAULT_MAX_IDLE_LEGS, DEFAULT_NAME};
pub use events::{ConnId, Events};
pub use conn::{Conn, ConnInfo, Side, Stats, LINK_SILENCE, PING_EVERY};
pub use forward::{TARGET_DIAL_TIMEOUT, TARGET_UNREACHABLE};
pub use error::{Error, ProtoError, RemoteError, Result};
pub use listener::{Listener, CONTROL_PING, CONTROL_SILENCE, LISTEN_BACKLOG};
pub use proto::{negotiate, parse_proto_range, proto_range, server_proto, Feature, ProtoLimit, PROTO_MAX, PROTO_MIN};
pub use reuse::REASON_LEG_LOST;
pub use values::{check_client_token, check_name, check_serve_token, new_word, normalize_word, query_escape};

/// The target a serving side names when it offers stdin/stdout instead of a
/// TCP port.
pub const STDIO_TARGET: &str = "stdio";

/// Re-exported so a TLS configuration can be built without depending on
/// rustls directly.
pub use tokio_rustls::rustls;

#[cfg(test)]
mod testhub;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod reuse_tests;
#[cfg(test)]
mod leak_tests;
