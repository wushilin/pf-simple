//! The Rust SDK for the pf-simple relay hub over QUIC: tunnel protocol 3
//! (`docs/PROTOCOL.md` §13 of the pf-simple repository).
//!
//! It is [`pfrelay`] with another way to the hub. The client discovers the
//! hub's QUIC listener over the hub's HTTPS endpoint, pins its certificate
//! by the fingerprint that endpoint announced, and carries each request on a
//! stream of one QUIC connection. Everything else is pfrelay's: the same
//! [`Conn`], [`Listener`], [`Events`], [`Error`]s, retries and forwarders.
//! A QUIC side works with a WebSocket side through the same hub, in either
//! role.
//!
//! Moving a program from WebSocket to QUIC means building the client here:
//!
//! ```no_run
//! # async fn demo() -> pfrelay_quic::Result<()> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! let client = pfrelay_quic::Client::builder("https://hub.example/", "k3f9-x2mq-7hpa").build()?;
//! let mut conn = client.dial().await?;
//! conn.write_all(b"hello").await?;
//! conn.shutdown().await?; // half-close
//! let mut answer = Vec::new();
//! conn.read_to_end(&mut answer).await?;
//! conn.close().await?;
//! # Ok(()) }
//! ```
//!
//! There is no fallback: where UDP is blocked, this fails to connect, and
//! pfrelay (WebSocket) is the one to use.

use std::path::PathBuf;
use std::sync::Arc;

mod pin;
mod stream;
mod transport;
pub mod wire;

pub use pfrelay::{
    rustls as tls, Conn, ConnId, ConnInfo, Error, Events, Listener, RemoteError, Result, Side, Stats, Timing,
    DEFAULT_NAME, LISTEN_BACKLOG, STDIO_TARGET, TARGET_DIAL_TIMEOUT, TARGET_UNREACHABLE,
};
pub use pin::{fingerprint, IDLE_TIMEOUT, KEEP_ALIVE};
pub use stream::DELIVER_WAIT;
pub use transport::{ANSWER_WAIT, NO_QUIC, PIN_MISMATCH, REQUEST_WAIT};

/// The tunnel protocol this SDK speaks: protocol 3, which exists only over
/// QUIC. It works with clients of protocols 0 to 2 (WebSocket) through the
/// hub, which bridges the two.
pub const PROTO: u32 = 3;

/// What a [`Client`] calls itself in the hub's log and console unless told
/// otherwise.
pub const DEFAULT_AGENT: &str = concat!("pfrelay-quic-rs ", env!("CARGO_PKG_VERSION"));

/// Talks to one relay hub about one tunnel (one word), over QUIC.
///
/// It is a [`pfrelay::Client`] (it dereferences to one), so it has the same
/// methods: [`listen`](pfrelay::Client::listen),
/// [`serve_tcp`](pfrelay::Client::serve_tcp), [`dial`](pfrelay::Client::dial),
/// [`connect_tcp`](pfrelay::Client::connect_tcp),
/// [`check`](pfrelay::Client::check), [`watch`](pfrelay::Client::watch),
/// [`stats`](pfrelay::Client::stats) and the rest. `probe` asks the hub's
/// HTTPS endpoint, as version probes always do. Cloning it is cheap, and
/// clones share their QUIC connection.
#[derive(Clone)]
pub struct Client {
    inner: pfrelay::Client,
    quic: Arc<transport::Quic>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("pfrelay_quic::Client").field(&self.inner).finish()
    }
}

impl std::ops::Deref for Client {
    type Target = pfrelay::Client;
    fn deref(&self) -> &pfrelay::Client {
        &self.inner
    }
}

impl From<Client> for pfrelay::Client {
    fn from(c: Client) -> pfrelay::Client {
        c.inner
    }
}

impl Client {
    /// Starts building a client for the hub at `server` (`https://host[:port]`,
    /// optionally followed by `/`, `/pf` or `/pf/`) and the tunnel `word`.
    pub fn builder(server: impl Into<String>, word: impl Into<String>) -> ClientBuilder {
        let quic = Arc::new(transport::Quic::default());
        let inner = pfrelay::Client::builder(server, word)
            .agent(DEFAULT_AGENT)
            .transport(quic.clone() as Arc<dyn pfrelay::transport::Transport>);
        ClientBuilder { inner, quic }
    }

    /// The pfrelay client this is.
    pub fn client(&self) -> &pfrelay::Client {
        &self.inner
    }

    /// Closes the QUIC connection to the hub (code `none`), ending what it
    /// carries. The next request opens a new one.
    pub fn close(&self) {
        pfrelay::transport::Transport::close(&*self.quic);
    }
}

/// Builds a [`Client`]. Its settings are [`pfrelay::ClientBuilder`]'s,
/// except those of the WebSocket protocols (`max_proto`, reuse).
pub struct ClientBuilder {
    inner: pfrelay::ClientBuilder,
    quic: Arc<transport::Quic>,
}

macro_rules! forward {
    ($($(#[$m:meta])* fn $name:ident($arg:ident: $ty:ty);)+) => {
        $(
            $(#[$m])*
            pub fn $name(mut self, $arg: $ty) -> Self {
                self.inner = self.inner.$name($arg);
                self
            }
        )+
    };
}

impl ClientBuilder {
    forward! {
        /// A serve token of the hub, for `listen`, `serve_tcp` and `probe`.
        /// Without one, a registration is anonymous, which the hub must allow.
        fn serve_token(token: impl Into<String>);
        /// A second secret the serving side asks of whoever connects.
        fn client_token(token: impl Into<String>);
        /// What the hub's console calls the tunnel; [`DEFAULT_NAME`] by default.
        fn name(name: impl Into<String>);
        /// What the serving side tells the console it forwards to.
        fn target(target: impl Into<String>);
        /// What this program calls itself, such as `myapp 1.2.0`;
        /// [`DEFAULT_AGENT`] by default.
        fn agent(agent: impl Into<String>);
        /// Trusts the certificates in this PEM text for the hub's HTTPS
        /// endpoint (in place of the system's roots).
        fn ca_pem(pem: impl Into<Vec<u8>>);
        /// Trusts the certificates in this PEM file for the hub's HTTPS
        /// endpoint (in place of the system's roots).
        fn ca_file(path: impl Into<PathBuf>);
        /// Uses this TLS configuration for the hub's HTTPS endpoint. The
        /// QUIC listener's certificate is pinned instead (PROTOCOL.md §13.3).
        fn tls_config(config: Arc<tls::ClientConfig>);
        /// The handlers to call as things happen; none by default.
        fn events(events: Events);
        /// Retry and recheck timing.
        fn timing(timing: Timing);
    }

    /// Receives what the client has to say about registrations, retries
    /// and connections. Nothing is logged by default.
    pub fn logger(mut self, log: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.inner = self.inner.logger(log);
        self
    }

    /// Checks the settings and makes the client.
    pub fn build(self) -> Result<Client> {
        Ok(Client { inner: self.inner.build()?, quic: self.quic })
    }
}
