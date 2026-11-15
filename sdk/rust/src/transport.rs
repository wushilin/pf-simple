//! A way to reach the hub other than WebSocket, for SDKs built on this one.
//!
//! `pfrelay-quic` plugs its QUIC transport (tunnel protocol 3,
//! PROTOCOL.md §13) in here, through [`ClientBuilder::transport`]. The
//! [`Client`] keeps everything else: listeners, the retry loop, reasons,
//! events, stats, forwarders and `watch`, so both transports behave alike.
//! Only `listen`, `serve_tcp`, `dial`, `connect_tcp` and `check` go through
//! the transport; `probe` stays an HTTPS request (§6.5).
//!
//! A transport hands over each connection as a [`Stream`]: a QUIC stream
//! that has passed its request and answer, carrying protocol 3's frames
//! (§13.5). The client reads and writes the frames itself. The stream's
//! `poll_shutdown` must send FIN, and dropping it must end both directions:
//! after FIN by waiting briefly for the peer's own end, without FIN by
//! resetting the stream.
//!
//! Refusals come back as this crate's [`Error`]s, as over WebSocket: 403 as
//! [`Error::AccessDenied`], others as [`Error::Status`]. A transport may use
//! [`Params::get`] for requests to the hub's HTTPS endpoint, with the
//! client's TLS settings.
//!
//! [`ClientBuilder::transport`]: crate::ClientBuilder::transport

use std::future::Future;
use std::pin::Pin;

use crate::client::{refusal, Client};
use crate::error::{Error, Result};
use crate::http::{self, Answer};

/// A boxed future, as the transport's methods return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a connection's stream is: bytes both ways, and FIN on shutdown.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Io for T {}

/// One connection's stream, as a transport hands it over.
pub type Stream = Box<dyn Io>;

/// What a transport needs of the client, taken at each call.
#[derive(Clone)]
pub struct Params {
    client: Client,
}

impl Params {
    pub(crate) fn new(client: &Client) -> Params {
        Params { client: client.clone() }
    }

    /// The hub's base URL, `https://host[:port]`.
    pub fn server(&self) -> String {
        self.client.server()
    }

    /// The word, normalized.
    pub fn word(&self) -> &str {
        &self.client.inner.word
    }

    pub fn serve_token(&self) -> Option<&str> {
        self.client.inner.serve_token.as_deref()
    }

    pub fn client_token(&self) -> Option<&str> {
        self.client.inner.client_token.as_deref()
    }

    /// The tunnel's name, as plain UTF-8.
    pub fn name(&self) -> &str {
        &self.client.inner.name
    }

    /// What the program calls itself, for `X-PF-Version`.
    pub fn agent(&self) -> &str {
        self.client.agent()
    }

    /// Says something through the client's logger.
    pub fn log(&self, msg: &str) {
        self.client.log(msg)
    }

    /// A plain GET to `path` on the hub's HTTPS endpoint, with the client's
    /// TLS settings and these headers.
    pub async fn get(&self, path: &str, headers: &[(&str, String)]) -> Result<HttpAnswer> {
        let i = &self.client.inner;
        match http::request(&i.base, i.connector(), path, headers, false).await? {
            Answer::Plain { head, body } => Ok(HttpAnswer { status: head.status, head, body }),
            Answer::Upgraded(_) => Err(Error::Protocol("the server switched protocols unasked".into())),
        }
    }
}

/// The hub's answer to [`Params::get`].
pub struct HttpAnswer {
    pub status: u16,
    pub body: Vec<u8>,
    head: http::Head,
}

impl HttpAnswer {
    /// The first value of a header; names are case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.get(name)
    }

    /// The answer as a refusal, as the client words them (PROTOCOL.md §9).
    pub fn refusal(&self) -> Error {
        refusal(&self.head, &self.body)
    }
}

/// The error of a refused request with this status and the hub's message:
/// 403 is [`Error::AccessDenied`], anything else [`Error::Status`].
pub fn refused(status: u16, message: &str) -> Error {
    match status {
        403 => Error::AccessDenied,
        code => Error::Status { code, message: message.to_string() },
    }
}

/// A way to reach the hub.
pub trait Transport: Send + Sync + 'static {
    /// Registers the tunnel, returning once it is registered.
    fn register<'a>(&'a self, p: Params, target: &'a str) -> BoxFuture<'a, Result<Box<dyn Registration>>>;
    /// Opens one connection: its stream, and the hub's id for it.
    fn connect(&self, p: Params) -> BoxFuture<'_, Result<(Stream, String)>>;
    /// Asks whether the tunnel can be reached.
    fn check(&self, p: Params) -> BoxFuture<'_, Result<()>>;
    /// Releases what the transport keeps between requests.
    fn close(&self) {}
}

/// One registration, until it ends.
pub trait Registration: Send {
    /// Waits for the hub's next request for a connection. Its error is why
    /// the registration ended.
    fn next(&mut self) -> BoxFuture<'_, Result<Box<dyn Open>>>;
    /// Ends the registration.
    fn close(&mut self);
}

/// The hub asking for one connection.
pub trait Open: Send {
    /// The hub's id for the connection.
    fn id(&self) -> &str;
    /// Takes the connection: its stream.
    fn accept(self: Box<Self>) -> BoxFuture<'static, Result<Stream>>;
    /// Tells the hub why this side cannot carry it.
    fn refuse(self: Box<Self>, reason: &str) -> BoxFuture<'static, ()>;
}
