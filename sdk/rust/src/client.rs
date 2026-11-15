//! The client: one hub, one tunnel (one word).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};

use crate::conn::{Conn, ConnInfo, Registry, Side, Stats};
use crate::error::{Error, Result};
use crate::events::{ConnId, Events};
use crate::http::{self, Answer, Connector, Head, Upgraded};
use crate::proto::{self, Endpoint, ProtoLimit};
use crate::transport::{Params, Transport};
use crate::values::{self, Base};

/// What a [`Client`] calls itself in the hub's log and console unless told
/// otherwise.
pub const DEFAULT_AGENT: &str = concat!("pfrelay-rs ", env!("CARGO_PKG_VERSION"));
/// The tunnel name a serving client registers unless told otherwise.
pub const DEFAULT_NAME: &str = "pfrelay";

pub(crate) const H_PROTO: &str = "X-PF-Tunnel-Proto";
pub(crate) const H_VERSION: &str = "X-PF-Version";
pub(crate) const H_WORD: &str = "X-PF-Tunnel-Word";
pub(crate) const H_SERVE: &str = "X-PF-Serve-Token";
pub(crate) const H_NAME: &str = "X-PF-Tunnel-Name";
pub(crate) const H_TARGET: &str = "X-PF-Tunnel-Target";
pub(crate) const H_CLIENT_HASH: &str = "X-PF-Client-Token-SHA256";
pub(crate) const H_CLIENT_TOKEN: &str = "X-PF-Client-Token";
pub(crate) const H_CONN: &str = "X-PF-Tunnel-Conn";
pub(crate) const H_ERROR: &str = "X-PF-Tunnel-Error";
pub(crate) const H_SESSION: &str = "X-PF-Tunnel-Session";
pub(crate) const H_KEEP_ALIVE: &str = "X-PF-Tunnel-Keep-Alive";

/// How many idle legs a serving client keeps for reuse unless told
/// otherwise (PROTOCOL.md §12.9).
pub const DEFAULT_MAX_IDLE_LEGS: usize = 16;

/// The answer to a version probe (PROTOCOL.md §6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// The hub's program version, such as `0.14.0`.
    pub version: String,
    /// The tunnel protocols it speaks.
    #[serde(rename = "protoMin", default)]
    pub proto_min: u32,
    #[serde(rename = "protoMax", default)]
    pub proto_max: u32,
    /// The name of the serve token that asked.
    #[serde(default)]
    pub token: String,
}

/// Where the hub's certificate is trusted from.
enum Trust {
    Native,
    Roots(Vec<Vec<u8>>, Vec<PathBuf>),
    Config(Arc<ClientConfig>),
}

type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// The client's timing (PROTOCOL.md §9). The defaults are what pf-client
/// does; change them only to test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// A failed registration or check is retried after this pause, which
    /// doubles each time...
    pub retry_min: Duration,
    /// ...up to this.
    pub retry_max: Duration,
    /// A control channel that lasted this long starts the pause again from
    /// `retry_min`.
    pub settled: Duration,
    /// [`Client::watch`] checks a tunnel that is up this often.
    pub recheck: Duration,
    /// After a clean finish on a leg offered reuse, how long to wait for
    /// the hub's verdict (PROTOCOL.md §12.5).
    pub verdict_wait: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
            settled: Duration::from_secs(60),
            recheck: Duration::from_secs(30),
            verdict_wait: Duration::from_secs(3),
        }
    }
}

impl Timing {
    /// The pause after `pause`: double, up to `retry_max`.
    pub fn next(&self, pause: Duration) -> Duration {
        (pause * 2).min(self.retry_max)
    }
}

/// Builds a [`Client`].
pub struct ClientBuilder {
    server: String,
    word: String,
    serve_token: Option<String>,
    client_token: Option<String>,
    name: String,
    target: Option<String>,
    agent: Option<String>,
    trust: Trust,
    log: Option<Logger>,
    events: Events,
    timing: Timing,
    connector: Option<Connector>,
    max_proto: ProtoLimit,
    no_reuse: bool,
    max_idle_legs: usize,
    transport: Option<Arc<dyn Transport>>,
}

impl ClientBuilder {
    /// Reaches the hub through `transport` instead of WebSocket: for SDKs
    /// built on this one, such as `pfrelay-quic` (see [`crate::transport`]).
    /// Everything else stays the same. Reuse of accept legs, which is
    /// WebSocket only, is then off.
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// A serve token of the hub, for [`Client::listen`] and
    /// [`Client::probe`]. Without one, a registration is anonymous, which
    /// the hub must allow (and which needs protocol 1).
    pub fn serve_token(mut self, token: impl Into<String>) -> Self {
        self.serve_token = Some(token.into()).filter(|t: &String| !t.is_empty());
        self
    }

    /// A second secret the serving side asks of whoever connects. The
    /// serving side registers its SHA-256; the connecting side sends it.
    pub fn client_token(mut self, token: impl Into<String>) -> Self {
        self.client_token = Some(token.into()).filter(|t: &String| !t.is_empty());
        self
    }

    /// What the hub's console calls the tunnel; [`DEFAULT_NAME`] by default.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// What the serving side tells the console it forwards to; `listener`
    /// by default.
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into()).filter(|t: &String| !t.is_empty());
        self
    }

    /// What this program calls itself in `X-PF-Version`, such as
    /// `myapp 1.2.0`. For the hub's log and console only.
    pub fn agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = Some(agent.into()).filter(|t: &String| !t.is_empty());
        self
    }

    /// Trusts the certificates in this PEM text (in place of the system's
    /// roots), such as the CA of a hub that issues its own certificate.
    pub fn ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        match &mut self.trust {
            Trust::Roots(pems, _) => pems.push(pem.into()),
            _ => self.trust = Trust::Roots(vec![pem.into()], Vec::new()),
        }
        self
    }

    /// Trusts the certificates in this PEM file (in place of the system's
    /// roots).
    pub fn ca_file(mut self, path: impl Into<PathBuf>) -> Self {
        match &mut self.trust {
            Trust::Roots(_, files) => files.push(path.into()),
            _ => self.trust = Trust::Roots(Vec::new(), vec![path.into()]),
        }
        self
    }

    /// Uses this TLS configuration. Its ALPN is replaced by `http/1.1`.
    pub fn tls_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.trust = Trust::Config(config);
        self
    }

    /// Receives what the client has to say about registrations, retries
    /// and connections. Nothing is logged by default.
    pub fn logger(mut self, log: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.log = Some(Arc::new(log));
        self
    }

    /// The handlers to call as things happen; none by default. They are
    /// called synchronously and must not block (see [`Events`]).
    pub fn events(mut self, events: Events) -> Self {
        self.events = events;
        self
    }

    /// The newest tunnel protocol to offer: [`ProtoLimit::Newest`] (the
    /// default) offers protocol 2; `UpTo(1)` behaves like pf-client 0.14;
    /// `Unannounced` like a client from before 0.14.
    pub fn max_proto(mut self, limit: ProtoLimit) -> Self {
        self.max_proto = limit;
        self
    }

    /// Never reuse the serving side's accept legs (protocol 2): each
    /// connection gets a new one, as in protocol 1.
    pub fn no_reuse(mut self) -> Self {
        self.no_reuse = true;
        self
    }

    /// How many idle legs to keep for reuse at most; 0 (and the default)
    /// means [`DEFAULT_MAX_IDLE_LEGS`]. More are closed when the hub offers
    /// them. To turn reuse off, use [`no_reuse`](Self::no_reuse).
    pub fn max_idle_legs(mut self, n: usize) -> Self {
        self.max_idle_legs = n;
        self
    }

    /// Retry and recheck timing; [`Timing::default`] unless told otherwise.
    pub fn timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    /// Talks to the hub over this connector instead of TLS (tests only).
    #[cfg(test)]
    pub(crate) fn connector(mut self, connector: Connector) -> Self {
        self.connector = Some(connector);
        self
    }

    /// Checks the settings (PROTOCOL.md §2, §3) and makes the client.
    pub fn build(self) -> Result<Client> {
        let base = Base::parse(&self.server)?;
        let word = values::normalize_word(&self.word)?;
        if let Some(t) = &self.serve_token {
            values::check_serve_token(t)?;
        }
        if let Some(t) = &self.client_token {
            values::check_client_token(t)?;
        }
        let name = values::check_name(&self.name)?;
        if let Some(t) = &self.target {
            if t.chars().any(char::is_control) {
                return Err(Error::Config("the target may not contain control characters".into()));
            }
        }
        let connector = match self.connector {
            Some(c) => c,
            None => http::tls_connector(base.clone(), tls_config(self.trust)?),
        };
        Ok(Client {
            inner: Arc::new(Inner {
                base,
                word,
                connector,
                timing: self.timing,
                serve_token: self.serve_token,
                client_token: self.client_token,
                name,
                target: self.target.unwrap_or_else(|| "listener".into()),
                agent: self.agent.unwrap_or_else(|| DEFAULT_AGENT.into()),
                registry: Arc::new(Registry::new(self.events)),
                max_proto: self.max_proto,
                reuse: !self.no_reuse && self.max_proto.max() >= 2 && self.transport.is_none(),
                max_idle_legs: if self.max_idle_legs == 0 { DEFAULT_MAX_IDLE_LEGS } else { self.max_idle_legs },
                log: self.log,
                transport: self.transport,
            }),
        })
    }
}

fn tls_config(trust: Trust) -> Result<Arc<ClientConfig>> {
    let mut config = match trust {
        Trust::Config(c) => (*c).clone(),
        Trust::Native | Trust::Roots(..) => {
            let mut roots = RootCertStore::empty();
            match trust {
                Trust::Roots(pems, files) => {
                    let mut all = pems;
                    for f in files {
                        all.push(std::fs::read(&f).map_err(|e| {
                            Error::Config(format!("cannot read the CA file {}: {e}", f.display()))
                        })?);
                    }
                    for pem in all {
                        use rustls_pki_types::pem::PemObject;
                        let mut n = 0;
                        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(&pem) {
                            let cert = cert.map_err(|e| Error::Config(format!("a CA certificate is not valid PEM: {e}")))?;
                            roots
                                .add(cert)
                                .map_err(|e| Error::Config(format!("a CA certificate is not usable: {e}")))?;
                            n += 1;
                        }
                        if n == 0 {
                            return Err(Error::Config("no certificate in the CA PEM".into()));
                        }
                    }
                }
                _ => {
                    for cert in rustls_native_certs::load_native_certs().certs {
                        let _ = roots.add(cert);
                    }
                }
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| Error::Tls(e.to_string()))?
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub(crate) struct Inner {
    pub(crate) base: Base,
    pub(crate) word: String,
    connector: Connector,
    pub(crate) timing: Timing,
    pub(crate) serve_token: Option<String>,
    pub(crate) client_token: Option<String>,
    pub(crate) name: String,
    pub(crate) target: String,
    agent: String,
    pub(crate) registry: Arc<Registry>,
    log: Option<Logger>,
    max_proto: ProtoLimit,
    /// This client takes part in reusing legs (protocol 2).
    pub(crate) reuse: bool,
    pub(crate) max_idle_legs: usize,
    /// Another way to the hub than WebSocket, if one is attached.
    pub(crate) transport: Option<Arc<dyn Transport>>,
}

impl Inner {
    pub(crate) fn connector(&self) -> &Connector {
        &self.connector
    }
}

/// Talks to one relay hub about one tunnel (one word). It can serve the
/// tunnel ([`Client::listen`]) or connect through it ([`Client::dial`],
/// [`Client::check`]). Cloning it is cheap, and clones share their
/// bookkeeping.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("server", &self.inner.base.url()).field("word", &self.word_label()).finish()
    }
}

impl Client {
    /// Starts building a client for the hub at `server` (`https://host[:port]`,
    /// optionally followed by `/`, `/pf` or `/pf/`) and the tunnel `word`.
    pub fn builder(server: impl Into<String>, word: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            server: server.into(),
            word: word.into(),
            serve_token: None,
            client_token: None,
            name: DEFAULT_NAME.into(),
            target: None,
            agent: None,
            trust: Trust::Native,
            log: None,
            events: Events::default(),
            timing: Timing::default(),
            connector: None,
            max_proto: ProtoLimit::Newest,
            no_reuse: false,
            max_idle_legs: DEFAULT_MAX_IDLE_LEGS,
            transport: None,
        }
    }

    /// The word, normalized.
    pub fn word(&self) -> &str {
        &self.inner.word
    }

    /// The hub's base URL, as `https://host[:port]`.
    pub fn server(&self) -> String {
        self.inner.base.url()
    }

    /// This client's totals, open connections included.
    pub fn stats(&self) -> Stats {
        self.inner.registry.stats()
    }

    /// This client's open connections, oldest first.
    pub fn conns(&self) -> Vec<ConnInfo> {
        self.inner.registry.conns()
    }

    /// Ends the open connection `id` at once and tells the far end
    /// `reason`, as [`Conn::fail`] does; the connection then ends with
    /// [`Error::Dropped`]. Returns whether such a connection was open.
    pub fn drop_conn(&self, id: &ConnId, reason: &str) -> bool {
        self.inner.registry.drop_conn(id, reason)
    }

    pub(crate) fn events(&self) -> &Events {
        &self.inner.registry.events
    }

    /// Checks, for as long as the future runs, whether the tunnel can be
    /// reached, and reports through [`Events::on_tunnel`]: the first result,
    /// then every change. A tunnel that is up is checked every 30 seconds;
    /// one that is down sooner, from 1 second doubling to 30. It is for the
    /// connecting side, which can open connections either way. Drop the
    /// future (or abort its task) to stop it.
    pub async fn watch(&self) {
        let t = self.inner.timing;
        let mut backoff = t.retry_min;
        let mut up: Option<bool> = None;
        loop {
            let result = self.check().await;
            let now_up = result.is_ok();
            if up != Some(now_up) {
                match &result {
                    Ok(()) => self.log("the tunnel is up"),
                    Err(e) => self.log(&format!("the tunnel is not available ({e}); this keeps checking")),
                }
                self.events().tunnel(now_up, result.as_ref().err());
            }
            up = Some(now_up);
            let wait = if now_up {
                backoff = t.retry_min;
                t.recheck
            } else {
                let w = backoff;
                backoff = t.next(backoff);
                w
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// What this client calls itself in `X-PF-Version`.
    pub(crate) fn agent(&self) -> &str {
        &self.inner.agent
    }

    /// The attached transport, and what it needs of this client.
    pub(crate) fn alt(&self) -> Option<(&Arc<dyn Transport>, Params)> {
        self.inner.transport.as_ref().map(|t| (t, Params::new(self)))
    }

    pub(crate) fn log(&self, msg: &str) {
        if let Some(l) = &self.inner.log {
            l(msg);
        }
    }

    /// The word as logs show it: enough to tell tunnels apart, not enough to
    /// connect.
    pub(crate) fn word_label(&self) -> String {
        format!("{}-…", &self.inner.word[..4])
    }

    /// Sends a request to `endpoint` with its own headers, offering the
    /// protocol range it needs, and checks the hub's protocol on the answer
    /// (on every answer but a 404).
    pub(crate) async fn send(&self, endpoint: Endpoint, extra: Vec<(&'static str, String)>, upgrade: bool) -> Result<Answer> {
        let i = &self.inner;
        let needs = proto::needs(endpoint, i.client_token.is_some(), i.serve_token.is_some());
        let mut headers = vec![("User-Agent", i.agent.clone())];
        if let Some(range) = proto::offer(&needs, i.max_proto) {
            headers.push((H_PROTO, range));
            headers.push((H_VERSION, i.agent.clone()));
        }
        headers.extend(extra);
        let answer = http::request(&i.base, &i.connector, endpoint.path(), &headers, upgrade).await?;
        let head = match &answer {
            Answer::Upgraded(u) => Some(&u.head),
            Answer::Plain { head, .. } if head.status != 404 => Some(head),
            Answer::Plain { .. } => None,
        };
        if let Some(head) = head {
            proto::answered(&needs, head.get(H_PROTO))?;
        }
        Ok(answer)
    }

    /// A WebSocket to `endpoint`; any other answer is an error.
    pub(crate) async fn upgrade(&self, endpoint: Endpoint, extra: Vec<(&'static str, String)>) -> Result<Upgraded> {
        match self.send(endpoint, extra, true).await? {
            Answer::Upgraded(u) => Ok(*u),
            Answer::Plain { head, body } => Err(refusal(&head, &body)),
        }
    }

    /// A plain GET to `endpoint`; anything but 2xx is an error.
    pub(crate) async fn get(&self, endpoint: Endpoint, extra: Vec<(&'static str, String)>) -> Result<(Head, Vec<u8>)> {
        match self.send(endpoint, extra, false).await? {
            Answer::Plain { head, body } if head.status / 100 == 2 => Ok((head, body)),
            Answer::Plain { head, body } => Err(refusal(&head, &body)),
            Answer::Upgraded(_) => Err(Error::Protocol("the server switched protocols unasked".into())),
        }
    }

    fn word_header(&self) -> Vec<(&'static str, String)> {
        vec![(H_WORD, self.inner.word.clone())]
    }

    /// What the connecting side sends: the word, and the client token if
    /// the tunnel has one.
    fn connect_headers(&self) -> Vec<(&'static str, String)> {
        let mut h = self.word_header();
        if let Some(t) = &self.inner.client_token {
            h.push((H_CLIENT_TOKEN, t.clone()));
        }
        h
    }

    /// What `serve` sends.
    pub(crate) fn serve_headers(&self, target: &str) -> Vec<(&'static str, String)> {
        let i = &self.inner;
        let mut h = self.word_header();
        h.push((H_NAME, values::query_escape(&i.name)));
        h.push((H_TARGET, target.to_string()));
        if let Some(t) = &i.serve_token {
            h.push((H_SERVE, t.clone()));
        }
        if let Some(t) = &i.client_token {
            h.push((H_CLIENT_HASH, hex::encode(Sha256::digest(t.as_bytes()))));
        }
        h
    }

    /// What `accept` sends for connection `id`.
    pub(crate) fn accept_headers(&self, id: &str) -> Vec<(&'static str, String)> {
        let mut h = self.word_header();
        h.push((H_CONN, id.to_string()));
        h
    }

    /// Brings this side's leg of connection `id` to the hub. With the
    /// registration's session, it asks for reuse; the result says whether
    /// the hub offered it (PROTOCOL.md §12.3).
    pub(crate) async fn accept(&self, id: &str, session: Option<&str>) -> Result<(Upgraded, bool)> {
        let mut h = self.accept_headers(id);
        if let Some(s) = session {
            h.push((H_SESSION, s.to_string()));
        }
        let up = self.upgrade(Endpoint::Accept, h).await?;
        let offered = session.is_some() && crate::reuse::offered(&up.head);
        Ok((up, offered))
    }

    /// Opens one connection through the tunnel.
    ///
    /// The hub answers before the serving side has: if the serving side
    /// cannot be reached, or cannot reach its target, the first read fails
    /// with an [`Error::Remote`] saying so.
    pub async fn dial(&self) -> Result<Conn> {
        if let Some((t, p)) = self.alt() {
            let (stream, id) = t.connect(p).await?;
            return Ok(Conn::start_framed(stream, &id, Side::Connect, self.inner.registry.clone()));
        }
        let up = self.upgrade(Endpoint::Connect, self.connect_headers()).await?;
        let id = up.head.get(H_CONN).unwrap_or_default().to_string();
        Ok(Conn::start(up, &id, Side::Connect, self.inner.registry.clone(), None))
    }

    /// Asks the hub whether someone serves this word (and whether the
    /// client token, if the tunnel needs one, is right).
    pub async fn check(&self) -> Result<()> {
        if let Some((t, p)) = self.alt() {
            return t.check(p).await;
        }
        self.get(Endpoint::Check, self.connect_headers()).await.map(|_| ())
    }

    /// Asks the hub for its version and the tunnel protocols it speaks. It
    /// needs a valid serve token: without one the hub says nothing about
    /// itself.
    pub async fn probe(&self) -> Result<ServerInfo> {
        let mut h = Vec::new();
        if let Some(t) = &self.inner.serve_token {
            h.push((H_SERVE, t.clone()));
        }
        let (head, body) = match self.send(Endpoint::Version, h, false).await? {
            Answer::Plain { head, .. } if head.status == 404 => return Err(Error::NoProbe),
            Answer::Plain { head, body } => (head, body),
            Answer::Upgraded(_) => return Err(Error::Protocol("the server switched protocols unasked".into())),
        };
        if head.status / 100 != 2 {
            return Err(refusal(&head, &body));
        }
        match serde_json::from_slice::<ServerInfo>(&body) {
            Ok(info) if !info.version.is_empty() => Ok(info),
            _ => Err(Error::Protocol("the server's answer to the version probe is not understood".into())),
        }
    }
}

/// Turns a refusal into an error to act on (PROTOCOL.md §9).
pub(crate) fn refusal(head: &Head, body: &[u8]) -> Error {
    let message = http::error_text(body);
    match head.status {
        403 => Error::AccessDenied,
        404 if message.is_empty() => Error::NoRelay,
        code => Error::Status { code, message },
    }
}
