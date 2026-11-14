//! The client: one hub, one tunnel (one word).

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};

use crate::conn::{Conn, ConnInfo, Registry, Side, Stats};
use crate::error::{Error, Result};
use crate::http::{self, Answer, Head, Upgraded};
use crate::proto::{self, Endpoint};
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
}

impl ClientBuilder {
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
        let tls = tls_config(self.trust)?;
        Ok(Client {
            inner: Arc::new(Inner {
                base,
                word,
                tls,
                serve_token: self.serve_token,
                client_token: self.client_token,
                name,
                target: self.target.unwrap_or_else(|| "listener".into()),
                agent: self.agent.unwrap_or_else(|| DEFAULT_AGENT.into()),
                registry: Arc::new(Registry::default()),
                log: self.log,
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
    tls: Arc<ClientConfig>,
    pub(crate) serve_token: Option<String>,
    pub(crate) client_token: Option<String>,
    pub(crate) name: String,
    pub(crate) target: String,
    agent: String,
    pub(crate) registry: Arc<Registry>,
    log: Option<Logger>,
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
        let mut headers = vec![
            (H_PROTO, proto::offer(&needs)),
            (H_VERSION, i.agent.clone()),
            ("User-Agent", i.agent.clone()),
        ];
        headers.extend(extra);
        let answer = http::request(&i.base, &i.tls, endpoint.path(), &headers, upgrade).await?;
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
    pub(crate) fn serve_headers(&self) -> Vec<(&'static str, String)> {
        let i = &self.inner;
        let mut h = self.word_header();
        h.push((H_NAME, values::query_escape(&i.name)));
        h.push((H_TARGET, i.target.clone()));
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

    /// Opens one connection through the tunnel.
    ///
    /// The hub answers before the serving side has: if the serving side
    /// cannot be reached, or cannot reach its target, the first read fails
    /// with an [`Error::Remote`] saying so.
    pub async fn dial(&self) -> Result<Conn> {
        let up = self.upgrade(Endpoint::Connect, self.connect_headers()).await?;
        let id = up.head.get(H_CONN).unwrap_or_default().to_string();
        Ok(Conn::start(up, id, Side::Connect, self.inner.registry.clone()))
    }

    /// Asks the hub whether someone serves this word (and whether the
    /// client token, if the tunnel needs one, is right).
    pub async fn check(&self) -> Result<()> {
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
