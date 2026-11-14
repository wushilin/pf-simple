//! Connection ids, and the handlers a client calls as things happen.

use std::fmt;
use std::sync::Arc;

use crate::conn::ConnInfo;
use crate::error::Error;

/// Names one connection through the tunnel: the id the hub gave it, the
/// same on both ends of the tunnel. It is opaque: compare it, hash it,
/// print it.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(Arc<str>);

impl ConnId {
    pub(crate) fn new(id: &str) -> ConnId {
        ConnId(Arc::from(id))
    }

    /// The start of the id, enough to tell connections apart in a log.
    pub fn short(&self) -> &str {
        let end = self.0.char_indices().nth(8).map_or(self.0.len(), |(i, _)| i);
        &self.0[..end]
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnId({})", self.0)
    }
}

impl serde::Serialize for ConnId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

type ServingFn = dyn Fn(bool) + Send + Sync;
type TunnelFn = dyn Fn(bool, Option<&Error>) + Send + Sync;
type OpenFn = dyn Fn(&ConnInfo) + Send + Sync;
type CloseFn = dyn Fn(&ConnInfo, Option<&Error>) + Send + Sync;
type RefuseFn = dyn Fn(&ConnId, &str) + Send + Sync;

/// The handlers a [`Client`](crate::Client) calls as things happen. None
/// is set by default; set the ones you want and give them to
/// [`ClientBuilder::events`](crate::ClientBuilder::events).
///
/// Handlers are called **synchronously**, on the task where the event
/// happened, so they must return quickly and must not block; hand anything
/// slow to another task. They may call [`Client::stats`](crate::Client::stats),
/// [`Client::conns`](crate::Client::conns) and
/// [`Client::drop_conn`](crate::Client::drop_conn).
#[derive(Clone, Default)]
pub struct Events {
    pub(crate) serving: Option<Arc<ServingFn>>,
    pub(crate) tunnel: Option<Arc<TunnelFn>>,
    pub(crate) open: Option<Arc<OpenFn>>,
    pub(crate) close: Option<Arc<CloseFn>>,
    pub(crate) refuse: Option<Arc<RefuseFn>>,
}

impl fmt::Debug for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Events")
            .field("on_serving", &self.serving.is_some())
            .field("on_tunnel", &self.tunnel.is_some())
            .field("on_open", &self.open.is_some())
            .field("on_close", &self.close.is_some())
            .field("on_refuse", &self.refuse.is_some())
            .finish()
    }
}

impl Events {
    pub fn new() -> Events {
        Events::default()
    }

    /// [`Client::listen`](crate::Client::listen) or
    /// [`Client::serve_tcp`](crate::Client::serve_tcp) registered with the
    /// hub (`true`), or lost that registration (`false`).
    pub fn on_serving(mut self, f: impl Fn(bool) + Send + Sync + 'static) -> Self {
        self.serving = Some(Arc::new(f));
        self
    }

    /// [`Client::watch`](crate::Client::watch) found the tunnel reachable
    /// (`true`), or not (`false`, with why). Called with the first result,
    /// then on every change.
    pub fn on_tunnel(mut self, f: impl Fn(bool, Option<&Error>) + Send + Sync + 'static) -> Self {
        self.tunnel = Some(Arc::new(f));
        self
    }

    /// A connection was opened: dialed, accepted by a listener, or carried
    /// by a forwarder.
    pub fn on_open(mut self, f: impl Fn(&ConnInfo) + Send + Sync + 'static) -> Self {
        self.open = Some(Arc::new(f));
        self
    }

    /// A connection ended, exactly once for each `on_open`, with its final
    /// figures. The error is `None` after a clean finish, and otherwise why
    /// it failed ([`Error::Remote`] when the far end or the hub said why,
    /// [`Error::Dropped`] when this side dropped it).
    pub fn on_close(mut self, f: impl Fn(&ConnInfo, Option<&Error>) + Send + Sync + 'static) -> Self {
        self.close = Some(Arc::new(f));
        self
    }

    /// This side refused a connection the hub offered, telling the far end
    /// the reason: the backlog was full, or the target could not be
    /// reached. A refused connection is never opened.
    pub fn on_refuse(mut self, f: impl Fn(&ConnId, &str) + Send + Sync + 'static) -> Self {
        self.refuse = Some(Arc::new(f));
        self
    }

    pub(crate) fn serving(&self, up: bool) {
        if let Some(f) = &self.serving {
            f(up);
        }
    }

    pub(crate) fn tunnel(&self, up: bool, err: Option<&Error>) {
        if let Some(f) = &self.tunnel {
            f(up, err);
        }
    }

    pub(crate) fn refused(&self, id: &ConnId, reason: &str) {
        if let Some(f) = &self.refuse {
            f(id, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        let id = ConnId::new("8f14e45fceea167a");
        assert_eq!(id.to_string(), "8f14e45fceea167a");
        assert_eq!(id.short(), "8f14e45f");
        assert_eq!(id, ConnId::new("8f14e45fceea167a"));
        assert_eq!(serde_json::to_string(&id).unwrap(), r#""8f14e45fceea167a""#);
        assert_eq!(ConnId::new("ab").short(), "ab");
    }
}
