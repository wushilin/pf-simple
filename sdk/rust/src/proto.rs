//! Protocol versions and their negotiation (PROTOCOL.md §5).
//!
//! The client offers `min-max` in `X-PF-Tunnel-Proto` on every request.
//! `max` is [`PROTO_MAX`]; `min` is the protocol of the newest feature the
//! request depends on. It checks the protocol the hub answers with on every
//! response except a 404, and refuses with a [`ProtoError`] when a feature
//! it depends on needs more.

use crate::error::ProtoError;

/// The lowest tunnel protocol this SDK speaks. Protocol 0 is a hub that
/// announces none (pf-simple before 0.14.0).
pub const PROTO_MIN: u32 = 0;
/// The highest tunnel protocol this SDK speaks. Protocol 2 adds reusing
/// the serving side's accept legs (PROTOCOL.md §12).
pub const PROTO_MAX: u32 = 2;

/// The newest protocol a client offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtoLimit {
    /// The newest this SDK speaks, [`PROTO_MAX`].
    #[default]
    Newest,
    /// At most this protocol: `UpTo(1)` behaves like pf-client 0.14.
    UpTo(u32),
    /// Announce no protocol at all, like a client from before 0.14: no
    /// `X-PF-Tunnel-Proto` and no `X-PF-Version` (protocol 0).
    Unannounced,
}

impl ProtoLimit {
    /// The newest protocol offered.
    pub fn max(self) -> u32 {
        match self {
            ProtoLimit::Newest => PROTO_MAX,
            ProtoLimit::UpTo(n) => n.min(PROTO_MAX),
            ProtoLimit::Unannounced => 0,
        }
    }
}

/// Something a request may depend on that not every protocol has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feature {
    /// A client token (protocol 1).
    ClientToken,
    /// Serving without a serve token (protocol 1).
    AnonymousServe,
    /// Reusing the serving side's accept legs (protocol 2). Nothing ever
    /// depends on it: without it, legs are simply not reused.
    Reuse,
}

impl Feature {
    /// The protocol that first has this feature.
    pub fn proto(self) -> u32 {
        match self {
            Feature::ClientToken | Feature::AnonymousServe => 1,
            Feature::Reuse => 2,
        }
    }

    /// What the feature is called in messages.
    pub fn name(self) -> &'static str {
        match self {
            Feature::ClientToken => "a client token",
            Feature::AnonymousServe => "serving without a serve token",
            Feature::Reuse => "reusing accept legs",
        }
    }
}

/// The first pf-simple release that speaks a protocol.
pub(crate) fn release_of(proto: u32) -> &'static str {
    match proto {
        0 => "0.11.0",
        1 => "0.14.0",
        2 => "0.15.0",
        _ => "of a newer release",
    }
}

/// The endpoints of the hub (PROTOCOL.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Serve,
    Connect,
    Accept,
    Check,
    Version,
}

impl Endpoint {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Endpoint::Serve => "/pf/api/tunnel/serve",
            Endpoint::Connect => "/pf/api/tunnel/connect",
            Endpoint::Accept => "/pf/api/tunnel/accept",
            Endpoint::Check => "/pf/api/tunnel/check",
            Endpoint::Version => "/pf/api/tunnel/version",
        }
    }
}

/// What a request to `endpoint` depends on beyond protocol 0.
pub(crate) fn needs(endpoint: Endpoint, client_token: bool, serve_token: bool) -> Vec<Feature> {
    let mut out = Vec::new();
    match endpoint {
        Endpoint::Serve => {
            if client_token {
                out.push(Feature::ClientToken);
            }
            if !serve_token {
                out.push(Feature::AnonymousServe);
            }
        }
        Endpoint::Connect | Endpoint::Check => {
            if client_token {
                out.push(Feature::ClientToken);
            }
        }
        Endpoint::Accept | Endpoint::Version => {}
    }
    out
}

/// The range to offer for a request that depends on `needs`, or none at
/// all for a client that announces none. The minimum is the newest feature
/// the request depends on, but never above the maximum: a hub then answers
/// with less, and the client refuses (§5.3).
pub(crate) fn offer(needs: &[Feature], limit: ProtoLimit) -> Option<String> {
    if limit == ProtoLimit::Unannounced {
        return None;
    }
    let max = limit.max();
    let min = needs.iter().map(|f| f.proto()).fold(PROTO_MIN, u32::max).min(max);
    Some(proto_range(min, max))
}

/// Checks the hub's answer: `header` is its `X-PF-Tunnel-Proto`, if any.
pub(crate) fn answered(needs: &[Feature], header: Option<&str>) -> Result<(), ProtoError> {
    let server = server_proto(header);
    for &f in needs {
        if server < f.proto() {
            return Err(ProtoError { server, need: f });
        }
    }
    Ok(())
}

/// Formats a range for `X-PF-Tunnel-Proto`.
pub fn proto_range(min: u32, max: u32) -> String {
    format!("{min}-{max}")
}

/// Reads a range as a peer sends it: empty is protocol 0, a single number
/// is a range of one.
pub fn parse_proto_range(s: &str) -> Option<(u32, u32)> {
    let s = s.trim();
    if s.is_empty() {
        return Some((0, 0));
    }
    let (lo, hi) = s.split_once('-').unwrap_or((s, s));
    let min: u32 = lo.parse().ok()?;
    let max: u32 = hi.parse().ok()?;
    (min <= max && max <= 1 << 20).then_some((min, max))
}

/// The protocol a hub chose, from its `X-PF-Tunnel-Proto`: missing or not a
/// number is protocol 0.
pub fn server_proto(header: Option<&str>) -> u32 {
    header.and_then(|h| h.trim().parse::<u32>().ok()).unwrap_or(0)
}

/// Picks the protocol to use with a peer that speaks `min..=max`: the
/// highest both have. `false` when they share none.
pub fn negotiate(min: u32, max: u32) -> (u32, bool) {
    let proto = max.min(PROTO_MAX);
    #[allow(clippy::absurd_extreme_comparisons)] // PROTO_MIN may rise one day
    let ok = proto >= min && proto >= PROTO_MIN;
    (proto, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offers() {
        let o = |e, ct, st| offer(&needs(e, ct, st), ProtoLimit::Newest).unwrap();
        assert_eq!(o(Endpoint::Connect, false, false), "0-2");
        assert_eq!(o(Endpoint::Connect, true, false), "1-2");
        assert_eq!(o(Endpoint::Check, true, false), "1-2");
        assert_eq!(o(Endpoint::Serve, false, true), "0-2");
        assert_eq!(o(Endpoint::Serve, false, false), "1-2");
        assert_eq!(o(Endpoint::Serve, true, true), "1-2");
        assert_eq!(o(Endpoint::Accept, true, false), "0-2");
        assert_eq!(o(Endpoint::Version, true, false), "0-2");
    }

    #[test]
    fn limits() {
        let serve = needs(Endpoint::Serve, true, true);
        let plain = needs(Endpoint::Connect, false, false);
        assert_eq!(offer(&plain, ProtoLimit::UpTo(1)).unwrap(), "0-1");
        assert_eq!(offer(&serve, ProtoLimit::UpTo(1)).unwrap(), "1-1");
        assert_eq!(offer(&serve, ProtoLimit::UpTo(0)).unwrap(), "0-0");
        assert_eq!(offer(&plain, ProtoLimit::UpTo(9)).unwrap(), "0-2");
        assert_eq!(offer(&serve, ProtoLimit::Unannounced), None);
        assert_eq!(ProtoLimit::Unannounced.max(), 0);
        // Nothing depends on reuse, so it never raises the minimum.
        assert!(!needs(Endpoint::Accept, true, false).contains(&Feature::Reuse));
        assert_eq!(Feature::Reuse.proto(), 2);
    }

    #[test]
    fn checks_answers() {
        let n = needs(Endpoint::Serve, true, true);
        assert_eq!(
            answered(&n, None),
            Err(ProtoError { server: 0, need: Feature::ClientToken })
        );
        assert!(answered(&n, Some("garbage")).is_err());
        assert!(answered(&n, Some("0")).is_err());
        assert!(answered(&n, Some("1")).is_ok());
        assert!(answered(&n, Some(" 2 ")).is_ok());
        assert!(answered(&needs(Endpoint::Serve, false, true), None).is_ok());
        let anon = needs(Endpoint::Serve, false, false);
        assert_eq!(answered(&anon, None).unwrap_err().need, Feature::AnonymousServe);
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_proto_range(""), Some((0, 0)));
        assert_eq!(parse_proto_range("1"), Some((1, 1)));
        assert_eq!(parse_proto_range("0-1"), Some((0, 1)));
        assert_eq!(parse_proto_range("2-1"), None);
        assert_eq!(parse_proto_range("x"), None);
        assert_eq!(parse_proto_range("-1"), None);
        assert_eq!(negotiate(0, 5), (2, true));
        assert_eq!(negotiate(3, 5), (2, false));
        assert_eq!(negotiate(0, 1), (1, true));
        assert_eq!(negotiate(0, 0), (0, true));
        assert_eq!(server_proto(Some("1")), 1);
        assert_eq!(server_proto(Some("-1")), 0);
    }
}
