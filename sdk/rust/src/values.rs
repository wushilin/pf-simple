//! The values of PROTOCOL.md §3, and the hub's base URL (§2).

use rand::Rng;

use crate::error::{Error, Result};

const WORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Trims and lower-cases a word, and checks it is three groups of four
/// ASCII letters or digits joined by `-`.
pub fn normalize_word(word: &str) -> Result<String> {
    let w = word.trim().to_ascii_lowercase();
    let b = w.as_bytes();
    let ok = b.len() == 14
        && b.iter().enumerate().all(|(i, &c)| {
            if i == 4 || i == 9 {
                c == b'-'
            } else {
                c.is_ascii_lowercase() || c.is_ascii_digit()
            }
        });
    if !ok {
        return Err(Error::Config(
            "the word must be three groups of four letters or digits, like k3f9-x2mq-7hpa (case does not matter)".into(),
        ));
    }
    Ok(w)
}

/// A random word that is easy to read out: no `0 o 1 i l`.
pub fn new_word() -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(14);
    for i in 0..12 {
        if i == 4 || i == 8 {
            out.push('-');
        }
        out.push(WORD_ALPHABET[rng.random_range(0..WORD_ALPHABET.len())] as char);
    }
    out
}

fn printable(s: &str) -> bool {
    s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

/// Checks a serve token: 32 to 128 printable ASCII characters.
pub fn check_serve_token(token: &str) -> Result<()> {
    if token.len() < 32 || token.len() > 128 || !printable(token) {
        return Err(Error::Config(
            "the serve token must be 32 to 128 printable ASCII characters, without spaces".into(),
        ));
    }
    Ok(())
}

/// Checks a client token: 8 to 128 printable ASCII characters.
pub fn check_client_token(token: &str) -> Result<()> {
    if token.len() < 8 || token.len() > 128 || !printable(token) {
        return Err(Error::Config(
            "the client token must be 8 to 128 printable ASCII characters, without spaces".into(),
        ));
    }
    Ok(())
}

/// Checks a tunnel name and returns it trimmed: 1 to 64 characters, no
/// control characters.
pub fn check_name(name: &str) -> Result<String> {
    let n = name.trim();
    let count = n.chars().count();
    if count == 0 || count > 64 {
        return Err(Error::Config("the tunnel name must be 1 to 64 characters".into()));
    }
    if n.chars().any(char::is_control) {
        return Err(Error::Config("the tunnel name may not contain control characters".into()));
    }
    Ok(n.to_string())
}

/// URL-query-escapes text the way Go's `url.QueryEscape` does: space
/// becomes `+`, and every byte but `A-Z a-z 0-9 - _ . ~` becomes `%XX`.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The prefix a hub is at unless its admin chose another (PROTOCOL.md §2).
pub(crate) const DEFAULT_PREFIX: &str = "/pf";
/// The longest prefix, and the longest segment of one (PROTOCOL.md §2).
const MAX_PREFIX: usize = 200;
const MAX_SEGMENT: usize = 64;
/// What a base URL may be, for error messages.
const ACCEPTED: &str = "use https://host[:port], optionally followed by the hub's prefix (like /pf, \
the default): one or more segments, each / and 1 to 64 of A-Z a-z 0-9 . _ ~ -, \
not . or .., at most 200 characters, with one trailing / allowed";

/// A hub's address (PROTOCOL.md §2): `https://host[:port]` followed by the
/// hub's prefix, `/pf` when none is given. Every request goes to
/// `<prefix>/api/tunnel/<endpoint>` on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Base {
    /// What goes in the `Host` header: the authority as given.
    pub authority: String,
    /// The host to connect to and verify, without brackets.
    pub host: String,
    pub port: u16,
    /// Where the hub is mounted, like `/pf`: no trailing `/`.
    pub prefix: String,
}

impl Base {
    /// Parses and checks a base URL. This is the only place one is read.
    pub(crate) fn parse(raw: &str) -> Result<Base> {
        let raw = raw.trim();
        let bad = |why: &str| Error::Config(format!("invalid server URL {raw:?}: {why}; {ACCEPTED}"));
        let rest = match raw.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
            Some(_) => return Err(bad("only https:// is supported")),
            None => return Err(bad("no https://")),
        };
        if rest.contains('#') {
            return Err(bad("a fragment (#) is not allowed"));
        }
        if rest.contains('?') {
            return Err(bad("a query (?) is not allowed"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(bad("user information (@) is not allowed"));
        }
        if authority.is_empty() {
            return Err(bad("no host"));
        }
        let prefix = parse_prefix(path).map_err(|why| bad(&why))?;
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            let (h, tail) = after.split_once(']').ok_or_else(|| bad("unclosed ["))?;
            let port = match tail {
                "" => None,
                t => Some(t.strip_prefix(':').ok_or_else(|| bad("bad port"))?),
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() {
            return Err(bad("no host"));
        }
        let port = match port {
            None => 443,
            Some(p) => p.parse::<u16>().ok().filter(|&p| p != 0).ok_or_else(|| bad("bad port"))?,
        };
        Ok(Base { authority: authority.to_string(), host, port, prefix })
    }

    /// The hub's base URL for messages: `https://host[:port]`, followed by
    /// the prefix when it is not the default.
    pub(crate) fn url(&self) -> String {
        if self.prefix == DEFAULT_PREFIX {
            format!("https://{}", self.authority)
        } else {
            format!("https://{}{}", self.authority, self.prefix)
        }
    }

    /// The path of one of the hub's endpoints: `<prefix>/api/tunnel/<endpoint>`.
    pub(crate) fn path(&self, endpoint: &str) -> String {
        format!("{}/api/tunnel/{endpoint}", self.prefix)
    }
}

/// Checks the path of a base URL and gives the prefix it names, without a
/// trailing `/` (PROTOCOL.md §2).
fn parse_prefix(path: &str) -> std::result::Result<String, String> {
    if path.is_empty() || path == "/" {
        return Ok(DEFAULT_PREFIX.to_string());
    }
    let prefix = path.strip_suffix('/').unwrap_or(path);
    if prefix.len() > MAX_PREFIX {
        return Err(format!("the prefix is longer than {MAX_PREFIX} characters"));
    }
    // The path starts with '/', so the first piece is empty.
    for seg in prefix.split('/').skip(1) {
        if seg.is_empty() {
            return Err("the prefix has an empty segment (//)".into());
        }
        if seg.len() > MAX_SEGMENT {
            return Err(format!("a segment of the prefix is longer than {MAX_SEGMENT} characters"));
        }
        if seg == "." || seg == ".." {
            return Err(format!("a segment of the prefix is {seg:?}"));
        }
        if let Some(c) = seg.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))) {
            return Err(format!("the prefix holds {c:?}"));
        }
    }
    Ok(prefix.to_string())
}

/// Makes a reason that came over the wire safe to show: printable
/// characters only, at most 200 of them (PROTOCOL.md §8.3).
pub(crate) fn clean_reason(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert_eq!(normalize_word("  K3F9-x2mq-7HPA\n").unwrap(), "k3f9-x2mq-7hpa");
        for bad in ["k3f9x2mq7hpa", "k3f9-x2mq-7hp", "k3f9-x2mq-7hpä", "k3f9_x2mq_7hpa", ""] {
            assert!(normalize_word(bad).is_err(), "{bad}");
        }
        for _ in 0..100 {
            let w = new_word();
            assert_eq!(normalize_word(&w).unwrap(), w);
            assert!(!w.contains(['0', 'o', '1', 'i', 'l']));
        }
    }

    #[test]
    fn tokens_and_names() {
        assert!(check_serve_token(&"a".repeat(32)).is_ok());
        assert!(check_serve_token(&"a".repeat(31)).is_err());
        assert!(check_serve_token(&"a".repeat(129)).is_err());
        assert!(check_serve_token(&format!("{} ", "a".repeat(32))).is_err());
        assert!(check_client_token("open-sesame").is_ok());
        assert!(check_client_token("short").is_err());
        assert_eq!(check_name("  Office SSH ").unwrap(), "Office SSH");
        assert!(check_name("   ").is_err());
        assert!(check_name("a\tb").is_err());
        assert!(check_name(&"é".repeat(64)).is_ok());
        assert!(check_name(&"é".repeat(65)).is_err());
        assert_eq!(query_escape("Office SSH/é~"), "Office+SSH%2F%C3%A9~");
    }

    #[test]
    fn bases() {
        let b = Base::parse("https://127.0.0.1:8443/pf/").unwrap();
        assert_eq!((b.host.as_str(), b.port, b.authority.as_str()), ("127.0.0.1", 8443, "127.0.0.1:8443"));
        let b = Base::parse("https://hub.example").unwrap();
        assert_eq!((b.host.as_str(), b.port), ("hub.example", 443));
        let b = Base::parse("https://[::1]:9/").unwrap();
        assert_eq!((b.host.as_str(), b.port), ("::1", 9));
        for bad in ["http://h/", "h:1", "https://", "https://h:0", "https://u@h/"] {
            assert!(Base::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn prefixes() {
        for (raw, prefix) in [
            ("https://h", "/pf"),
            ("https://h/", "/pf"),
            ("https://h/pf", "/pf"),
            ("https://h/pf/", "/pf"),
            ("https://h:8443/xzfe-aeeg-e2da/", "/xzfe-aeeg-e2da"),
            ("https://h/a/b.c_d~e-f", "/a/b.c_d~e-f"),
            ("https://h/PF", "/PF"),
            ("https://h/x", "/x"),
        ] {
            let b = Base::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(b.prefix, prefix, "{raw}");
        }
        let b = Base::parse("https://h:8443/xzfe-aeeg-e2da/").unwrap();
        assert_eq!((b.host.as_str(), b.port), ("h", 8443));
        let seg64 = format!("https://h/{}", "a".repeat(64));
        assert!(Base::parse(&seg64).is_ok());
        let long200 = format!("https://h{}", "/abcdefghi".repeat(20)); // 200 characters
        assert!(Base::parse(&long200).is_ok());
        assert!(Base::parse(&format!("{long200}/")).is_ok());

        let seg65 = format!("https://h/{}", "a".repeat(65));
        let long202 = format!("https://h{}/a", "/abcdefghi".repeat(20)); // 202 characters
        for bad in [
            "http://h/",
            "http://h/pf",
            "https://h/pf?x=1",
            "https://h?x=1",
            "https://h/pf#top",
            "https://h#top",
            "https://u@h/pf",
            "https://u:p@h/",
            "https://h//",
            "https://h//pf",
            "https://h/pf//",
            "https://h/a//b",
            "https://h/.",
            "https://h/..",
            "https://h/a/./b",
            "https://h/a/../b",
            "https://h/a%2Fb",
            "https://h/%2F",
            "https://h/a b",
            "https://h/a+b",
            "https://h/\u{e9}",
            seg65.as_str(),
            long202.as_str(),
        ] {
            let e = Base::parse(bad).err().unwrap_or_else(|| panic!("{bad} was accepted"));
            assert!(e.to_string().contains("1 to 64 of A-Z a-z 0-9 . _ ~ -"), "{bad}: {e}");
        }
    }

    #[test]
    fn request_paths() {
        let b = Base::parse("https://h:8443/xzfe-aeeg-e2da/").unwrap();
        assert_eq!(b.path("serve"), "/xzfe-aeeg-e2da/api/tunnel/serve");
        assert_eq!(b.path("quic"), "/xzfe-aeeg-e2da/api/tunnel/quic");
        assert_eq!(b.url(), "https://h:8443/xzfe-aeeg-e2da");
        let b = Base::parse("https://h/a/b.c_d~e-f").unwrap();
        assert_eq!(b.path("version"), "/a/b.c_d~e-f/api/tunnel/version");
        for raw in ["https://h", "https://h/", "https://h/pf/"] {
            let b = Base::parse(raw).unwrap();
            assert_eq!(b.path("connect"), "/pf/api/tunnel/connect");
            assert_eq!(b.url(), "https://h");
        }
    }

    #[test]
    fn reasons() {
        assert_eq!(clean_reason("a\x00b\nc"), "abc");
        assert_eq!(clean_reason(&"x".repeat(500)).len(), 200);
    }
}
