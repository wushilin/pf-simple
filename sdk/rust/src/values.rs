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

/// A hub's address, from `https://host[:port]` with an optional `/`, `/pf`
/// or `/pf/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Base {
    /// What goes in the `Host` header: the authority as given.
    pub authority: String,
    /// The host to connect to and verify, without brackets.
    pub host: String,
    pub port: u16,
}

impl Base {
    pub(crate) fn parse(raw: &str) -> Result<Base> {
        let raw = raw.trim();
        let bad = |why: &str| Error::Config(format!("invalid server URL {raw:?}: {why}"));
        let rest = match raw.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
            Some(_) => return Err(bad("only https:// is supported")),
            None => return Err(bad("use https://host[:port]/")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if !matches!(path, "" | "/" | "/pf" | "/pf/") {
            return Err(bad("give the server's address only, like https://host[:port]/"));
        }
        if authority.is_empty() || authority.contains(['@', '?', '#']) {
            return Err(bad("use https://host[:port]/"));
        }
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
        Ok(Base { authority: authority.to_string(), host, port })
    }

    pub(crate) fn url(&self) -> String {
        format!("https://{}", self.authority)
    }
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
        for bad in ["http://h/", "https://h/x", "h:1", "https://", "https://h:0", "https://u@h/"] {
            assert!(Base::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reasons() {
        assert_eq!(clean_reason("a\x00b\nc"), "abc");
        assert_eq!(clean_reason(&"x".repeat(500)).len(), 200);
    }
}
