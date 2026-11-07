//! HTTP hostname and single-label wildcard helpers shared by ACL and routing.

/// Normalize an HTTP tunnel hostname or `*.suffix` pattern.
///
/// Rules (v1):
/// - Trim and lowercase.
/// - Exact names: no `*`, no leading/trailing `.`, no `..`, length 1..=253.
/// - Wildcards: only a leading `*.` followed by a non-empty suffix with the
///   same label rules. `*.example.com` is valid; `*example.com`,
///   `foo.*.example.com`, and `*.*.example.com` are not.
pub fn normalize_http_hostname(raw: &str) -> Result<String, &'static str> {
    let host = raw.trim().to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err("hostname is empty or too long");
    }
    if let Some(suffix) = host.strip_prefix("*.") {
        if !valid_hostname_labels(suffix) {
            return Err("invalid wildcard hostname suffix");
        }
        if suffix.contains('*') {
            return Err("wildcard hostnames must use a single leading '*.'");
        }
        return Ok(host);
    }
    if host.contains('*') {
        return Err("wildcard hostnames must use a leading '*.' only");
    }
    if !valid_hostname_labels(&host) {
        return Err("invalid hostname");
    }
    Ok(host)
}

fn valid_hostname_labels(value: &str) -> bool {
    if value.is_empty() || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return false;
    }
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// True when `pattern` is a leading single-label wildcard (`*.example.com`).
pub fn is_wildcard_hostname(pattern: &str) -> bool {
    pattern.starts_with("*.") && !pattern[2..].contains('*')
}

/// Single-label wildcard match: `*.example.com` matches `foo.example.com`
/// but not `foo.bar.example.com` and not `example.com`.
pub fn single_label_wildcard_matches(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    let Some(rest) = host.strip_suffix(suffix) else {
        return false;
    };
    let Some(label) = rest.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

/// Pick the route key for a request host.
///
/// Order: exact key (already lowercased) first; else the longest matching
/// single-label wildcard pattern. Equal-length ties break lexicographically
/// for stability.
pub fn resolve_hostname_key<'a, I>(host: &str, keys: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut exact: Option<&str> = None;
    let mut best_wild: Option<&str> = None;
    for key in keys {
        if key == host {
            exact = Some(key);
            break;
        }
        if !is_wildcard_hostname(key) {
            continue;
        }
        if !single_label_wildcard_matches(key, host) {
            continue;
        }
        best_wild = Some(match best_wild {
            None => key,
            Some(prev) if key.len() > prev.len() => key,
            Some(prev) if key.len() == prev.len() && key < prev => key,
            Some(prev) => prev,
        });
    }
    exact.or(best_wild)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_exact_and_wildcard() {
        assert_eq!(
            normalize_http_hostname("Demo.Local").unwrap(),
            "demo.local"
        );
        assert_eq!(
            normalize_http_hostname("*.Example.COM").unwrap(),
            "*.example.com"
        );
        assert!(normalize_http_hostname("").is_err());
        assert!(normalize_http_hostname("*example.com").is_err());
        assert!(normalize_http_hostname("foo.*.example.com").is_err());
        assert!(normalize_http_hostname("*.*.example.com").is_err());
        assert!(normalize_http_hostname("*. ").is_err());
    }

    #[test]
    fn single_label_wildcard_rules() {
        assert!(single_label_wildcard_matches(
            "*.example.com",
            "app.example.com"
        ));
        assert!(!single_label_wildcard_matches(
            "*.example.com",
            "a.b.example.com"
        ));
        assert!(!single_label_wildcard_matches(
            "*.example.com",
            "example.com"
        ));
        assert!(!single_label_wildcard_matches(
            "*.example.com",
            "app.other.com"
        ));
    }

    #[test]
    fn resolve_prefers_exact_then_longest_wildcard() {
        let keys = ["*.example.com", "app.example.com", "*.b.example.com"];
        assert_eq!(
            resolve_hostname_key("app.example.com", keys),
            Some("app.example.com")
        );
        assert_eq!(
            resolve_hostname_key("foo.example.com", keys),
            Some("*.example.com")
        );
        assert_eq!(
            resolve_hostname_key("a.b.example.com", keys),
            Some("*.b.example.com")
        );
        assert_eq!(resolve_hostname_key("nope.local", keys), None);
    }
}
