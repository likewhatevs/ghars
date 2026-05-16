//! Shared HTTP body-cap helpers. The `Content-Length` pre-read check
//! is needed by both `extract` (tarball download) and `github`
//! (releases JSON fetch); putting it here keeps a single source of
//! truth for the header-parse + threshold compare so a future
//! refactor that adjusts one site doesn't drift the other.

/// Parse `Content-Length` from `headers` as `u64`. Returns `Some(cl)`
/// when the header is present, parses cleanly, AND exceeds
/// `max_bytes`. Returns `None` when the header is absent, malformed,
/// or below the cap — falling back to streaming Layer 2 byte-count
/// enforcement.
#[must_use]
pub(crate) fn content_length_exceeds(
    headers: &reqwest::header::HeaderMap,
    max_bytes: u64,
) -> Option<u64> {
    headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&cl| cl > max_bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use reqwest::header::{CONTENT_LENGTH, HeaderMap, HeaderValue};

    fn headers_with_cl(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn content_length_exceeds_fires_when_header_over_cap() {
        let h = headers_with_cl("2048");
        assert_eq!(content_length_exceeds(&h, 1024), Some(2048));
    }

    #[test]
    fn content_length_exceeds_returns_none_when_under_cap() {
        let h = headers_with_cl("512");
        assert_eq!(content_length_exceeds(&h, 1024), None);
    }

    #[test]
    fn content_length_exceeds_returns_none_at_exact_boundary() {
        let h = headers_with_cl("1024");
        // Strictly-greater: 1024 == 1024 does not fire.
        assert_eq!(content_length_exceeds(&h, 1024), None);
    }

    #[test]
    fn content_length_exceeds_returns_none_when_header_missing() {
        let h = HeaderMap::new();
        assert_eq!(content_length_exceeds(&h, 1024), None);
    }

    #[test]
    fn content_length_exceeds_returns_none_when_header_unparseable() {
        let h = headers_with_cl("not-a-number");
        // Malformed CL falls through — streaming Layer 2 catches the
        // overflow at byte-count time.
        assert_eq!(content_length_exceeds(&h, 1024), None);
    }
}
