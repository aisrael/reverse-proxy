//! The admission rule: decide if the proxy accepts a request.
//!
//! The functions here are pure. They do no I/O.

use hyper::HeaderMap;

/// The header that carries the API key.
const API_KEY: &str = "x-api-key";

/// Return `true` if the request is admitted: it has a non-empty `x-api-key`.
///
/// Never log the value of the header.
pub fn admit(headers: &HeaderMap) -> bool {
    headers
        .get(API_KEY)
        .is_some_and(|value| !value.as_bytes().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn admits_a_request_with_a_key() {
        assert!(admit(&headers(&[("x-api-key", "test")])));
    }

    #[test]
    fn rejects_a_request_without_the_key() {
        assert!(!admit(&headers(&[("x-other", "test")])));
    }

    #[test]
    fn rejects_a_request_with_an_empty_key() {
        assert!(!admit(&headers(&[("x-api-key", "")])));
    }
}
