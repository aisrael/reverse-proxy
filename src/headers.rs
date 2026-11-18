//! Pure functions that change the headers of a request or a response that
//! the proxy passes on. They do no I/O, so tests call them without sockets.

use hyper::HeaderMap;
use hyper::header::CONNECTION;
use hyper::header::HeaderName;

/// Headers that apply to one connection only. A proxy must not pass them on.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove the hop-by-hop headers. Also remove every header that a `Connection`
/// header names.
pub fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let named_by_connection: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in named_by_connection {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn removes_the_fixed_headers() {
        let mut map = headers(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-authenticate", "Basic"),
            ("proxy-authorization", "Basic abc"),
            ("te", "trailers"),
            ("trailer", "x-checksum"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
        ]);

        remove_hop_by_hop(&mut map);

        assert!(map.is_empty(), "left: {map:?}");
    }

    #[test]
    fn removes_the_headers_that_connection_names() {
        let mut map = headers(&[
            ("connection", "x-one, X-Two"),
            ("connection", "x-three"),
            ("x-one", "1"),
            ("x-two", "2"),
            ("x-three", "3"),
            ("x-four", "4"),
        ]);

        remove_hop_by_hop(&mut map);

        assert_eq!(map.len(), 1, "left: {map:?}");
        assert_eq!(map["x-four"], "4");
    }

    #[test]
    fn keeps_the_end_to_end_headers() {
        let mut map = headers(&[
            ("authorization", "Bearer abc"),
            ("content-length", "5"),
            ("content-type", "text/plain"),
            ("x-custom", "yes"),
        ]);

        remove_hop_by_hop(&mut map);

        assert_eq!(map.len(), 4);
    }

    #[test]
    fn ignores_a_connection_value_that_is_not_a_header_name() {
        let mut map = headers(&[("connection", "a b, ,\"x\""), ("x-one", "1")]);

        remove_hop_by_hop(&mut map);

        assert_eq!(map.len(), 1, "left: {map:?}");
        assert_eq!(map["x-one"], "1");
    }
}
