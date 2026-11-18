//! Pure functions that change the headers of a request or a response that
//! the proxy passes on. They do no I/O, so tests call them without sockets.

use hyper::HeaderMap;
use hyper::Version;
use hyper::header::CONNECTION;
use hyper::header::HOST;
use hyper::header::HeaderName;
use hyper::header::HeaderValue;
use std::net::IpAddr;

/// The name that the proxy gives itself in the `Via` header.
const PROXY_NAME: &str = "reverse-proxy";

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

/// Headers that tell the upstream about the client and the proxy. The proxy
/// sets them itself, and it does not trust the values from a client.
const FORWARDING: [&str; 5] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "forwarded",
    "via",
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

/// Replace the forwarding headers of a request.
///
/// First remove the values that the client sent. Then set:
///
/// - `X-Forwarded-For`: the IP address of the client.
/// - `X-Forwarded-Host`: `original_host`, the host that the client asked for.
///   Do not set it if there is no original host.
/// - `X-Forwarded-Proto`: `proto`, the protocol of the client connection.
/// - `Via`: the HTTP version of the client request, and the name of the proxy.
pub fn set_forwarding(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    original_host: Option<&HeaderValue>,
    proto: &'static str,
    version: Version,
) {
    for name in FORWARDING {
        headers.remove(name);
    }
    insert(headers, "x-forwarded-for", &client_ip.to_string());
    if let Some(host) = original_host {
        headers.insert("x-forwarded-host", host.clone());
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));
    insert(
        headers,
        "via",
        &format!("{} {PROXY_NAME}", via_protocol(version)),
    );
}

/// Set `Host` to the address of the upstream (`host:port`).
pub fn set_host(headers: &mut HeaderMap, upstream: &str) {
    insert(headers, HOST.as_str(), upstream);
}

/// The protocol version as the `Via` header writes it.
fn via_protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    }
}

/// Set a header from text. Skip it if the text is not a valid header value.
fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn set_forwarding_replaces_the_values_from_the_client() {
        let mut map = headers(&[
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
            ("forwarded", "for=1.2.3.4"),
            ("via", "1.1 other"),
        ]);
        let host = HeaderValue::from_static("proxy.example:8080");

        set_forwarding(
            &mut map,
            "192.0.2.7".parse().unwrap(),
            Some(&host),
            "http",
            Version::HTTP_11,
        );

        assert_eq!(map.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(map["x-forwarded-for"], "192.0.2.7");
        assert_eq!(map["x-forwarded-proto"], "http");
        assert_eq!(map["x-forwarded-host"], "proxy.example:8080");
        assert_eq!(map["via"], "1.1 reverse-proxy");
        assert!(!map.contains_key("forwarded"));
    }

    #[test]
    fn set_forwarding_does_not_set_the_host_when_there_is_none() {
        let mut map = headers(&[("x-forwarded-host", "evil.example")]);

        set_forwarding(
            &mut map,
            "2001:db8::1".parse().unwrap(),
            None,
            "http",
            Version::HTTP_2,
        );

        assert!(!map.contains_key("x-forwarded-host"));
        assert_eq!(map["x-forwarded-for"], "2001:db8::1");
        assert_eq!(map["via"], "2 reverse-proxy");
    }

    #[test]
    fn set_host_replaces_the_host() {
        let mut map = headers(&[("host", "proxy.example:8080")]);

        set_host(&mut map, "127.0.0.1:9000");

        assert_eq!(map.get_all("host").iter().count(), 1);
        assert_eq!(map["host"], "127.0.0.1:9000");
    }

    #[test]
    fn set_host_adds_the_host_when_there_is_none() {
        let mut map = HeaderMap::new();

        set_host(&mut map, "127.0.0.1:9000");

        assert_eq!(map["host"], "127.0.0.1:9000");
    }
}
