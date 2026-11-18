//! Pure functions that change the headers of a request or a response that
//! the proxy passes on. They do no I/O, so tests call them without sockets.

use hyper::HeaderMap;
use hyper::Version;
use hyper::header::CONNECTION;
use hyper::header::HOST;
use hyper::header::HeaderName;
use hyper::header::HeaderValue;
use hyper::header::VIA;
use std::net::IpAddr;

/// The start of the name that the proxy gives itself in the `Via` header. Each
/// proxy adds a random part (see `new_via_name`).
const PROXY_NAME: &str = "reverse-proxy";

/// The header that carries the request ID.
pub const REQUEST_ID: &str = "x-request-id";

/// The longest request ID that the proxy accepts from a client.
const MAX_REQUEST_ID_LEN: usize = 128;

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

/// The only request headers that the proxy sends to the upstream, with the
/// headers that it sets itself (`Host`, `X-Forwarded-*`, `Via`). The proxy
/// removes every other request header. The names are in lower case.
///
/// `Authorization` and `Cookie` are not on the list. The proxy decides from the
/// client certificate, and the upstream does not need these headers.
const ALLOWED_REQUEST: [&str; 15] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-encoding",
    "content-length",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "range",
    "user-agent",
    "via",
    REQUEST_ID,
];

/// Headers that tell the upstream about the client and the proxy. The proxy
/// sets them itself, and it does not trust the values from a client.
/// `Via` is not here: the proxy keeps it and adds to it (see `set_forwarding`).
const FORWARDING: [&str; 4] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "forwarded",
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

/// Remove each header of a request that is not on the `ALLOWED_REQUEST` list.
pub fn retain_allowed_request(headers: &mut HeaderMap) {
    let not_allowed: Vec<HeaderName> = headers
        .keys()
        .filter(|name| !ALLOWED_REQUEST.contains(&name.as_str()))
        .cloned()
        .collect();
    for name in not_allowed {
        headers.remove(name);
    }
}

/// Make a name for one proxy in the `Via` header: `reverse-proxy-` and 8 random
/// hexadecimal digits. Each start of the proxy makes a new name. A request that
/// comes back to the same proxy has this name in its `Via` header, and a request
/// that comes from another proxy of this program does not.
pub fn new_via_name() -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("{PROXY_NAME}-{}", &id[..8])
}

/// True if a `Via` header of `headers` has the proxy `name`.
///
/// A `Via` value is a list. Each item is the protocol, a space, and the name of
/// a proxy (`1.1 reverse-proxy-1a2b3c4d`). A comment can follow.
pub fn via_has(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get_all(VIA)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|item| item.split_whitespace().nth(1))
        .any(|received_by| received_by == name)
}

/// Replace the forwarding headers of a request.
///
/// First remove the values that the client sent. Then set:
///
/// - `X-Forwarded-For`: the IP address of the client.
/// - `X-Forwarded-Host`: `original_host`, the host that the client asked for.
///   Do not set it if there is no original host.
/// - `X-Forwarded-Proto`: `proto`, the protocol of the client connection.
///
/// Keep the `Via` values that the request has, and add one value: the HTTP
/// version of the client request, and `via_name`, the name of the proxy. The
/// chain of names lets a proxy see that a request came back to it (a loop).
pub fn set_forwarding(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    original_host: Option<&HeaderValue>,
    proto: &'static str,
    version: Version,
    via_name: &str,
) {
    for name in FORWARDING {
        headers.remove(name);
    }
    insert(headers, "x-forwarded-for", &client_ip.to_string());
    if let Some(host) = original_host {
        headers.insert("x-forwarded-host", host.clone());
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));
    if let Ok(value) = HeaderValue::from_str(&format!("{} {via_name}", via_protocol(version))) {
        headers.append(VIA, value);
    }
}

/// Set `Host` to the address of the upstream (`host:port`).
pub fn set_host(headers: &mut HeaderMap, upstream: &str) {
    insert(headers, HOST.as_str(), upstream);
}

/// Make sure that `headers` has exactly one valid `X-Request-Id`. Return its value.
///
/// Keep the first value if it is valid. A valid value has 1 to 128 characters,
/// and each character is a letter, a digit, or one of `-`, `_`, `.` and `:`.
/// Otherwise replace it with a new UUID. This stops a client from putting
/// long or odd text in the logs.
pub fn ensure_request_id(headers: &mut HeaderMap) -> HeaderValue {
    let value = headers
        .get(REQUEST_ID)
        .filter(|value| is_valid_request_id(value.as_bytes()))
        .cloned()
        .unwrap_or_else(|| {
            let id = uuid::Uuid::new_v4().to_string();
            HeaderValue::from_str(&id).expect("a UUID is a valid header value")
        });
    headers.insert(REQUEST_ID, value.clone());
    value
}

/// True if `value` is a valid request ID. See `ensure_request_id`.
fn is_valid_request_id(value: &[u8]) -> bool {
    (1..=MAX_REQUEST_ID_LEN).contains(&value.len())
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(byte))
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
    fn retain_allowed_request_keeps_only_the_headers_on_the_list() {
        let mut map = headers(&[
            ("accept", "text/plain"),
            ("content-type", "text/plain"),
            ("content-length", "5"),
            ("user-agent", "test"),
            ("x-request-id", "id-1"),
            ("via", "1.1 other"),
            ("authorization", "Bearer abc"),
            ("cookie", "a=b"),
            ("x-custom", "yes"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);

        retain_allowed_request(&mut map);

        let mut names: Vec<&str> = map.keys().map(|name| name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "accept",
                "content-length",
                "content-type",
                "user-agent",
                "via",
                "x-request-id"
            ]
        );
    }

    #[test]
    fn retain_allowed_request_removes_every_value_of_a_header() {
        let mut map = headers(&[("cookie", "a=b"), ("cookie", "c=d"), ("accept", "*/*")]);

        retain_allowed_request(&mut map);

        assert_eq!(map.len(), 1, "left: {map:?}");
    }

    #[test]
    fn ignores_a_connection_value_that_is_not_a_header_name() {
        let mut map = headers(&[("connection", "a b, ,\"x\""), ("x-one", "1")]);

        remove_hop_by_hop(&mut map);

        assert_eq!(map.len(), 1, "left: {map:?}");
        assert_eq!(map["x-one"], "1");
    }

    #[test]
    fn set_forwarding_replaces_the_values_from_the_client_and_adds_to_via() {
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
            "reverse-proxy-1a2b3c4d",
        );

        assert_eq!(map.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(map["x-forwarded-for"], "192.0.2.7");
        assert_eq!(map["x-forwarded-proto"], "http");
        assert_eq!(map["x-forwarded-host"], "proxy.example:8080");
        let via: Vec<&str> = map
            .get_all("via")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(via, ["1.1 other", "1.1 reverse-proxy-1a2b3c4d"]);
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
            "reverse-proxy-1a2b3c4d",
        );

        assert!(!map.contains_key("x-forwarded-host"));
        assert_eq!(map["x-forwarded-for"], "2001:db8::1");
        assert_eq!(map["via"], "2 reverse-proxy-1a2b3c4d");
    }

    #[test]
    fn new_via_name_is_different_each_time() {
        let name = new_via_name();

        assert!(name.starts_with("reverse-proxy-"), "{name}");
        assert_eq!(name.len(), "reverse-proxy-".len() + 8);
        assert_ne!(name, new_via_name());
    }

    #[test]
    fn via_has_finds_the_name_in_any_item() {
        let map = headers(&[
            ("via", "1.0 fred, 1.1 reverse-proxy-1a2b3c4d (comment)"),
            ("via", "2 other"),
        ]);

        assert!(via_has(&map, "reverse-proxy-1a2b3c4d"));
        assert!(via_has(&map, "other"));
    }

    #[test]
    fn via_has_does_not_find_another_name() {
        let map = headers(&[
            ("via", "1.1 reverse-proxy-ffffffff"),
            ("via", "1.1 xreverse-proxy-1a2b3c4d, 1.1"),
        ]);

        assert!(!via_has(&map, "reverse-proxy-1a2b3c4d"));
        assert!(!via_has(&HeaderMap::new(), "reverse-proxy-1a2b3c4d"));
    }

    #[test]
    fn set_host_replaces_the_host() {
        let mut map = headers(&[("host", "proxy.example:8080")]);

        set_host(&mut map, "127.0.0.1:9000");

        assert_eq!(map.get_all("host").iter().count(), 1);
        assert_eq!(map["host"], "127.0.0.1:9000");
    }

    #[test]
    fn keeps_a_valid_request_id() {
        let mut map = headers(&[("x-request-id", "abc-123_X.y:z")]);

        let id = ensure_request_id(&mut map);

        assert_eq!(id, "abc-123_X.y:z");
        assert_eq!(map["x-request-id"], "abc-123_X.y:z");
    }

    #[test]
    fn makes_a_request_id_when_there_is_none() {
        let mut map = HeaderMap::new();

        let id = ensure_request_id(&mut map);

        assert_eq!(id.len(), 36, "not a UUID: {id:?}");
        assert_eq!(map["x-request-id"], id);
    }

    #[test]
    fn replaces_a_request_id_that_is_not_valid() {
        let too_long = "a".repeat(129);
        for bad in ["", "has space", "<script>", too_long.as_str()] {
            let mut map = headers(&[("x-request-id", bad)]);

            let id = ensure_request_id(&mut map);

            assert_ne!(id, bad);
            assert_eq!(id.len(), 36, "not a UUID: {id:?}");
        }
    }

    #[test]
    fn keeps_the_longest_valid_request_id() {
        let longest = "a".repeat(128);
        let mut map = headers(&[("x-request-id", longest.as_str())]);

        assert_eq!(ensure_request_id(&mut map), longest.as_str());
    }

    #[test]
    fn keeps_one_request_id_when_the_client_sends_two() {
        let mut map = headers(&[("x-request-id", "first"), ("x-request-id", "second")]);

        let id = ensure_request_id(&mut map);

        assert_eq!(id, "first");
        assert_eq!(map.get_all("x-request-id").iter().count(), 1);
    }

    #[test]
    fn set_host_adds_the_host_when_there_is_none() {
        let mut map = HeaderMap::new();

        set_host(&mut map, "127.0.0.1:9000");

        assert_eq!(map["host"], "127.0.0.1:9000");
    }
}
