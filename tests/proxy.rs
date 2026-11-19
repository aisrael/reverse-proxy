//! Black-box tests for the `proxy` mode.
//!
//! The tests start the compiled program as child processes: the `server` mode
//! (the upstream) and the `proxy` mode. They talk to the proxy over HTTPS only.
//! They use no types or functions from the program code.
//!
//! The proxy needs the dev certificates. Make them first, with
//! `./scripts/gen-dev-certs.sh`.
//!
//! The program listens on fixed addresses, so only one copy of each mode can
//! run at a time. The tests use `#[serial]`, so they run one after the other.
//! Stop any other copy of the program before you run the tests.

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::HeaderMap;
use hyper::Method;
use hyper::Request;
use hyper::StatusCode;
use hyper::header::HOST;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::pem::PemObject;
use serial_test::serial;
use std::fs::File;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The address of the `proxy` mode.
const PROXY_ADDR: &str = "127.0.0.1:8443";

/// The address of the `server` mode (the upstream).
const SERVER_ADDR: &str = "127.0.0.1:9000";

/// The certificate of the dev CA. The proxy uses a certificate that this CA signed.
const CA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/ca.pem");
const POLICY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/policies.yaml");

/// The certificate and the key of the proxy.
const CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/server.pem");
const KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/server.key");

/// The certificate and the key of the test client. The CA signed it. Its
/// SPIFFE ID is `spiffe://acme/prod/payment-agent`.
const CLIENT_CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/payment-agent.pem");
const CLIENT_KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/payment-agent.key");

/// A client certificate and key that a second CA signed. The proxy does not
/// trust that CA.
const UNTRUSTED_CERT_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/untrusted-agent.pem");
const UNTRUSTED_KEY_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/untrusted-agent.key");

/// A client certificate and key that the dev CA signed. The certificate expired
/// in January 2020.
const EXPIRED_CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/expired-agent.pem");
const EXPIRED_KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/expired-agent.key");

/// The client certificate of `reporting-agent`. The test policy lets it read
/// reports only.
const REPORTING_CERT_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/reporting-agent.pem");
const REPORTING_KEY_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/reporting-agent.key");

/// A client certificate and key that the dev CA signed. The certificate has no
/// URI SAN, so the client has no identity.
const NO_URI_CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/no-uri-agent.pem");
const NO_URI_KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/no-uri-agent.key");

/// A running copy of the program. The process stops when this value is dropped.
struct Program {
    child: Child,
    addr: &'static str,
    /// The file that holds the STDERR of the program. The file is read only if
    /// the program fails to start or to stop.
    stderr_path: PathBuf,
    /// The file that holds the STDOUT of the program: the audit events.
    stdout_path: PathBuf,
}

impl Program {
    /// Start the program in `mode` and wait until it accepts connections on `addr`.
    ///
    /// Panic if another process already uses `addr`. Panic at once, with the
    /// STDERR of the program, if the program exits during startup. Panic with
    /// the STDERR too if the program does not accept connections within 10
    /// seconds.
    async fn start(mode: &str, addr: &'static str) -> Self {
        Self::start_with_ca(mode, addr, CA_PATH).await
    }

    /// Start the program as `start` does, with the CA bundle file `client_ca`.
    async fn start_with_ca(mode: &str, addr: &'static str, client_ca: &str) -> Self {
        Self::start_with(mode, addr, client_ca, &[]).await
    }

    /// Start the program as `start_with_ca` does, and set more environment
    /// variables from `env`.
    async fn start_with(
        mode: &str,
        addr: &'static str,
        client_ca: &str,
        env: &[(&str, &str)],
    ) -> Self {
        assert!(
            TcpStream::connect(addr).is_err(),
            "another process uses {addr}. Stop it and run the tests again"
        );

        let stderr_path = std::env::temp_dir().join(format!(
            "reverse-proxy-{}-{mode}.stderr",
            std::process::id()
        ));
        let stderr = File::create(&stderr_path).expect("failed to create the STDERR file");
        let stdout_path = std::env::temp_dir().join(format!(
            "reverse-proxy-{}-{mode}.stdout",
            std::process::id()
        ));
        let stdout = File::create(&stdout_path).expect("failed to create the STDOUT file");
        let child = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .arg(mode)
            // Set both addresses, so the values from the shell (for example,
            // from `.envrc`) cannot change them.
            .env("PROXY_ADDR", PROXY_ADDR)
            .env("SERVER_ADDR", SERVER_ADDR)
            .env("PROXY_TLS_CERT", CERT_PATH)
            .env("PROXY_TLS_KEY", KEY_PATH)
            .env("PROXY_CLIENT_CA", client_ca)
            .env("PROXY_POLICY_FILE", POLICY_PATH)
            .envs(env.iter().copied())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to start the program");
        let mut program = Program {
            child,
            addr,
            stderr_path,
            stdout_path,
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(addr).is_err() {
            if let Some(status) = program.child.try_wait().expect("failed to wait") {
                panic!(
                    "the program exited during startup ({status}):\n{}",
                    program.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the program did not start within 10 seconds:\n{}",
                program.stderr()
            );
            sleep(Duration::from_millis(50)).await;
        }
        program
    }

    /// What the program wrote to STDERR so far.
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|err| format!("(unable to read the STDERR file: {err})"))
    }

    /// The audit events that the program wrote to STDOUT so far. Panic if a
    /// line is not a JSON object.
    fn audit_events(&self) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(&self.stdout_path).expect("failed to read STDOUT");
        text.lines()
            .map(|line| {
                let event: serde_json::Value = serde_json::from_str(line)
                    .unwrap_or_else(|err| panic!("STDOUT line is not JSON ({err}): {line}"));
                assert!(event.is_object(), "STDOUT line is not an object: {line}");
                event
            })
            .collect()
    }

    /// Send SIGINT to the program. This is the same as Ctrl+C.
    fn interrupt(&self) {
        let status = Command::new("kill")
            .arg("-INT")
            .arg(self.child.id().to_string())
            .status()
            .expect("failed to run kill");
        assert!(status.success(), "kill failed ({status})");
    }

    /// Wait until the program exits. Panic if it does not exit within `limit`.
    async fn wait_for_exit(&mut self, limit: Duration) -> ExitStatus {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().expect("failed to wait") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the program did not exit within {limit:?}:\n{}",
                self.stderr()
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Check that the program no longer accepts connections.
    fn assert_not_listening(&self) {
        assert!(
            TcpStream::connect(self.addr).is_err(),
            "the program still accepts connections on {}",
            self.addr
        );
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.stderr_path);
        let _ = std::fs::remove_file(&self.stdout_path);
    }
}

/// A client that trusts the dev CA and sends a client certificate. It opens a new connection for each request.
struct TestClient {
    connector: TlsConnector,
}

fn client() -> TestClient {
    TestClient {
        connector: tls_connector(&[b"http/1.1"]),
    }
}

/// A client with the certificate of `reporting-agent`.
fn reporting_client() -> TestClient {
    TestClient {
        connector: make_connector(
            &[b"http/1.1"],
            Some((REPORTING_CERT_PATH, REPORTING_KEY_PATH)),
        ),
    }
}

/// Make a TLS connector that trusts the dev CA, sends the client certificate
/// and offers `alpn` protocols.
fn tls_connector(alpn: &[&[u8]]) -> TlsConnector {
    make_connector(alpn, Some((CLIENT_CERT_PATH, CLIENT_KEY_PATH)))
}

/// Make a TLS connector that trusts the dev CA and offers `alpn` protocols.
/// `client_auth` is the certificate file and the key file of the client. With
/// `None`, the connector sends no client certificate.
fn make_connector(alpn: &[&[u8]], client_auth: Option<(&str, &str)>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(CA_PATH)
        .expect("cannot read the CA. Run ./scripts/gen-dev-certs.sh first");
    for cert in certs {
        roots
            .add(cert.expect("the CA file is not valid"))
            .expect("the CA certificate is not valid");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("invalid protocol versions")
        .with_root_certificates(roots);
    let mut config = match client_auth {
        Some((cert_path, key_path)) => {
            let certs = CertificateDer::pem_file_iter(cert_path)
                .expect("cannot read the client certificate. Run ./scripts/gen-dev-certs.sh first")
                .collect::<Result<Vec<_>, _>>()
                .expect("the client certificate file is not valid");
            let key = PrivateKeyDer::from_pem_file(key_path).expect("cannot read the client key");
            builder
                .with_client_auth_cert(certs, key)
                .expect("the client certificate does not match the key")
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|name| name.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// Open a TLS connection to the proxy. The certificate is for `localhost`.
async fn connect(connector: &TlsConnector) -> TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(PROXY_ADDR)
        .await
        .expect("failed to connect to the proxy");
    let name = ServerName::try_from("localhost").expect("not a valid name");
    connector
        .connect(name, tcp)
        .await
        .expect("the TLS handshake failed")
}

/// Check that the proxy rejects the client of `connector` in the TLS handshake.
///
/// With TLS 1.3, the client can finish its side of the handshake before the
/// server checks the client certificate. So the rejection can show when the
/// client connects, or when it reads. In both cases the client gets no HTTP
/// response. After that, a client with a valid certificate still works.
async fn assert_rejected(connector: &TlsConnector) {
    let tcp = tokio::net::TcpStream::connect(PROXY_ADDR)
        .await
        .expect("failed to connect to the proxy");
    let name = ServerName::try_from("localhost").expect("not a valid name");
    if let Ok(mut stream) = connector.connect(name, tcp).await {
        let _ = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        let mut reply = Vec::new();
        let result = stream.read_to_end(&mut reply).await;
        assert!(
            result.is_err() || reply.is_empty(),
            "the proxy answered a client with a bad certificate: {}",
            String::from_utf8_lossy(&reply)
        );
    }

    // The upstream is not running, so a request that passes gets `502`.
    let (status, _, _) = send(&client(), Method::GET, "/", &[], "").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// Send a request to the proxy. Return the status, the headers and the body.
async fn send(
    client: &TestClient,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    let stream = connect(&client.connector).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("the HTTP handshake failed");
    tokio::spawn(connection);

    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, PROXY_ADDR);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(body.into()))
        .expect("failed to build the request");
    let response = sender
        .send_request(request)
        .await
        .expect("the request failed");
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .expect("failed to read the response body")
        .to_bytes();
    (parts.status, parts.headers, body)
}

#[tokio::test]
#[serial]
async fn returns_the_response_of_the_upstream() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, _, body) = send(&client(), Method::GET, "/any/path?x=1", &[], "").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"ok\n");
}

#[tokio::test]
#[serial]
async fn forwards_the_request_headers() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, headers, body) = send(
        &client(),
        Method::GET,
        "/echo?x=1",
        &[("accept-language", "en"), ("user-agent", "test-agent")],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["accept-language"], "en");
    assert_eq!(headers["user-agent"], "test-agent");
    assert!(body.is_empty());
}

#[tokio::test]
#[serial]
async fn does_not_forward_a_header_that_is_not_on_the_list() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    // The `server` mode sends the request headers back, so the response shows
    // what the upstream received.
    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[
            ("authorization", "Bearer abc"),
            ("cookie", "session=abc"),
            ("x-custom", "yes"),
            ("accept", "text/plain"),
        ],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("authorization"));
    assert!(!headers.contains_key("cookie"));
    assert!(!headers.contains_key("x-custom"));
    assert_eq!(headers["accept"], "text/plain");
}

#[tokio::test]
#[serial]
async fn forwards_the_request_body() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, headers, body) = send(
        &client(),
        Method::POST,
        "/echo",
        &[("content-type", "text/plain")],
        "hello",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "text/plain");
    assert_eq!(&body[..], b"hello");
}

#[tokio::test]
#[serial]
async fn forwards_a_large_body_both_ways_when_the_limits_are_off() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[
            ("PROXY_MAX_REQUEST_BODY_BYTES", "0"),
            ("PROXY_MAX_RESPONSE_BODY_BYTES", "0"),
        ],
    )
    .await;
    // 8 MiB, with a pattern that shows a lost or a reordered chunk.
    let sent: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    let (status, _, received) = send(&client(), Method::POST, "/echo", &[], sent.clone()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(received.len(), sent.len());
    assert!(received[..] == sent[..], "the body changed on the way");
}

#[tokio::test]
#[serial]
async fn replaces_the_forwarding_headers_and_the_host() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    // The `server` mode sends the request headers back, so the response shows
    // what the upstream received.
    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
            ("forwarded", "for=1.2.3.4"),
            ("via", "1.1 other"),
        ],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get_all("x-forwarded-for").iter().count(), 1);
    assert_eq!(headers["x-forwarded-for"], "127.0.0.1");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-host"], PROXY_ADDR);
    // The proxy keeps the `Via` value of the client and adds its own.
    let via: Vec<&str> = headers
        .get_all("via")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(via.len(), 2, "{via:?}");
    assert_eq!(via[0], "1.1 other");
    assert!(via[1].starts_with("1.1 reverse-proxy-"), "{via:?}");
    assert!(!headers.contains_key("forwarded"));
    assert_eq!(headers["host"], SERVER_ADDR);
}

#[tokio::test]
#[serial]
async fn removes_the_hop_by_hop_headers() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    // The `server` mode sends the request headers back, so the response shows
    // what the upstream received.
    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[
            ("connection", "x-secret"),
            ("x-secret", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic abc"),
            ("accept", "text/plain"),
        ],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("x-secret"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("proxy-authorization"));
    assert_eq!(headers["accept"], "text/plain");
}

#[tokio::test]
#[serial]
async fn passes_a_503_with_retry_after_through_unchanged() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    // The upstream answers `503` itself. The proxy must not change it to its own
    // error status (`502` or `504`).
    let (status, headers, _) = send(&client(), Method::GET, "/status/503", &[], "").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers["retry-after"], "1");
}

#[tokio::test]
#[serial]
async fn keeps_a_valid_request_id_and_sends_it_both_ways() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    // The `server` mode sends the request headers back. The response then shows
    // the ID that the upstream received.
    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[("x-request-id", "client-id-1")],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get_all("x-request-id").iter().count(), 1);
    assert_eq!(headers["x-request-id"], "client-id-1");
}

#[tokio::test]
#[serial]
async fn makes_a_request_id_when_the_client_sends_none() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let client = client();

    let (_, first, _) = send(&client, Method::GET, "/echo", &[], "").await;
    let (_, second, _) = send(&client, Method::GET, "/echo", &[], "").await;

    assert_eq!(first["x-request-id"].len(), 36);
    assert_ne!(first["x-request-id"], second["x-request-id"]);
}

#[tokio::test]
#[serial]
async fn replaces_a_request_id_that_is_not_valid() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let too_long = "a".repeat(200);

    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[("x-request-id", &too_long)],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-request-id"].len(), 36);
}

#[tokio::test]
#[serial]
async fn returns_a_request_id_on_a_502() {
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/",
        &[("x-request-id", "client-id-2")],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(headers["x-request-id"], "client-id-2");
}

#[tokio::test]
#[serial]
async fn returns_502_when_the_upstream_is_down() {
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, _, body) = send(&client(), Method::GET, "/", &[], "").await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(&body[..], b"Bad Gateway");
}

#[tokio::test]
#[serial]
async fn rejects_a_client_without_a_certificate() {
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    assert_rejected(&make_connector(&[b"http/1.1"], None)).await;
}

#[tokio::test]
#[serial]
async fn rejects_a_client_certificate_from_an_untrusted_ca() {
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let connector = make_connector(
        &[b"http/1.1"],
        Some((UNTRUSTED_CERT_PATH, UNTRUSTED_KEY_PATH)),
    );

    assert_rejected(&connector).await;
}

#[tokio::test]
#[serial]
async fn rejects_an_expired_client_certificate() {
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let connector = make_connector(&[b"http/1.1"], Some((EXPIRED_CERT_PATH, EXPIRED_KEY_PATH)));

    assert_rejected(&connector).await;
}

#[tokio::test]
#[serial]
async fn rejects_a_request_from_a_certificate_without_an_identity() {
    // No upstream runs. A 502 would mean that the proxy tried to connect.
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let client = TestClient {
        connector: make_connector(&[b"http/1.1"], Some((NO_URI_CERT_PATH, NO_URI_KEY_PATH))),
    };

    let (status, headers, body) = send(&client, Method::GET, "/", &[], "").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key("x-request-id"));
    assert!(body.is_empty());
}

#[tokio::test]
#[serial]
async fn forwards_a_request_that_the_policy_allows() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let client = reporting_client();

    let (status, _, body) = send(&client, Method::GET, "/reports/1?x=1", &[], "").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"ok\n");
}

#[tokio::test]
#[serial]
async fn rejects_a_request_that_the_policy_does_not_allow() {
    // No upstream runs. A 502 would mean that the proxy tried to connect.
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let reporting = reporting_client();

    for (client, method, path) in [
        // The path is not in the policy of this identity.
        (&reporting, Method::GET, "/echo"),
        // The method is not allowed.
        (&reporting, Method::POST, "/reports/1"),
        // The prefix needs one more segment.
        (&reporting, Method::GET, "/reports"),
        (&client(), Method::GET, "/payments"),
    ] {
        let (status, headers, body) = send(client, method.clone(), path, &[], "").await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert!(headers.contains_key("x-request-id"));
        assert!(body.is_empty());
    }
}

#[tokio::test]
#[serial]
async fn rejects_a_path_that_is_not_valid() {
    // No upstream runs. A 502 would mean that the proxy tried to connect.
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    for path in [
        "/echo/../echo",
        "/echo/%2e%2e/echo",
        "/echo//x",
        "/status/%2Fx",
    ] {
        let (status, _, body) = send(&client(), Method::GET, path, &[], "").await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert!(body.is_empty());
    }
}

#[tokio::test]
#[serial]
async fn writes_an_audit_event_for_a_request_that_the_policy_allows() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, _, _) = send(
        &reporting_client(),
        Method::GET,
        "/reports/1?x=1",
        &[("x-request-id", "audit-test-1")],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let events = proxy.audit_events();
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event["target"], "audit");
    assert_eq!(event["request_id"], "audit-test-1");
    assert_eq!(event["identity"], "spiffe://acme/prod/reporting-agent");
    assert_eq!(event["method"], "GET");
    // The query is not in the event.
    assert_eq!(event["path"], "/reports/1");
    assert_eq!(event["host"], PROXY_ADDR);
    assert_eq!(event["decision"], "ALLOW");
    assert_eq!(event["status"], 200);
    assert_eq!(event["upstream_status"], 200);
    assert!(event["latency_ms"].is_u64(), "{event}");
    assert!(event["timestamp"].is_string(), "{event}");
    assert!(event.get("reason").is_none(), "{event}");
}

#[tokio::test]
#[serial]
async fn writes_an_audit_event_for_each_request_that_the_proxy_denies() {
    // No upstream runs. The proxy never connects to it for these requests.
    let proxy = Program::start("proxy", PROXY_ADDR).await;
    let no_identity = TestClient {
        connector: make_connector(&[b"http/1.1"], Some((NO_URI_CERT_PATH, NO_URI_KEY_PATH))),
    };

    send(&no_identity, Method::GET, "/", &[], "").await;
    send(&client(), Method::GET, "/echo/../echo", &[], "").await;
    send(&reporting_client(), Method::POST, "/reports/1", &[], "").await;

    let events = proxy.audit_events();
    assert_eq!(events.len(), 3, "{events:?}");
    for event in &events {
        assert_eq!(event["decision"], "DENY", "{event}");
        assert!(event.get("upstream_status").is_none(), "{event}");
        assert!(event["request_id"].is_string(), "{event}");
    }
    // No valid identity: the event has no identity.
    assert_eq!(events[0]["reason"], "no_identity");
    assert_eq!(events[0]["status"], 401);
    assert!(events[0].get("identity").is_none(), "{}", events[0]);
    assert_eq!(events[1]["reason"], "invalid_path");
    assert_eq!(events[1]["status"], 400);
    assert_eq!(events[1]["identity"], "spiffe://acme/prod/payment-agent");
    assert_eq!(events[2]["reason"], "policy");
    assert_eq!(events[2]["status"], 403);
    assert_eq!(events[2]["method"], "POST");
}

#[tokio::test]
#[serial]
async fn the_audit_event_of_a_502_has_no_upstream_status() {
    let proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, _, _) = send(&client(), Method::GET, "/", &[], "").await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let events = proxy.audit_events();
    assert_eq!(events.len(), 1, "{events:?}");
    // The policy allowed the request. The upstream did not answer.
    assert_eq!(events[0]["decision"], "ALLOW");
    assert_eq!(events[0]["status"], 502);
    assert!(events[0].get("upstream_status").is_none(), "{}", events[0]);
}

#[tokio::test]
#[serial]
async fn keeps_secrets_out_of_the_output() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start("proxy", PROXY_ADDR).await;

    send(
        &reporting_client(),
        Method::GET,
        "/reports/1?token=query-secret",
        &[
            ("authorization", "Bearer header-secret"),
            ("cookie", "session=cookie-secret"),
        ],
        "",
    )
    .await;

    let output = format!(
        "{}\n{}",
        std::fs::read_to_string(&proxy.stdout_path).expect("failed to read STDOUT"),
        proxy.stderr()
    );
    for secret in ["query-secret", "header-secret", "cookie-secret"] {
        assert!(!output.contains(secret), "{secret} is in the output");
    }
}

#[tokio::test]
#[serial]
async fn writes_audit_events_to_stdout_and_other_logs_to_stderr() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start("proxy", PROXY_ADDR).await;

    send(&reporting_client(), Method::GET, "/reports/1", &[], "").await;

    assert!(proxy.stderr().contains("listening"), "{}", proxy.stderr());
    assert!(!proxy.stderr().contains("request_id"), "{}", proxy.stderr());
    // `audit_events` panics if a line of STDOUT is not a JSON object.
    assert_eq!(proxy.audit_events().len(), 1);
}

#[tokio::test]
#[serial]
async fn ctrl_c_stops_the_proxy_with_exit_code_0() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let mut proxy = Program::start("proxy", PROXY_ADDR).await;
    let client = client();
    let (status, _, _) = send(&client, Method::GET, "/", &[], "").await;
    assert_eq!(status, StatusCode::OK);
    drop(client);

    proxy.interrupt();

    let status = proxy.wait_for_exit(Duration::from_secs(5)).await;
    assert_eq!(status.code(), Some(0), "{}", proxy.stderr());
    proxy.assert_not_listening();
}

#[tokio::test]
#[serial]
async fn negotiates_h2_and_http_1_1_with_alpn() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    for (offered, chosen) in [(&b"h2"[..], &b"h2"[..]), (b"http/1.1", b"http/1.1")] {
        let stream = connect(&tls_connector(&[offered])).await;

        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(chosen));
    }
}

#[tokio::test]
#[serial]
async fn keeps_running_after_a_plain_http_request_to_the_tls_port() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let mut plain = tokio::net::TcpStream::connect(PROXY_ADDR).await.unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    // The proxy closes the connection. It does not send an HTTP response.
    // A TLS alert is allowed, and the read can fail with a reset.
    let mut reply = Vec::new();
    let _ = plain.read_to_end(&mut reply).await;
    assert!(
        !reply.starts_with(b"HTTP/"),
        "got an HTTP response on the TLS port"
    );

    let (status, _, _) = send(&client(), Method::GET, "/", &[], "").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn answers_508_and_does_not_forward_a_request_that_came_back_to_the_proxy() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start("proxy", PROXY_ADDR).await;

    // The `server` mode sends the request headers back. The response shows the
    // `Via` value that the proxy added. A proxy that gets a request with this
    // value has seen the request before.
    let (status, headers, _) = send(&client(), Method::GET, "/echo", &[], "").await;
    assert_eq!(status, StatusCode::OK);
    let via = headers["via"].to_str().unwrap().to_string();

    let (status, _, body) = send(
        &client(),
        Method::GET,
        "/echo",
        &[
            ("via", &format!("1.1 other, {via}")),
            ("x-request-id", "loop-1"),
        ],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::LOOP_DETECTED);
    assert!(body.is_empty());
    let events = proxy.audit_events();
    let event = events.last().expect("no audit event");
    assert_eq!(event["request_id"], "loop-1");
    assert_eq!(event["decision"], "DENY");
    assert_eq!(event["reason"], "loop");
    assert_eq!(event["status"], 508);
    assert!(event.get("upstream_status").is_none(), "{event}");
}

#[tokio::test]
#[serial]
async fn does_not_stop_a_request_that_has_the_name_of_another_proxy() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;

    let (status, _, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[("via", "1.1 reverse-proxy-00000000")],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn exits_with_code_1_when_the_upstream_is_the_proxy() {
    // The program must stop before it binds, so it needs no free port.
    let output = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
        .arg("proxy")
        .env("PROXY_ADDR", PROXY_ADDR)
        .env("SERVER_ADDR", PROXY_ADDR)
        .env("PROXY_TLS_CERT", CERT_PATH)
        .env("PROXY_TLS_KEY", KEY_PATH)
        .env("PROXY_CLIENT_CA", CA_PATH)
        .env("PROXY_POLICY_FILE", POLICY_PATH)
        .output()
        .expect("failed to run the program");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    // `main` prints the error in Debug format, so the text is the variant name.
    assert!(stderr.contains("UpstreamIsProxy"), "{stderr}");
}

#[tokio::test]
#[serial]
async fn exits_with_code_1_when_a_required_variable_is_not_set() {
    for missing in [
        "PROXY_TLS_CERT",
        "PROXY_TLS_KEY",
        "PROXY_CLIENT_CA",
        "PROXY_POLICY_FILE",
    ] {
        // The program must stop before it binds, so it needs no free port.
        let output = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .arg("proxy")
            .env("PROXY_ADDR", PROXY_ADDR)
            .env("SERVER_ADDR", SERVER_ADDR)
            .env("PROXY_TLS_CERT", CERT_PATH)
            .env("PROXY_TLS_KEY", KEY_PATH)
            .env("PROXY_CLIENT_CA", CA_PATH)
            .env("PROXY_POLICY_FILE", POLICY_PATH)
            .env_remove(missing)
            .output()
            .expect("failed to run the program");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{missing}: {stderr}");
        assert!(stderr.contains(missing), "{missing}: {stderr}");
    }
}

/// The path of a file in the `dev-certs` directory.
fn dev_cert_path(name: &str) -> String {
    format!("{}/dev-certs/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Make an empty directory in the temporary directory for a test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("reverse-proxy-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("failed to create the directory");
    dir
}

/// Replace `target` with a copy of `source`. Write a new file and rename it, so
/// the proxy never sees a half-written file.
fn replace_file(target: &std::path::Path, source: &str) {
    let new = target.with_extension("new");
    std::fs::copy(source, &new).expect("failed to copy the file");
    std::fs::rename(&new, target).expect("failed to rename the file");
}

/// Connect with `connector` and send one request. Return `true` if the proxy
/// sends an HTTP response, so the TLS handshake worked.
async fn gets_a_response(connector: &TlsConnector) -> bool {
    let Ok(tcp) = tokio::net::TcpStream::connect(PROXY_ADDR).await else {
        return false;
    };
    let name = ServerName::try_from("localhost").expect("not a valid name");
    let Ok(mut stream) = connector.connect(name, tcp).await else {
        return false;
    };
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return false;
    }
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply).await;
    reply.starts_with(b"HTTP/1.1")
}

/// Wait until `gets_a_response` gives `expected` for `connector`. Panic after 10 seconds.
async fn wait_for_handshake(connector: &TlsConnector, expected: bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while gets_a_response(connector).await != expected {
        assert!(Instant::now() < deadline, "{what}");
        sleep(Duration::from_millis(100)).await;
    }
}

fn connector_for(agent: &str) -> TlsConnector {
    make_connector(
        &[b"http/1.1"],
        Some((
            &dev_cert_path(&format!("{agent}.pem")),
            &dev_cert_path(&format!("{agent}.key")),
        )),
    )
}

#[tokio::test]
#[serial]
async fn trusts_the_new_cas_after_the_ca_file_changes() {
    let dir = temp_dir("reload-ca");
    let ca_file = dir.join("ca.pem");
    std::fs::copy(CA_PATH, &ca_file).unwrap();
    let _proxy = Program::start_with_ca("proxy", PROXY_ADDR, ca_file.to_str().unwrap()).await;
    let payment = connector_for("payment-agent");
    let untrusted = connector_for("untrusted-agent");
    assert!(gets_a_response(&payment).await);
    assert!(!gets_a_response(&untrusted).await);

    replace_file(&ca_file, &dev_cert_path("other-ca.pem"));

    wait_for_handshake(&untrusted, true, "the new CA is not trusted").await;
    assert!(!gets_a_response(&payment).await, "the old CA is trusted");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
#[serial]
async fn keeps_the_old_cas_when_the_new_ca_file_is_not_valid() {
    let dir = temp_dir("reload-bad-ca");
    let ca_file = dir.join("ca.pem");
    std::fs::copy(CA_PATH, &ca_file).unwrap();
    let proxy = Program::start_with_ca("proxy", PROXY_ADDR, ca_file.to_str().unwrap()).await;
    let payment = connector_for("payment-agent");

    std::fs::write(&ca_file, "not a PEM file\n").unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !proxy.stderr().contains("keeping the old CAs") {
        assert!(Instant::now() < deadline, "no warning:\n{}", proxy.stderr());
        sleep(Duration::from_millis(100)).await;
    }
    assert!(gets_a_response(&payment).await, "the old CA is not trusted");

    // A good file works again after the bad one.
    replace_file(&ca_file, &dev_cert_path("other-ca.pem"));
    wait_for_handshake(&connector_for("untrusted-agent"), true, "no reload").await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
#[serial]
async fn lets_an_open_connection_finish_after_its_ca_is_removed() {
    let dir = temp_dir("reload-open-connection");
    let ca_file = dir.join("ca.pem");
    std::fs::copy(CA_PATH, &ca_file).unwrap();
    let _proxy = Program::start_with_ca("proxy", PROXY_ADDR, ca_file.to_str().unwrap()).await;
    let payment = connector_for("payment-agent");
    let stream = connect(&payment).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("the HTTP handshake failed");
    tokio::spawn(connection);
    let request = || {
        Request::builder()
            .uri("/")
            .header(HOST, PROXY_ADDR)
            .body(Full::new(Bytes::new()))
            .unwrap()
    };
    // No upstream runs, so a request that passes gets `502`.
    let first = sender.send_request(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::BAD_GATEWAY);

    replace_file(&ca_file, &dev_cert_path("other-ca.pem"));
    wait_for_handshake(&payment, false, "the old CA is still trusted").await;

    let second = sender.send_request(request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::BAD_GATEWAY);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
#[serial]
async fn reloads_the_ca_file_when_a_symbolic_link_changes() {
    use std::os::unix::fs::symlink;
    // The layout of a Kubernetes volume: `ca.pem` -> `data/ca.pem`, and `data` -> `v1`.
    let dir = temp_dir("reload-symlink");
    for (version, source) in [
        ("v1", CA_PATH.to_string()),
        ("v2", dev_cert_path("other-ca.pem")),
    ] {
        std::fs::create_dir(dir.join(version)).unwrap();
        std::fs::copy(source, dir.join(version).join("ca.pem")).unwrap();
    }
    symlink("v1", dir.join("data")).unwrap();
    symlink("data/ca.pem", dir.join("ca.pem")).unwrap();
    let ca_file = dir.join("ca.pem");
    let _proxy = Program::start_with_ca("proxy", PROXY_ADDR, ca_file.to_str().unwrap()).await;
    let untrusted = connector_for("untrusted-agent");
    assert!(!gets_a_response(&untrusted).await);

    symlink("v2", dir.join("data.new")).unwrap();
    std::fs::rename(dir.join("data.new"), dir.join("data")).unwrap();

    wait_for_handshake(&untrusted, true, "the new CA is not trusted").await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Listen on the upstream address. The kernel accepts connections, and nothing
/// reads or answers them.
fn hang_as_upstream() -> std::net::TcpListener {
    std::net::TcpListener::bind(SERVER_ADDR).expect("another process uses the upstream address")
}

#[tokio::test]
#[serial]
async fn answers_504_when_the_upstream_does_not_answer_in_time() {
    let _upstream = hang_as_upstream();
    let proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[("PROXY_UPSTREAM_TIMEOUT_SECS", "1")],
    )
    .await;

    let started = Instant::now();
    let (status, _, body) = send(&client(), Method::GET, "/", &[], "").await;

    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(&body[..], b"Gateway Timeout");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_secs(5));
    let events = proxy.audit_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["decision"], "ALLOW");
    assert_eq!(events[0]["status"], 504);
    assert!(events[0].get("upstream_status").is_none());
}

#[tokio::test]
#[serial]
async fn exits_with_code_1_when_the_upstream_timeout_is_not_a_number_of_seconds() {
    let output = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
        .arg("proxy")
        .env("PROXY_UPSTREAM_TIMEOUT_SECS", "0")
        .env("PROXY_TLS_CERT", CERT_PATH)
        .env("PROXY_TLS_KEY", KEY_PATH)
        .env("PROXY_CLIENT_CA", CA_PATH)
        .env("PROXY_POLICY_FILE", POLICY_PATH)
        .output()
        .expect("failed to run the program");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("PROXY_UPSTREAM_TIMEOUT_SECS"),
        "got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";

#[tokio::test]
#[serial]
async fn sends_the_trace_id_of_the_client_to_the_upstream() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start("proxy", PROXY_ADDR).await;
    let traceparent = format!("00-{TRACE_ID}-b7ad6b7169203331-01");

    let (status, headers, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[
            ("traceparent", &traceparent),
            ("tracestate", "vendor=value"),
            ("baggage", "user=secret"),
        ],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Same trace, new span: the span of the proxy is the parent for the upstream.
    let sent = headers["traceparent"].to_str().unwrap();
    assert!(sent.starts_with(&format!("00-{TRACE_ID}-")), "got: {sent}");
    assert!(!sent.contains("b7ad6b7169203331"), "got: {sent}");
    assert_eq!(headers["tracestate"], "vendor=value");
    assert!(!headers.contains_key("baggage"));
    let events = proxy.audit_events();
    assert_eq!(events[0]["trace_id"], TRACE_ID);
}

#[tokio::test]
#[serial]
async fn starts_a_new_trace_when_the_client_sends_no_valid_trace_context() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start("proxy", PROXY_ADDR).await;

    let (_, none, _) = send(&client(), Method::GET, "/echo", &[], "").await;
    let (_, bad, _) = send(
        &client(),
        Method::GET,
        "/echo",
        &[("traceparent", "not-valid")],
        "",
    )
    .await;

    let events = proxy.audit_events();
    for (headers, event) in [none, bad].iter().zip(&events) {
        let sent = headers["traceparent"].to_str().unwrap();
        let trace_id = event["trace_id"].as_str().expect("no trace_id");
        assert_eq!(trace_id.len(), 32);
        assert!(sent.starts_with(&format!("00-{trace_id}-")), "got: {sent}");
        assert!(!headers.contains_key("tracestate"));
    }
    assert_ne!(events[0]["trace_id"], events[1]["trace_id"]);
}

#[tokio::test]
#[serial]
async fn answers_408_when_the_client_sends_the_request_body_too_slowly() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[("PROXY_CLIENT_TIMEOUT_SECS", "1")],
    )
    .await;
    let mut stream = connect(&client().connector).await;
    // The request says that the body has 10 bytes. The client sends 3 and stops.
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc",
        )
        .await
        .unwrap();

    let started = Instant::now();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply))
        .await
        .expect("the proxy did not answer in time")
        .ok();

    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 408"),
        "got: {}",
        String::from_utf8_lossy(&reply)
    );
    assert!(started.elapsed() < Duration::from_secs(4));
    let events = proxy.audit_events();
    assert_eq!(events[0]["status"], 408);
    assert!(events[0].get("upstream_status").is_none());
}

#[tokio::test]
#[serial]
async fn closes_the_connection_of_a_client_that_sends_the_request_head_too_slowly() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[("PROXY_CLIENT_TIMEOUT_SECS", "1")],
    )
    .await;
    let mut stream = connect(&client().connector).await;
    // The head has no empty line at the end, so it is never complete.
    stream
        .write_all(b"GET /echo HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();

    let mut reply = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply)).await;

    assert!(result.is_ok(), "the proxy kept the connection open");
    assert!(!String::from_utf8_lossy(&reply).contains("200 OK"));
}

/// The limit for the body tests, in bytes.
const BODY_LIMIT: usize = 1024;

#[tokio::test]
#[serial]
async fn answers_413_for_a_request_body_above_the_limit() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[
            ("PROXY_MAX_REQUEST_BODY_BYTES", "1024"),
            ("PROXY_MAX_RESPONSE_BODY_BYTES", "0"),
        ],
    )
    .await;

    let (at_limit, _, echoed) = send(
        &client(),
        Method::POST,
        "/echo",
        &[],
        vec![b'x'; BODY_LIMIT],
    )
    .await;
    let (too_large, _, _) = send(
        &client(),
        Method::POST,
        "/echo",
        &[],
        vec![b'x'; BODY_LIMIT + 1],
    )
    .await;

    assert_eq!(at_limit, StatusCode::OK);
    assert_eq!(echoed.len(), BODY_LIMIT);
    assert_eq!(too_large, StatusCode::PAYLOAD_TOO_LARGE);
    let events = proxy.audit_events();
    assert_eq!(events[1]["status"], 413);
    assert!(events[1].get("upstream_status").is_none());
}

#[tokio::test]
#[serial]
async fn answers_413_when_a_streamed_request_body_grows_above_the_limit() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[("PROXY_MAX_REQUEST_BODY_BYTES", "1024")],
    )
    .await;
    let mut stream = connect(&client().connector).await;
    // A chunked body has no length. Two chunks of 600 bytes (0x258) are 1200 bytes.
    let chunk = "x".repeat(600);
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n258\r\n{chunk}\r\n258\r\n{chunk}\r\n0\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply))
        .await
        .expect("the proxy did not answer in time")
        .ok();

    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 413"),
        "got: {}",
        String::from_utf8_lossy(&reply)
    );
    assert_eq!(proxy.audit_events()[0]["status"], 413);
}

#[tokio::test]
#[serial]
async fn answers_502_for_a_response_body_above_the_limit() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let proxy = Program::start_with(
        "proxy",
        PROXY_ADDR,
        CA_PATH,
        &[
            ("PROXY_MAX_REQUEST_BODY_BYTES", "0"),
            ("PROXY_MAX_RESPONSE_BODY_BYTES", "1024"),
        ],
    )
    .await;

    // The `server` mode sends the request body back, so its size is the size
    // of the response body.
    let (at_limit, _, echoed) = send(
        &client(),
        Method::POST,
        "/echo",
        &[],
        vec![b'x'; BODY_LIMIT],
    )
    .await;
    let (too_large, _, body) = send(
        &client(),
        Method::POST,
        "/echo",
        &[],
        vec![b'x'; BODY_LIMIT + 1],
    )
    .await;

    assert_eq!(at_limit, StatusCode::OK);
    assert_eq!(echoed.len(), BODY_LIMIT);
    assert_eq!(too_large, StatusCode::BAD_GATEWAY);
    assert_eq!(&body[..], b"Bad Gateway");
    let events = proxy.audit_events();
    assert_eq!(events[1]["status"], 502);
    assert_eq!(events[1]["upstream_status"], 200);
}

#[tokio::test]
#[serial]
async fn limits_the_request_body_to_1_mib_by_default() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let mib = 1024 * 1024;

    let (at_limit, _, _) = send(&client(), Method::POST, "/echo", &[], vec![b'x'; mib]).await;
    let (too_large, _, _) = send(&client(), Method::POST, "/echo", &[], vec![b'x'; mib + 1]).await;

    assert_eq!(at_limit, StatusCode::OK);
    assert_eq!(too_large, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
#[serial]
async fn exits_with_code_1_when_a_body_limit_is_not_a_number_of_bytes() {
    let output = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
        .arg("proxy")
        .env("PROXY_MAX_RESPONSE_BODY_BYTES", "1MiB")
        .env("PROXY_TLS_CERT", CERT_PATH)
        .env("PROXY_TLS_KEY", KEY_PATH)
        .env("PROXY_CLIENT_CA", CA_PATH)
        .env("PROXY_POLICY_FILE", POLICY_PATH)
        .output()
        .expect("failed to run the program");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("PROXY_MAX_RESPONSE_BODY_BYTES"),
        "got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
