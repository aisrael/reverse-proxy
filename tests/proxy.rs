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
const PROXY_ADDR: &str = "127.0.0.1:8080";

/// The address of the `server` mode (the upstream).
const SERVER_ADDR: &str = "127.0.0.1:9000";

/// The certificate of the dev CA. The proxy uses a certificate that this CA signed.
const CA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/ca.pem");

/// The certificate and the key of the proxy.
const CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/server.pem");
const KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/server.key");

/// A running copy of the program. The process stops when this value is dropped.
struct Program {
    child: Child,
    addr: &'static str,
    /// The file that holds the STDERR of the program. The file is read only if
    /// the program fails to start or to stop.
    stderr_path: PathBuf,
}

impl Program {
    /// Start the program in `mode` and wait until it accepts connections on `addr`.
    ///
    /// Panic if another process already uses `addr`. Panic at once, with the
    /// STDERR of the program, if the program exits during startup. Panic with
    /// the STDERR too if the program does not accept connections within 10
    /// seconds.
    async fn start(mode: &str, addr: &'static str) -> Self {
        assert!(
            TcpStream::connect(addr).is_err(),
            "another process uses {addr}. Stop it and run the tests again"
        );

        let stderr_path = std::env::temp_dir().join(format!(
            "reverse-proxy-{}-{mode}.stderr",
            std::process::id()
        ));
        let stderr = File::create(&stderr_path).expect("failed to create the STDERR file");
        let child = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .arg(mode)
            // Set both addresses, so the values from the shell (for example,
            // from `.envrc`) cannot change them.
            .env("PROXY_ADDR", PROXY_ADDR)
            .env("SERVER_ADDR", SERVER_ADDR)
            .env("PROXY_TLS_CERT", CERT_PATH)
            .env("PROXY_TLS_KEY", KEY_PATH)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to start the program");
        let mut program = Program {
            child,
            addr,
            stderr_path,
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
    }
}

/// A client that trusts the dev CA. It opens a new connection for each request.
struct TestClient {
    connector: TlsConnector,
}

fn client() -> TestClient {
    TestClient {
        connector: tls_connector(&[b"http/1.1"]),
    }
}

/// Make a TLS connector that trusts the dev CA and offers `alpn` protocols.
fn tls_connector(alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(CA_PATH)
        .expect("cannot read the CA. Run ./scripts/gen-dev-certs.sh first");
    for cert in certs {
        roots
            .add(cert.expect("the CA file is not valid"))
            .expect("the CA certificate is not valid");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("invalid protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
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

/// Send a request to the proxy with a valid `x-api-key`. Return the status,
/// the headers and the body.
async fn send(
    client: &TestClient,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut all = vec![("x-api-key", "test")];
    all.extend_from_slice(headers);
    send_raw(client, method, path, &all, body).await
}

/// Send a request to the proxy with exactly the given headers.
async fn send_raw(
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
        &[("x-test", "one"), ("x-other", "two")],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-test"], "one");
    assert_eq!(headers["x-other"], "two");
    assert!(body.is_empty());
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
        &[("x-test", "one")],
        "hello",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-test"], "one");
    assert_eq!(&body[..], b"hello");
}

#[tokio::test]
#[serial]
async fn forwards_a_large_body_both_ways() {
    let _server = Program::start("server", SERVER_ADDR).await;
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
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
    assert_eq!(headers["via"], "1.1 reverse-proxy");
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
            ("x-kept", "yes"),
        ],
        "",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("x-secret"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("proxy-authorization"));
    assert_eq!(headers["x-kept"], "yes");
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
async fn rejects_a_request_without_an_api_key_before_it_reaches_the_upstream() {
    // No upstream runs. A 502 would mean that the proxy tried to connect.
    let _proxy = Program::start("proxy", PROXY_ADDR).await;
    let client = client();

    let (status, _, body) = send_raw(&client, Method::GET, "/", &[], "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.is_empty());

    let (status, _, _) = send_raw(&client, Method::GET, "/", &[("x-api-key", "")], "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
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
async fn exits_with_code_1_when_a_tls_variable_is_not_set() {
    for missing in ["PROXY_TLS_CERT", "PROXY_TLS_KEY"] {
        // The program must stop before it binds, so it needs no free port.
        let output = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .arg("proxy")
            .env("PROXY_ADDR", PROXY_ADDR)
            .env("SERVER_ADDR", SERVER_ADDR)
            .env("PROXY_TLS_CERT", CERT_PATH)
            .env("PROXY_TLS_KEY", KEY_PATH)
            .env_remove(missing)
            .output()
            .expect("failed to run the program");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{missing}: {stderr}");
        assert!(stderr.contains(missing), "{missing}: {stderr}");
    }
}
