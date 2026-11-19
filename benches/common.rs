//! Code that both benchmarks share.
//!
//! A benchmark either starts its own copy of the program (the `server` mode
//! and the `proxy` mode, each on a free port), or it uses a copy that is
//! already running. The program is a binary crate, so the benchmarks start the
//! compiled binary. They do not link to its code.
//!
//! The proxy needs the dev certificates. `Stack::start` makes them with
//! `./scripts/gen-dev-certs.sh` if they are missing or expired.

// Each benchmark uses a part of this file.
#![allow(dead_code)]

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::Request;
use hyper::StatusCode;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::HOST;
use hyper_util::rt::TokioIo;
use rand::RngExt;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use rand::rngs::StdRng;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::pem::PemObject;
use std::fs::File;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio_rustls::TlsConnector;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// The size of a request body, in bytes. Every body has a random size in this range.
pub const MIN_BODY_BYTES: usize = 32;
pub const MAX_BODY_BYTES: usize = 1024;

/// The path that every request uses. The `server` mode sends the body back.
pub const PATH: &str = "/echo";

/// Return a port that no process uses now. The operating system chooses it.
///
/// Another process could take the port before the program does. This is
/// unlikely, and the program then fails to start with a clear message.
pub fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("failed to bind to a free port")
        .local_addr()
        .expect("failed to read the address")
        .port()
}

/// A running copy of the program. The process stops when this value is dropped.
pub struct Program {
    child: Child,
    /// The file that holds the STDERR of the program. The file is read only if
    /// the program fails to start.
    stderr_path: PathBuf,
}

impl Program {
    /// Start the program in `mode` and wait until it accepts connections on
    /// `addr` (`host:port`). `env` sets more environment variables.
    ///
    /// The program writes no audit events and no log lines to the terminal. The
    /// STDOUT goes nowhere, so the audit events do not slow the benchmark. The
    /// log level is `warn`.
    ///
    /// Panic, with the STDERR of the program, if it exits during startup or
    /// does not accept connections within 10 seconds.
    pub fn start(mode: &str, addr: &str, env: &[(&str, &str)]) -> Self {
        let stderr_path = std::env::temp_dir().join(format!(
            "reverse-proxy-bench-{}-{}.stderr",
            std::process::id(),
            addr.replace(':', "-")
        ));
        let stderr = File::create(&stderr_path).expect("failed to create the STDERR file");
        let child = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .arg(mode)
            .env("RUST_LOG", "warn")
            .envs(env.iter().copied())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to start the program");
        let mut program = Program { child, stderr_path };

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
            std::thread::sleep(Duration::from_millis(50));
        }
        program
    }

    /// What the program wrote to STDERR so far.
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|err| format!("(unable to read the STDERR file: {err})"))
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.stderr_path);
    }
}

/// The `server` mode (the upstream) and the `proxy` mode in front of it. Each
/// listens on its own free port. Both stop when this value is dropped.
pub struct Stack {
    /// The address (`host:port`) of the upstream.
    pub upstream_addr: String,
    /// The address (`host:port`) of the proxy.
    pub proxy_addr: String,
    // The proxy is first, so it stops before the upstream.
    _proxy: Program,
    _server: Program,
}

impl Stack {
    /// Start the upstream and the proxy.
    ///
    /// The proxy uses the dev certificates, and the policy of the tests, which
    /// lets the client `payment-agent` send `POST /echo`. Every other setting
    /// of the proxy is the default, or comes from the environment of the
    /// benchmark. The proxy exports spans if `OTEL_EXPORTER_OTLP_ENDPOINT` is
    /// set. The upstream never exports.
    pub fn start() -> Self {
        make_dev_certificates();
        let upstream_addr = format!("127.0.0.1:{}", free_port());
        let server = Program::start(
            "server",
            &upstream_addr,
            &[
                ("SERVER_ADDR", &upstream_addr),
                // Only the proxy sends spans.
                ("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
                ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", ""),
                ("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", ""),
            ],
        );
        let proxy_addr = format!("127.0.0.1:{}", free_port());
        let proxy = Program::start(
            "proxy",
            &proxy_addr,
            &[
                ("PROXY_ADDR", &proxy_addr),
                ("SERVER_ADDR", &upstream_addr),
                ("PROXY_TLS_CERT", &format!("{ROOT}/dev-certs/server.pem")),
                ("PROXY_TLS_KEY", &format!("{ROOT}/dev-certs/server.key")),
                ("PROXY_CLIENT_CA", &format!("{ROOT}/dev-certs/ca.pem")),
                (
                    "PROXY_POLICY_FILE",
                    &format!("{ROOT}/tests/fixtures/policies.yaml"),
                ),
            ],
        );
        Stack {
            upstream_addr,
            proxy_addr,
            _proxy: proxy,
            _server: server,
        }
    }
}

/// Make the dev certificates that are missing or expired.
fn make_dev_certificates() {
    let status = Command::new(format!("{ROOT}/scripts/gen-dev-certs.sh"))
        .status()
        .expect("failed to run scripts/gen-dev-certs.sh");
    assert!(status.success(), "scripts/gen-dev-certs.sh failed");
}

/// Where a benchmark sends its requests.
pub enum Target {
    /// A stack that the benchmark started. It stops with the benchmark.
    Spawned(Stack),
    /// A stack that is already running. The addresses are `host:port`.
    External { proxy: String, upstream: String },
}

impl Target {
    /// Use the stack at `proxy` and `upstream` if both are given. Use none, and
    /// start a new stack, if neither is given. Panic if only one is given, or
    /// if a given address does not accept connections.
    pub fn connect(proxy: Option<&str>, upstream: Option<&str>) -> Self {
        match (proxy, upstream) {
            (None, None) => Target::Spawned(Stack::start()),
            (Some(proxy), Some(upstream)) => {
                for addr in [proxy, upstream] {
                    assert!(
                        TcpStream::connect(addr).is_ok(),
                        "nothing accepts connections on {addr}"
                    );
                }
                Target::External {
                    proxy: proxy.to_string(),
                    upstream: upstream.to_string(),
                }
            }
            _ => panic!("give both the proxy address and the upstream address, or neither"),
        }
    }

    /// The address (`host:port`) of the proxy.
    pub fn proxy_addr(&self) -> &str {
        match self {
            Target::Spawned(stack) => &stack.proxy_addr,
            Target::External { proxy, .. } => proxy,
        }
    }

    /// The address (`host:port`) of the upstream.
    pub fn upstream_addr(&self) -> &str {
        match self {
            Target::Spawned(stack) => &stack.upstream_addr,
            Target::External { upstream, .. } => upstream,
        }
    }

    /// A line that says where the requests go.
    pub fn describe(&self) -> String {
        let how = match self {
            Target::Spawned(_) => "a new stack, started by the benchmark",
            Target::External { .. } => "a stack that was already running",
        };
        format!(
            "target: {how} (proxy {}, upstream {})",
            self.proxy_addr(),
            self.upstream_addr()
        )
    }
}

/// Make a TLS connector that trusts the dev CA and sends the client
/// certificate of `payment-agent`. It offers HTTP/1.1 only.
pub fn make_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(format!("{ROOT}/dev-certs/ca.pem"))
        .expect("cannot read the CA. Run ./scripts/gen-dev-certs.sh first")
    {
        roots
            .add(cert.expect("the CA file is not valid"))
            .expect("the CA certificate is not valid");
    }
    let certs = CertificateDer::pem_file_iter(format!("{ROOT}/dev-certs/payment-agent.pem"))
        .expect("cannot read the client certificate")
        .collect::<Result<Vec<_>, _>>()
        .expect("the client certificate file is not valid");
    let key = PrivateKeyDer::from_pem_file(format!("{ROOT}/dev-certs/payment-agent.key"))
        .expect("cannot read the client key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("invalid protocol versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .expect("the client certificate does not match the key");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}

/// One HTTP/1.1 connection that stays open. A caller has one of these, so a
/// request does not pay for the TCP and TLS handshakes.
pub struct Client {
    sender: SendRequest<Full<Bytes>>,
    host: String,
}

impl Client {
    /// Connect to the upstream at `addr` (`host:port`), in plain HTTP.
    pub async fn connect_upstream(addr: &str) -> Self {
        let tcp = AsyncTcpStream::connect(addr)
            .await
            .expect("failed to connect to the upstream");
        tcp.set_nodelay(true).expect("failed to set TCP_NODELAY");
        Self::handshake(TokioIo::new(tcp), addr).await
    }

    /// Connect to the proxy at `addr` (`host:port`), with TLS and the client
    /// certificate. The certificate of the proxy is for `localhost`.
    pub async fn connect_proxy(addr: &str, connector: &TlsConnector) -> Self {
        let tcp = AsyncTcpStream::connect(addr)
            .await
            .expect("failed to connect to the proxy");
        tcp.set_nodelay(true).expect("failed to set TCP_NODELAY");
        let name = ServerName::try_from("localhost").expect("not a valid name");
        let tls = connector
            .connect(name, tcp)
            .await
            .expect("the TLS handshake failed");
        Self::handshake(TokioIo::new(tls), addr).await
    }

    async fn handshake<T>(io: TokioIo<T>, host: &str) -> Self
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("the HTTP handshake failed");
        tokio::spawn(connection);
        Client {
            sender,
            host: host.to_string(),
        }
    }

    /// Send `POST /echo` with `body`, and read the whole response. Return
    /// `true` if the status is `200`.
    pub async fn post(&mut self, body: Bytes) -> bool {
        let request = Request::builder()
            .method("POST")
            .uri(PATH)
            .header(HOST, &self.host)
            .body(Full::new(body))
            .expect("failed to build the request");
        // hyper needs this before each request on a connection that stays open.
        if self.sender.ready().await.is_err() {
            return false;
        }
        let Ok(response) = self.sender.send_request(request).await else {
            return false;
        };
        let ok = response.status() == StatusCode::OK;
        let response: hyper::Response<Incoming> = response;
        response.into_body().collect().await.is_ok() && ok
    }
}

/// Make a request body: random letters and digits. The length is random too,
/// from `MIN_BODY_BYTES` to `MAX_BODY_BYTES`. Make the body before the timer
/// starts, so the benchmark does not measure it.
pub fn random_body(rng: &mut StdRng) -> Bytes {
    let len = rng.random_range(MIN_BODY_BYTES..=MAX_BODY_BYTES);
    Bytes::from(Alphanumeric.sample_string(rng, len))
}
