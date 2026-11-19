//! Black-box tests for the server.
//!
//! The tests start the compiled server as a child process. They talk to it
//! over HTTP only. They use no types or functions from the server code.
//!
//! The server listens on a fixed address, so only one copy can run at a time.
//! The tests use `#[serial]`, so they run one after the other. Stop any other
//! copy of the server before you run the tests.

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use hyper::Request;
use hyper::StatusCode;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serial_test::serial;
use std::fs::File;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
use tokio::time::sleep;

/// The address that the server listens on.
const ADDR: &str = "127.0.0.1:9000";

/// A running server. The process stops when this value is dropped.
struct Server {
    child: Child,
    /// The file that holds the STDERR of the server. The file is read only if
    /// the server fails to start.
    stderr_path: PathBuf,
}

impl Server {
    /// Start the server and wait until it accepts connections.
    ///
    /// Panic at once, with the STDERR of the server, if the server exits during
    /// startup. Panic with the STDERR too if the server does not accept
    /// connections within 10 seconds.
    async fn start() -> Self {
        assert!(
            TcpStream::connect(ADDR).is_err(),
            "another process uses {ADDR}. Stop it and run the tests again"
        );

        let stderr_path =
            std::env::temp_dir().join(format!("reverse-proxy-{}.stderr", std::process::id()));
        let stderr = File::create(&stderr_path).expect("failed to create the STDERR file");
        let child = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .arg("server")
            // Set the address, so a value from the shell (for example, from
            // `.envrc`) cannot change it.
            .env("SERVER_ADDR", ADDR)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to start the server");
        let mut server = Server { child, stderr_path };

        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(ADDR).is_err() {
            if let Some(status) = server.child.try_wait().expect("failed to wait") {
                panic!(
                    "the server exited during startup ({status}):\n{}",
                    server.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the server did not start within 10 seconds:\n{}",
                server.stderr()
            );
            sleep(Duration::from_millis(50)).await;
        }
        server
    }

    /// What the server wrote to STDERR so far.
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|err| format!("(unable to read the STDERR file: {err})"))
    }

    /// Send SIGINT to the server. This is the same as Ctrl+C.
    fn interrupt(&self) {
        let status = Command::new("kill")
            .arg("-INT")
            .arg(self.child.id().to_string())
            .status()
            .expect("failed to run kill");
        assert!(status.success(), "kill failed ({status})");
    }

    /// Send SIGTERM to the server. Container platforms use this signal to stop a
    /// container.
    fn terminate(&self) {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("failed to run kill");
        assert!(status.success(), "kill failed ({status})");
    }

    /// Wait until the server exits. Panic if it does not exit within `limit`.
    async fn wait_for_exit(&mut self, limit: Duration) -> ExitStatus {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().expect("failed to wait") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the server did not exit within {limit:?}:\n{}",
                self.stderr()
            );
            sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.stderr_path);
    }
}

#[tokio::test]
#[serial]
async fn get_returns_ok_with_a_fixed_body() {
    let _server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .get(format!("http://{ADDR}/any/path?x=1").parse().unwrap())
        .await
        .expect("the request failed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok\n");
}

#[tokio::test]
#[serial]
async fn get_echo_returns_ok_and_the_request_headers() {
    let _server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let request = Request::get(format!("http://{ADDR}/echo"))
        .header("x-test", "one")
        .header("x-other", "two")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(request).await.expect("the request failed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-test"], "one");
    assert_eq!(response.headers()["x-other"], "two");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}

#[tokio::test]
#[serial]
async fn post_echo_returns_the_request_body_and_headers() {
    let _server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let request = Request::post(format!("http://{ADDR}/echo?x=1"))
        .header("x-test", "one")
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(b"hello")))
        .unwrap();

    let response = client.request(request).await.expect("the request failed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-test"], "one");
    assert_eq!(response.headers()["content-type"], "text/plain");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello");
}

#[tokio::test]
#[serial]
async fn status_returns_the_requested_status_code() {
    let _server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .get(format!("http://{ADDR}/status/418").parse().unwrap())
        .await
        .expect("the request failed");

    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert!(!response.headers().contains_key("retry-after"));
}

#[tokio::test]
#[serial]
async fn status_503_has_a_retry_after_header() {
    let _server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .get(format!("http://{ADDR}/status/503").parse().unwrap())
        .await
        .expect("the request failed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
}

#[tokio::test]
#[serial]
async fn status_returns_400_for_an_invalid_code() {
    let _server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    for code in ["abc", "99", "1000", ""] {
        let response = client
            .get(format!("http://{ADDR}/status/{code}").parse().unwrap())
            .await
            .expect("the request failed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "code: {code:?}");
    }
}

#[tokio::test]
#[serial]
async fn writes_one_info_log_line_for_each_request() {
    let server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let request = Request::builder()
        .uri(format!("http://{ADDR}/status/404?token=query-secret"))
        .header("x-request-id", "log-test-1")
        .header("authorization", "Bearer header-secret")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(request).await.expect("the request failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let log = server.stderr();
    let lines: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("request"))
        .collect();
    // The line for the start ("listening") has no `request` field.
    let line = lines
        .iter()
        .find(|line| line.contains(r#"request_id="log-test-1""#))
        .unwrap_or_else(|| panic!("no log line for the request:\n{log}"));
    assert!(line.contains("INFO"), "{line}");
    assert!(line.contains("method=GET"), "{line}");
    assert!(line.contains("path=/status/404"), "{line}");
    assert!(line.contains("status=404"), "{line}");
    // Never log the query or the other headers.
    assert!(!log.contains("query-secret"), "{log}");
    assert!(!log.contains("header-secret"), "{log}");
}

#[tokio::test]
#[serial]
async fn sigterm_stops_the_server_with_exit_code_0() {
    let mut server = Server::start().await;

    server.terminate();

    let status = server.wait_for_exit(Duration::from_secs(5)).await;
    assert_eq!(status.code(), Some(0), "{}", server.stderr());
    assert!(
        TcpStream::connect(ADDR).is_err(),
        "the server still listens after SIGTERM"
    );
}

#[tokio::test]
#[serial]
async fn ctrl_c_stops_the_server_with_exit_code_0() {
    let mut server = Server::start().await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = client
        .get(format!("http://{ADDR}/").parse().unwrap())
        .await
        .expect("the request failed");
    assert_eq!(response.status(), StatusCode::OK);
    drop(client);

    server.interrupt();

    let status = server.wait_for_exit(Duration::from_secs(5)).await;
    assert_eq!(status.code(), Some(0), "{}", server.stderr());
    assert!(
        TcpStream::connect(ADDR).is_err(),
        "the server still accepts connections"
    );
}
