//! Black-box tests for the server.
//!
//! The tests start the compiled server as a child process. They talk to it
//! over HTTP only. They use no types or functions from the server code.
//!
//! The server listens on a fixed address, so only one copy can run at a time.
//! The tests wait for each other. Stop any other copy of the server before you
//! run the tests.

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::StatusCode;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::fs::File;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tokio::time::sleep;

/// The address that the server listens on.
const ADDR: &str = "127.0.0.1:8080";

/// Only one test can use the address at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

/// A running server. The process stops when this value is dropped.
struct Server {
    child: Child,
    /// The file that holds the STDERR of the server. The file is read only if
    /// the server fails to start.
    stderr_path: PathBuf,
    _serial: MutexGuard<'static, ()>,
}

impl Server {
    /// Start the server and wait until it accepts connections.
    ///
    /// Panic at once, with the STDERR of the server, if the server exits during
    /// startup. Panic with the STDERR too if the server does not accept
    /// connections within 10 seconds.
    async fn start() -> Self {
        let serial = SERIAL.lock().await;
        assert!(
            TcpStream::connect(ADDR).is_err(),
            "another process uses {ADDR}. Stop it and run the tests again"
        );

        let stderr_path =
            std::env::temp_dir().join(format!("reverse-proxy-{}.stderr", std::process::id()));
        let stderr = File::create(&stderr_path).expect("failed to create the STDERR file");
        let child = Command::new(env!("CARGO_BIN_EXE_reverse-proxy"))
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to start the server");
        let mut server = Server {
            child,
            stderr_path,
            _serial: serial,
        };

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
