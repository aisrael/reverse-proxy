//! Custom benchmark: speed and percentiles, for the upstream alone and for the
//! proxy in front of it.
//!
//! For each number of callers, and for each target (the upstream, then the
//! proxy), the benchmark runs a warm-up phase and then a measuring phase. Every
//! caller has its own open connection and sends `POST /echo` one request at a
//! time. The body of each request is random text, 32 to 1024 bytes long. The
//! benchmark makes the body before the timer starts. It reports the number of
//! requests, the error rate, the requests per second, and the latency (min,
//! p50, p90, p95, p99 and max). Then it reports what the proxy adds.
//!
//! Only requests that get `200` have a latency. The percentiles use the
//! nearest-rank method on all the latencies of the measuring phase.
//!
//! ```sh
//! cargo bench --bench custom_benchmark
//! cargo bench --bench custom_benchmark -- -C 1,10,100 --duration-secs 10
//! ```
//!
//! The benchmark starts the upstream and the proxy on free ports. To use a
//! stack that is already running (for example, to send the spans to Grafana),
//! give both addresses with `--proxy-addr` and `--upstream-addr`.

#[path = "common.rs"]
mod common;

use bytes::Bytes;
use clap::Parser;
use common::Client;
use common::Target;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::Barrier;
use tokio_rustls::TlsConnector;

#[derive(Parser)]
struct Args {
    /// Seconds of warm-up before each measurement. The benchmark drops the
    /// results of the warm-up.
    #[arg(long, default_value_t = 5)]
    warmup_secs: u64,

    /// Seconds of each measurement.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,

    /// Seed for the random bodies. Caller `i` uses the seed plus `i`. Without
    /// a seed, each run uses different bodies.
    #[arg(long)]
    seed: Option<u64>,

    /// The numbers of callers to run, one after the other. Separate them with
    /// commas, or repeat the option.
    #[arg(
        short = 'C',
        long,
        value_delimiter = ',',
        default_value = "1",
        value_parser = clap::value_parser!(u64).range(1..=1000)
    )]
    concurrency: Vec<u64>,

    /// The address (`host:port`) of a proxy that is already running. Give it
    /// with `--upstream-addr`.
    #[arg(long, requires = "upstream_addr")]
    proxy_addr: Option<String>,

    /// The address (`host:port`) of the upstream that is already running.
    #[arg(long, requires = "proxy_addr")]
    upstream_addr: Option<String>,

    /// Cargo passes this option. The benchmark ignores it.
    #[arg(long, hide = true)]
    bench: bool,
}

/// One caller: its connection and its source of random bodies.
struct Caller {
    client: Client,
    rng: StdRng,
}

/// What the callers measured in one phase.
struct Phase {
    latencies: Vec<Duration>,
    ok: u64,
    errors: u64,
    /// The time of the slowest caller.
    elapsed: Duration,
}

/// What the benchmark reports for one target and one number of callers.
struct Report {
    requests: u64,
    ok: u64,
    errors: u64,
    elapsed: Duration,
    /// The latencies in milliseconds, sorted.
    latencies_ms: Vec<f64>,
}

impl Report {
    fn new(phase: Phase) -> Self {
        let mut latencies_ms: Vec<f64> = phase
            .latencies
            .iter()
            .map(|latency| latency.as_secs_f64() * 1000.0)
            .collect();
        latencies_ms.sort_by(f64::total_cmp);
        Report {
            requests: phase.ok + phase.errors,
            ok: phase.ok,
            errors: phase.errors,
            elapsed: phase.elapsed,
            latencies_ms,
        }
    }

    fn error_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.errors as f64 / self.requests as f64 * 100.0
        }
    }

    fn throughput(&self) -> f64 {
        self.ok as f64 / self.elapsed.as_secs_f64()
    }

    fn percentile(&self, p: f64) -> Option<f64> {
        percentile(&self.latencies_ms, p)
    }

    fn print(&self) {
        println!(
            "requests: {} (ok {}, errors {})",
            self.requests, self.ok, self.errors
        );
        println!("error rate: {:.2}%", self.error_rate());
        println!("throughput: {:.1} req/s", self.throughput());
        match (self.latencies_ms.first(), self.latencies_ms.last()) {
            (Some(min), Some(max)) => println!(
                "latency ms: min {min:.2}  p50 {:.2}  p90 {:.2}  p95 {:.2}  p99 {:.2}  max {max:.2}",
                self.percentile(50.0).unwrap_or_default(),
                self.percentile(90.0).unwrap_or_default(),
                self.percentile(95.0).unwrap_or_default(),
                self.percentile(99.0).unwrap_or_default(),
            ),
            _ => println!("no successful requests, so there are no latencies"),
        }
    }
}

/// The nearest-rank percentile `p` (0 to 100) of `sorted`, which is sorted
/// from low to high. `None` if `sorted` is empty.
fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted.get(rank.max(1) - 1).copied()
}

/// Send requests from every caller for `duration`. All callers start at the
/// same time. Return the callers, so the next phase can reuse their
/// connections, and what they measured.
async fn run_phase(callers: Vec<Caller>, duration: Duration) -> (Vec<Caller>, Phase) {
    let barrier = Arc::new(Barrier::new(callers.len()));
    let tasks: Vec<_> = callers
        .into_iter()
        .map(|mut caller| {
            let barrier = barrier.clone();
            tokio::spawn(async move {
                let mut latencies = Vec::new();
                let mut errors = 0_u64;
                barrier.wait().await;
                let start = Instant::now();
                while start.elapsed() < duration {
                    // Make the body before the timer starts.
                    let body: Bytes = common::random_body(&mut caller.rng);
                    let sent = Instant::now();
                    if caller.client.post(body).await {
                        latencies.push(sent.elapsed());
                    } else {
                        errors += 1;
                    }
                }
                (caller, latencies, errors, start.elapsed())
            })
        })
        .collect();

    let mut callers = Vec::new();
    let mut phase = Phase {
        latencies: Vec::new(),
        ok: 0,
        errors: 0,
        elapsed: Duration::ZERO,
    };
    for task in tasks {
        let (caller, latencies, errors, elapsed) = task.await.expect("a caller panicked");
        callers.push(caller);
        phase.ok += latencies.len() as u64;
        phase.errors += errors;
        phase.latencies.extend(latencies);
        phase.elapsed = phase.elapsed.max(elapsed);
    }
    (callers, phase)
}

/// Open one connection for each of `count` callers. `proxy` is the connector
/// for a proxy. With `None`, the callers use plain HTTP to the upstream.
async fn connect_callers(
    addr: &str,
    proxy: Option<&TlsConnector>,
    count: u64,
    seed: Option<u64>,
) -> Vec<Caller> {
    let mut callers = Vec::new();
    for index in 0..count {
        let client = match proxy {
            Some(connector) => Client::connect_proxy(addr, connector).await,
            None => Client::connect_upstream(addr).await,
        };
        let rng = match seed {
            Some(seed) => StdRng::seed_from_u64(seed + index),
            None => rand::make_rng(),
        };
        callers.push(Caller { client, rng });
    }
    callers
}

/// Warm up, then measure. Print the result and return it.
async fn measure(
    name: &str,
    addr: &str,
    proxy: Option<&TlsConnector>,
    count: u64,
    args: &Args,
) -> Report {
    println!("-- {name} --");
    let callers = connect_callers(addr, proxy, count, args.seed).await;
    println!("warm-up: {} s", args.warmup_secs);
    let (callers, _) = run_phase(callers, Duration::from_secs(args.warmup_secs)).await;
    println!("measuring: {} s", args.duration_secs);
    let (_, phase) = run_phase(callers, Duration::from_secs(args.duration_secs)).await;
    let report = Report::new(phase);
    report.print();
    report
}

/// Print what the proxy adds: the difference of the proxy and the upstream.
fn print_added(upstream: &Report, proxy: &Report) {
    println!("-- added by the proxy --");
    let mut parts = Vec::new();
    for (name, p) in [("p50", 50.0), ("p90", 90.0), ("p99", 99.0)] {
        if let (Some(direct), Some(through)) = (upstream.percentile(p), proxy.percentile(p)) {
            parts.push(format!("{name} {:+.2}", through - direct));
        }
    }
    if parts.is_empty() {
        println!("no successful requests, so nothing to compare");
        return;
    }
    println!("latency ms: {}", parts.join("  "));
    println!(
        "throughput: {:.1}% of the upstream",
        proxy.throughput() / upstream.throughput() * 100.0
    );
}

fn main() {
    let args = Args::parse();
    let target = Target::connect(args.proxy_addr.as_deref(), args.upstream_addr.as_deref());
    println!("{}", target.describe());
    println!(
        "bodies: random letters and digits, {} to {} bytes",
        common::MIN_BODY_BYTES,
        common::MAX_BODY_BYTES
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start the runtime");
    let connector = common::make_connector();
    for count in &args.concurrency {
        println!();
        println!("== {count} concurrent callers ==");
        let upstream = runtime.block_on(measure(
            "upstream (direct)",
            target.upstream_addr(),
            None,
            *count,
            &args,
        ));
        let proxy = runtime.block_on(measure(
            "proxy",
            target.proxy_addr(),
            Some(&connector),
            *count,
            &args,
        ));
        print_added(&upstream, &proxy);
    }
}
