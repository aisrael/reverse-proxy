//! Criterion benchmark: find a change in the speed of one request.
//!
//! One caller sends `POST /echo` over one open connection. The benchmark has
//! two groups: the upstream alone, and the proxy in front of it. The body of
//! each request is random text, 32 to 1024 bytes long. The benchmark makes the
//! body before the timer starts.
//!
//! The benchmark starts the upstream and the proxy on free ports. To use a
//! stack that is already running, set `BENCH_PROXY_ADDR` and
//! `BENCH_UPSTREAM_ADDR` (both `host:port`).
//!
//! To find a change:
//!
//! ```sh
//! cargo bench --bench criterion_benchmark -- --save-baseline before
//! # change the code
//! cargo bench --bench criterion_benchmark -- --baseline before
//! ```
//!
//! Criterion writes an HTML report to `target/criterion`. For percentiles and
//! many callers, use `custom_benchmark`.

#[path = "common.rs"]
mod common;

use common::Client;
use common::Target;
use criterion::BatchSize;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_echo(c: &mut Criterion) {
    let proxy = std::env::var("BENCH_PROXY_ADDR").ok();
    let upstream = std::env::var("BENCH_UPSTREAM_ADDR").ok();
    let target = Target::connect(proxy.as_deref(), upstream.as_deref());
    eprintln!("{}", target.describe());

    let runtime = Runtime::new().expect("failed to start the runtime");
    let connector = common::make_connector();
    let mut upstream_client = runtime.block_on(Client::connect_upstream(target.upstream_addr()));
    let mut proxy_client = runtime.block_on(Client::connect_proxy(target.proxy_addr(), &connector));

    let mut group = c.benchmark_group("post_echo");
    // The same seed makes the same bodies for each run and for each group.
    let mut rng = StdRng::seed_from_u64(42);
    group.bench_function("upstream_direct", |b| {
        b.iter_batched(
            || common::random_body(&mut rng),
            |body| {
                let ok = runtime.block_on(upstream_client.post(body));
                assert!(ok, "the upstream did not answer 200");
                black_box(ok)
            },
            BatchSize::SmallInput,
        );
    });
    let mut rng = StdRng::seed_from_u64(42);
    group.bench_function("through_proxy", |b| {
        b.iter_batched(
            || common::random_body(&mut rng),
            |body| {
                let ok = runtime.block_on(proxy_client.post(body));
                assert!(ok, "the proxy did not answer 200");
                black_box(ok)
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .sample_size(1000);
    targets = bench_echo
}
criterion_main!(benches);
