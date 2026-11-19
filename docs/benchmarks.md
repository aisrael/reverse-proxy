# Benchmarks

This page has the results of `benches/custom_benchmark.rs`. It sends `POST /echo` with a random body (letters and digits, 32 to 1024 bytes). It measures the upstream alone (plain HTTP), and the proxy in front of it (mTLS). Each caller has one connection that stays open.

To run the benchmarks again, see "Benchmarks" in the [README](../README.md).

## Summary

- The proxy has no errors at any level. The error rate is 0.00% in every run.
- At 1 caller, the proxy adds about 0.03 ms at p50 and 0.04 ms at p99.
- The added latency grows with the number of callers. At 100 callers, it adds 0.79 ms at p50 and 1.49 ms at p99.
- The throughput of both targets stops growing at about 20 callers. After that, more callers only add latency.
- The proxy handles 35% to 45% of the requests per second of the upstream. The proxy does TLS, header filtering, a policy check and an audit write for each request. The test server does almost no work.

## Setup

| Item | Value |
| --- | --- |
| Machine | Apple M5, 10 cores, macOS 27.2.1 |
| Rust | rustc 1.99.1, `cargo bench` (optimized) |
| Commit | `dbb1957` |
| Command | `cargo bench --bench custom_benchmark -- -C 1,5,10,20,50,100 --warmup-secs 5 --duration-secs 60 --seed 42` (with `ulimit -n 4096`) |
| Warm-up | 5 s, then 60 s of measurement, for each target and each number of callers |
| Proxy config | The defaults. No OpenTelemetry export, so the proxy makes no spans. The audit events go to STDOUT, and the benchmark drops them. |
| Protocol | Client to proxy: TLS 1.3 with a client certificate, HTTP/1.1. Proxy to upstream: HTTP/1.1, plain. |

## Results

Latency is in milliseconds. "Added" is the proxy minus the upstream, at the same percentile. The throughput is the number of successful requests each second.

| Callers | Target | Requests/s | p50 | p90 | p99 | Added p50 | Added p90 | Added p99 |
| --: | --- | --: | --: | --: | --: | --: | --: | --: |
| 1 | upstream | 45,715 | 0.02 | 0.02 | 0.04 |  |  |  |
| 1 | proxy | 17,817 | 0.05 | 0.06 | 0.07 | +0.03 | +0.04 | +0.04 |
| 5 | upstream | 117,019 | 0.04 | 0.06 | 0.08 |  |  |  |
| 5 | proxy | 40,766 | 0.12 | 0.16 | 0.19 | +0.08 | +0.10 | +0.12 |
| 10 | upstream | 127,992 | 0.07 | 0.11 | 0.14 |  |  |  |
| 10 | proxy | 48,071 | 0.20 | 0.26 | 0.33 | +0.13 | +0.16 | +0.20 |
| 20 | upstream | 145,082 | 0.13 | 0.19 | 0.24 |  |  |  |
| 20 | proxy | 63,731 | 0.29 | 0.41 | 0.66 | +0.16 | +0.22 | +0.42 |
| 50 | upstream | 147,799 | 0.33 | 0.46 | 0.60 |  |  |  |
| 50 | proxy | 62,728 | 0.77 | 1.05 | 1.55 | +0.44 | +0.59 | +0.95 |
| 100 | upstream | 153,329 | 0.63 | 0.93 | 1.18 |  |  |  |
| 100 | proxy | 68,401 | 1.42 | 1.97 | 2.67 | +0.79 | +1.05 | +1.49 |

## Charts

The charts have no legend. The lines are in the order of the title.

### Latency through the proxy

Lines: p50, p90, p99.

```mermaid
xychart-beta
    title "Latency through the proxy by number of callers (p50, p90, p99)"
    x-axis "Concurrent callers" ["1", "5", "10", "20", "50", "100"]
    y-axis "Latency (ms)" 0 --> 3
    line [0.05, 0.12, 0.20, 0.29, 0.77, 1.42]
    line [0.06, 0.16, 0.26, 0.41, 1.05, 1.97]
    line [0.07, 0.19, 0.33, 0.66, 1.55, 2.67]
```

### Latency of the upstream alone

Lines: p50, p90, p99. The scale is the same as the chart above.

```mermaid
xychart-beta
    title "Latency of the upstream alone by number of callers (p50, p90, p99)"
    x-axis "Concurrent callers" ["1", "5", "10", "20", "50", "100"]
    y-axis "Latency (ms)" 0 --> 3
    line [0.02, 0.04, 0.07, 0.13, 0.33, 0.63]
    line [0.02, 0.06, 0.11, 0.19, 0.46, 0.93]
    line [0.04, 0.08, 0.14, 0.24, 0.60, 1.18]
```

### Latency that the proxy adds

Lines: p50, p90, p99.

```mermaid
xychart-beta
    title "Latency added by the proxy by number of callers (p50, p90, p99)"
    x-axis "Concurrent callers" ["1", "5", "10", "20", "50", "100"]
    y-axis "Added latency (ms)" 0 --> 2
    line [0.03, 0.08, 0.13, 0.16, 0.44, 0.79]
    line [0.04, 0.10, 0.16, 0.22, 0.59, 1.05]
    line [0.04, 0.12, 0.20, 0.42, 0.95, 1.49]
```

### Throughput

Lines: upstream, proxy.

```mermaid
xychart-beta
    title "Successful requests per second by number of callers (upstream, proxy)"
    x-axis "Concurrent callers" ["1", "5", "10", "20", "50", "100"]
    y-axis "Requests per second" 0 --> 160000
    line [45715, 117019, 127992, 145082, 147799, 153329]
    line [17817, 40766, 48071, 63731, 62728, 68401]
```

## Limits of these results

- **The benchmark and both servers share one machine.** The load generator, the proxy and the upstream compete for 10 cores. The numbers show the relative cost of the proxy. They are not the limits of the proxy on its own hardware. Above 20 callers, the throughput barely grows for both targets, which suggests that the machine is the limit.
- **The upstream does almost no work.** `/echo` sends the body back. A real upstream is slower, so the added latency of the proxy is a smaller share of the total, and the throughput ratio is better than the 35% to 45% here.
- **The loopback network has no delay.** A real network adds a round trip, and a new TLS connection adds a handshake. Every caller here keeps one connection, so the results do not include the handshake. The proxy does a full handshake for each new connection (it does not resume sessions).
- **The audit events go nowhere.** The benchmark sends the STDOUT of the proxy to `/dev/null`. A real deployment writes them to a pipe or a file, which can cost more.
- **The p99 and the maximum have noise.** The maximum of the proxy at 50 callers (29 ms) is a single slow request in more than 3.7 million. It comes from the machine and not from the proxy. Run the benchmark again to check a result.
- **One run.** These numbers come from one run for each level. They are not an average of many runs. An earlier run with 30 s of measurement and 25 callers (instead of 20) gave much lower throughput at 25 and 50 callers (about 30,000 requests per second for the proxy). Results can vary a lot between runs on this machine, so run the benchmark again to check a result.
- **Only `POST /echo`.** Larger bodies, HTTP/2 clients, and a new connection for each request were not measured.

## Where the time goes

This run did not measure the sources of the overhead. The proxy makes a span for each step of a request (see "Benchmarks" in the README). To see their durations, start `docker compose up -d`, run the benchmark with `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318`, and look at the traces in Grafana. Add the result to this page.
