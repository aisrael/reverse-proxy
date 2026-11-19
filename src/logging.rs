//! Where the output of the program goes.
//!
//! - The audit events (target `audit`) go to STDOUT, one JSON line each. They
//!   do not depend on `RUST_LOG`.
//! - The other logs go to STDERR, as text. `RUST_LOG` sets their level.
//! - The spans of the proxy (for example `request` and `policy_check`) go to
//!   OpenTelemetry only, and only if the spans are exported. They are not in
//!   the logs.

use opentelemetry_sdk::trace::SdkTracer;
use std::io::IsTerminal;
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The target of the audit events.
pub const AUDIT_TARGET: &str = "audit";

/// The target of the spans and events of this program.
const PROGRAM_TARGET: &str = "reverse_proxy";

/// Set up the logs. Call this once, at start. Never log secrets.
///
/// `span_tracer` is the tracer for the spans. With `None`, the program makes
/// no spans, so they cost nothing.
pub fn init(span_tracer: Option<SdkTracer>) {
    // The default level is `info`. `audit=off` keeps the audit events out of STDERR.
    // The text logs have no spans: a span would add its name to each log line.
    let text_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive(
            format!("{AUDIT_TARGET}=off")
                .parse()
                .expect("valid directive"),
        )
        .and(filter_fn(|metadata| !metadata.is_span()));
    let text = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        // Colours only for a person at a terminal, not for a file or a pipe.
        .with_ansi(std::io::stderr().is_terminal())
        .with_filter(text_filter);

    let audit = tracing_subscriber::fmt::layer()
        .json()
        // Put the fields at the top level of the JSON object.
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(std::io::stdout)
        .with_filter(Targets::new().with_target(AUDIT_TARGET, Level::INFO));

    // Only the spans of this program go to OpenTelemetry. The events do not.
    let spans = span_tracer.map(|tracer| {
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(
                Targets::new()
                    .with_target(PROGRAM_TARGET, Level::INFO)
                    .and(filter_fn(|metadata| metadata.is_span())),
            )
    });

    tracing_subscriber::registry()
        .with(spans)
        .with(text)
        .with(audit)
        .init();
}
