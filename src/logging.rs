//! Where the output of the program goes.
//!
//! - The audit events (target `audit`) go to STDOUT, one JSON line each. They
//!   do not depend on `RUST_LOG`.
//! - The other logs go to STDERR, as text. `RUST_LOG` sets their level.

use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The target of the audit events.
pub const AUDIT_TARGET: &str = "audit";

/// Set up the logs. Call this once, at start. Never log secrets.
pub fn init() {
    // The default level is `info`. `audit=off` keeps the audit events out of STDERR.
    let text_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive(
            format!("{AUDIT_TARGET}=off")
                .parse()
                .expect("valid directive"),
        );
    let text = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(text_filter);

    let audit = tracing_subscriber::fmt::layer()
        .json()
        // Put the fields at the top level of the JSON object.
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(std::io::stdout)
        .with_filter(Targets::new().with_target(AUDIT_TARGET, Level::INFO));

    tracing_subscriber::registry().with(text).with(audit).init();
}
