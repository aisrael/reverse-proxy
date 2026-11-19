//! OpenTelemetry: the span for the upstream request, the trace context that the
//! proxy sends to the upstream, and the counter for timeouts.
//!
//! The proxy always makes trace IDs and counts timeouts. It exports them (OTLP
//! over HTTP) only if an endpoint is set with the standard `OTEL_*` variables,
//! for example `OTEL_EXPORTER_OTLP_ENDPOINT`.
//!
//! A span never has a query, a header or an identity.

use crate::errors::Error;
use hyper::HeaderMap;
use opentelemetry::Context;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::SpanKind;
use opentelemetry::trace::Status;
use opentelemetry::trace::TraceContextExt;
use opentelemetry::trace::Tracer;
use opentelemetry::trace::TracerProvider;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_http::HeaderInjector;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracer;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::warn;

/// The name of the instrumentation scope, and the default service name.
const NAME: &str = "reverse-proxy";

/// The name of the counter for timeouts.
const TIMEOUTS_COUNTER: &str = "reverse_proxy.timeouts";

/// Which timeout happened. This is the value of the attribute `timeout.kind`
/// of the counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutKind {
    /// The upstream sent no response head in time.
    Upstream,
    /// The client sent the request body too slowly.
    ClientBody,
    /// The client sent the request head too slowly (HTTP/1).
    ClientHeader,
    /// The TLS handshake took too long.
    Handshake,
}

impl TimeoutKind {
    /// The value of the attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            TimeoutKind::Upstream => "upstream",
            TimeoutKind::ClientBody => "client_body",
            TimeoutKind::ClientHeader => "client_header",
            TimeoutKind::Handshake => "handshake",
        }
    }
}

/// How an upstream request ended, for the span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanOutcome {
    /// The upstream sent a response head with this status.
    Response(u16),
    /// The connection or the request failed.
    Failed,
    /// The upstream sent no response head in time.
    UpstreamTimeout,
    /// The client sent the request body too slowly.
    ClientTimeout,
}

/// The telemetry of the proxy. Share it as `Arc<Telemetry>`.
pub struct Telemetry {
    tracer: SdkTracer,
    propagator: TraceContextPropagator,
    timeouts: Counter<u64>,
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Telemetry {
    /// Set up the telemetry from the `OTEL_*` environment variables.
    ///
    /// Export the spans if `OTEL_EXPORTER_OTLP_ENDPOINT` or
    /// `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set. Export the metrics if
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
    /// is set. `OTEL_SERVICE_NAME` is the service name. The default is
    /// `reverse-proxy`.
    ///
    /// Return an error if an exporter cannot be made, for example the endpoint
    /// is not a valid URL.
    pub fn init() -> Result<Self, Error> {
        let mut resource = Resource::builder();
        if std::env::var_os("OTEL_SERVICE_NAME").is_none() {
            resource = resource.with_service_name(NAME);
        }
        let resource = resource.build();

        let mut tracer_provider = SdkTracerProvider::builder().with_resource(resource.clone());
        if is_exported("TRACES") {
            let exporter = SpanExporter::builder()
                .with_http()
                .build()
                .map_err(|err| Error::Telemetry(err.to_string()))?;
            tracer_provider = tracer_provider.with_batch_exporter(exporter);
        }
        let mut meter_provider = SdkMeterProvider::builder().with_resource(resource);
        if is_exported("METRICS") {
            let exporter = MetricExporter::builder()
                .with_http()
                .build()
                .map_err(|err| Error::Telemetry(err.to_string()))?;
            meter_provider = meter_provider.with_periodic_exporter(exporter);
        }
        Ok(Self::with_providers(
            tracer_provider.build(),
            meter_provider.build(),
        ))
    }

    /// Telemetry that makes trace IDs and counts timeouts, and exports nothing.
    #[cfg(test)]
    pub fn without_export() -> Self {
        Self::with_providers(
            SdkTracerProvider::builder().build(),
            SdkMeterProvider::builder().build(),
        )
    }

    /// Telemetry that uses these providers. A test can give providers with an
    /// in-memory exporter.
    pub fn with_providers(
        tracer_provider: SdkTracerProvider,
        meter_provider: SdkMeterProvider,
    ) -> Self {
        let timeouts = meter_provider
            .meter(NAME)
            .u64_counter(TIMEOUTS_COUNTER)
            .with_unit("{timeout}")
            .with_description("The number of timeouts, by the kind of timeout.")
            .build();
        Self {
            tracer: tracer_provider.tracer(NAME),
            propagator: TraceContextPropagator::new(),
            timeouts,
            tracer_provider,
            meter_provider,
        }
    }

    /// Read the trace context (`traceparent` and `tracestate`) of a request.
    /// If there is no valid `traceparent`, the context is empty, and the next
    /// span starts a new trace.
    pub fn extract(&self, headers: &HeaderMap) -> Context {
        self.propagator
            .extract_with_context(&Context::new(), &HeaderExtractor(headers))
    }

    /// The trace ID of `context` as 32 hexadecimal digits. `None` if the
    /// context has no trace.
    pub fn trace_id(context: &Context) -> Option<String> {
        let span = context.span();
        let span_context = span.span_context();
        span_context
            .is_valid()
            .then(|| span_context.trace_id().to_string())
    }

    /// Start the span for a request to the upstream at `upstream` (a
    /// `host:port` address). `parent` is the context from `extract`. Return a
    /// context that has the new span.
    pub fn start_upstream_span(&self, parent: &Context, method: &str, upstream: &str) -> Context {
        let mut attributes = vec![KeyValue::new("http.request.method", method.to_string())];
        match upstream.rsplit_once(':') {
            Some((host, port)) => {
                attributes.push(KeyValue::new("server.address", host.to_string()));
                if let Ok(port) = port.parse::<i64>() {
                    attributes.push(KeyValue::new("server.port", port));
                }
            }
            None => attributes.push(KeyValue::new("server.address", upstream.to_string())),
        }
        let span = self
            .tracer
            .span_builder("upstream request")
            .with_kind(SpanKind::Client)
            .with_attributes(attributes)
            .start_with_context(&self.tracer, parent);
        parent.with_span(span)
    }

    /// Set `traceparent` and `tracestate` in `headers` from the span in
    /// `context`. Replace the values that are there.
    pub fn inject(&self, context: &Context, headers: &mut HeaderMap) {
        headers.remove("traceparent");
        headers.remove("tracestate");
        self.propagator
            .inject_context(context, &mut HeaderInjector(headers));
        // The propagator sets an empty `tracestate` when there is none.
        if headers
            .get("tracestate")
            .is_some_and(|value| value.is_empty())
        {
            headers.remove("tracestate");
        }
    }

    /// End the span in `context`. `outcome` says how the request ended.
    pub fn end_span(&self, context: &Context, outcome: SpanOutcome) {
        let span = context.span();
        match outcome {
            SpanOutcome::Response(status) => {
                span.set_attribute(KeyValue::new(
                    "http.response.status_code",
                    i64::from(status),
                ));
                if status >= 500 {
                    span.set_attribute(KeyValue::new("error.type", status.to_string()));
                    span.set_status(Status::error(""));
                }
            }
            SpanOutcome::Failed => {
                span.set_attribute(KeyValue::new("error.type", "connection"));
                span.set_status(Status::error("the request to the upstream failed"));
            }
            SpanOutcome::UpstreamTimeout => {
                span.set_attribute(KeyValue::new("error.type", "timeout"));
                span.set_status(Status::error("the upstream did not answer in time"));
            }
            SpanOutcome::ClientTimeout => {
                span.set_attribute(KeyValue::new("error.type", "client_timeout"));
                span.set_status(Status::error("the client sent the request too slowly"));
            }
        }
        span.end();
    }

    /// Add 1 to the counter of timeouts.
    pub fn record_timeout(&self, kind: TimeoutKind) {
        self.timeouts
            .add(1, &[KeyValue::new("timeout.kind", kind.as_str())]);
    }

    /// Send the spans and metrics that are waiting to the exporters, and stop.
    /// Log a warning if this fails.
    pub fn shutdown(&self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            warn!(%err, "failed to stop the tracer provider");
        }
        if let Err(err) = self.meter_provider.shutdown() {
            warn!(%err, "failed to stop the meter provider");
        }
    }
}

/// True if an OTLP endpoint is set for `signal` (`TRACES` or `METRICS`).
fn is_exported(signal: &str) -> bool {
    [
        "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
        format!("OTEL_EXPORTER_OTLP_{signal}_ENDPOINT"),
    ]
    .iter()
    .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()))
}
