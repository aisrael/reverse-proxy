# ADR 004: Timeouts and telemetry

- Status: Accepted
- Date: 2026-11-18

## Context

A slow client or a silent upstream can hold a connection and its task for a long time. The operator must see when this happens, and must be able to follow one request from the client, through the proxy, to the upstream.

## Decision

### Timeouts

There are two settings. Both default to 10 seconds, and both must be a whole number of seconds, more than 0.

| Setting | What it limits | What the client gets |
| --- | --- | --- |
| `PROXY_CLIENT_TIMEOUT_SECS` | The time to send the request head (HTTP/1), and the time to send the request body. | The connection closes (head), or `408` with an empty body (body). |
| `PROXY_UPSTREAM_TIMEOUT_SECS` | The time from the start of forwarding to the response head from the upstream. It includes the connection and the sending of the request. | `504`, body `Gateway Timeout`. |

- **Head.** `hyper` closes an HTTP/1 connection that does not send the request head in time (`header_read_timeout`). HTTP/2 has no such setting, because the head is a frame on a connection that is already open.
- **Body.** The proxy wraps the request body (`DeadlineBody`). The deadline is the start of the request plus the client limit, for the whole body, not for each chunk. When it passes, the body fails, the proxy stops the request to the upstream, and the client gets `408`. A client that keeps sending one byte at a time still fails at the deadline.
- **Upstream.** `tokio::time::timeout` around the request to the upstream. The upstream timer includes the time to send the request body. A slow client therefore hits the client limit first: the client deadline starts earlier. If both have passed, the proxy reports the client timeout, because the upstream is not the cause.
- **GET with a body.** `hyper` does not send the body of a `GET` request to the upstream, so the client body limit does not apply to it.

### Spans

The proxy makes one span for each request that it forwards: `upstream request`, kind `client`. It ends when the response head arrives or the request fails, so it covers the same time as the upstream timeout. It has the method, the upstream address and port, the response status, and `error.type` for a failure. It has no query, no header and no identity. A request that the proxy denies (`401`, `508`, `400`, `403`) has no span, because nothing goes to the upstream.

### Trace context

- A valid W3C `traceparent` in the request makes the span a child of it. The trace ID stays the same, and `tracestate` goes on.
- If there is no valid `traceparent`, the proxy starts a new trace.
- The proxy always sets `traceparent` and `tracestate` for the upstream from its own span. It never copies the client values. `baggage` is not forwarded (it is not on the allowlist of ADR 002).
- The audit event has `trace_id`. It is the trace ID of the span, or the ID from the client for a request without a span, or it is not present.

### Counter

`reverse_proxy.timeouts` (unit `{timeout}`) adds 1 for each timeout. The attribute `timeout.kind` is:

- `upstream`: no response head in time;
- `client_body`: the client sent the body too slowly;
- `client_header`: the client sent the head too slowly (HTTP/1);
- `handshake`: the TLS handshake took more than 10 seconds.

The counter has no attribute with a client value (no identity, no path), so the number of series stays small.

### Export

The proxy sends spans and metrics with OTLP over HTTP (protobuf) only if `OTEL_EXPORTER_OTLP_ENDPOINT` (or the `_TRACES_` or `_METRICS_` form) is set. The other `OTEL_*` variables work as the SDK defines them. Without an endpoint, the proxy still makes trace IDs, sends them to the upstream, and counts, but exports nothing. On a clean shutdown the proxy sends what is waiting.

## Consequences

- A response body that stops after the head has no limit. Neither has the idle time of a connection between requests.
- HTTP/2 clients have no head limit in the proxy.
- The default upstream limit is 10 seconds. A slow upstream, for example a report that takes 30 seconds, needs a higher value.
- A slow upload of a large body can reach the client limit even if the client is not malicious. Raise `PROXY_CLIENT_TIMEOUT_SECS` for such clients.
- The proxy does not log or export a header, a query or an identity in a span. The `trace_id` is not a secret.
- The batch exporters run on their own threads and use a blocking HTTP client. An endpoint that does not answer can delay a clean shutdown for a short time.
- The proxy does not export logs through OpenTelemetry.

## Alternatives considered

- **One timeout for all.** Simpler, but a slow client and a slow upstream need different limits and different answers (`408` and `504`).
- **One deadline for the whole request, including the response.** It would cut long downloads and streams.
- **A limit for the time between chunks (idle) instead of a deadline.** It does not stop a client that sends one byte at a time.
- **`tower::timeout`.** It limits one call. It does not know the client body, and it adds a dependency we do not need (see the discussion on `tower`).
- **`tracing-opentelemetry`.** It bridges `tracing` spans to OpenTelemetry. We have one span, so the OpenTelemetry API is enough.
- **Copy `traceparent` from the client without a new span.** The upstream would not see the proxy in the trace.
