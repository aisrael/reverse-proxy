# ADR 005: Body size limits and streaming

- Status: Accepted
- Date: 2026-11-18

## Context

A client can send a very large request body, and an upstream can send a very
large response body. If the proxy has no limit, one request can use a large
amount of bandwidth and time. If the proxy reads a whole body into memory to
check its size, one request can also use a large amount of memory.

## Decision

### Streaming

The proxy never reads a whole body into memory.

- The request body goes from the client to the upstream chunk by chunk. `hyper`
  reads a chunk from the client only when the upstream connection can take it.
- The response body goes from the upstream to the client in the same way.

A slow reader slows the sender (backpressure). The memory that one request uses
does not depend on the size of its body.

### Limits

There are two settings. Both default to 1 MiB (1048576 bytes). Each is a whole
number of bytes. `0` turns the limit off for that direction. A value that is
not a whole number is an error at start (exit code 1).

| Setting | Limits | Over the limit |
| ------- | ------ | -------------- |
| `PROXY_MAX_REQUEST_BODY_BYTES` | The request body from the client. | `413`, empty body. |
| `PROXY_MAX_RESPONSE_BODY_BYTES` | The response body from the upstream. | `502`, body `Bad Gateway` (length known), or the response stops (length not known). |

A body of exactly the limit is accepted.

The proxy counts the bytes while the body streams (`LimitBody` in
`src/limit.rs`). The wrapper counts the bytes of each data frame and keeps
nothing. When the count passes the limit, the wrapper sets a flag, returns an
error, and reads no more frames.

#### Request

1. If the request has a `Content-Length` above the limit, the proxy answers
   `413` at once. It does not connect to the upstream.
2. Otherwise the proxy forwards the request and counts. If the count passes the
   limit, the body fails. `hyper` stops the request to the upstream and closes
   that connection. The proxy sees the flag and answers `413`.

The `413` comes after the checks for identity (`401`), loops (`508`), path
(`400`) and policy (`403`). A client that the policy does not allow never gets
`413`. The audit event has `decision` `ALLOW`, `status` 413 and no
`upstream_status`, like the `408` case.

#### Response

1. If the response head has a `Content-Length` above the limit, the proxy
   drops the response. This closes the upstream connection. The client gets
   `502`. The audit event has the status `502` and the `upstream_status` of the
   head.
2. Otherwise the proxy sends the head and streams the body, and counts. If the
   count passes the limit, the body fails. `hyper` closes the upstream
   connection and ends the response to the client before its end: a closed
   connection (HTTP/1) or a reset stream (HTTP/2). The client sees an
   incomplete response.

In case 2 the proxy has already sent the status and the headers, so it cannot
change the status. The audit event is written when the head is ready, so it
does not show the failure. The proxy writes a warning in the log.

The span of the upstream request ends with `error.type` `body_too_large` in the
request case, and in the case of a response with a length that is too large.

### What the count includes

- The count is the bytes of the data frames as the proxy sees them. It does not
  include headers or trailers.
- The proxy does not decode `Content-Encoding`. A compressed body counts at its
  compressed size.

## Consequences

- A client cannot use the proxy to send a large body to the upstream, and an
  upstream cannot send a large body to a client, when the limits are on.
- The default of 1 MiB is small. A service that uploads or downloads larger
  bodies must change the settings. There is one value for all paths and all
  identities.
- A response that grows over the limit in the middle of the stream gives an
  incomplete response, and the client can see this only as a failed transfer.
  The status in the audit event is the status of the head.
- `hyper` does not send the body of a `GET` request, so the request limit does
  not apply to it.
- If the upstream sends its response before it reads the whole request body, the
  client gets that response and not `413`. The limit error comes after the head.
  The upstream connection is closed, but the response already reached the
  client.
- The limit applies to one request. It does not limit the number of requests or
  the total bytes of a connection.
- A limit does not replace a timeout. A client that sends slowly under the limit
  still hits the client timeout (ADR 004). A response body that stops after its
  head has no limit in time.

## Alternatives considered

- **Read the whole body, then check its size.** This is simple and always gives
  a clean `413` or `502`. We rejected it: it needs memory for the largest
  allowed body for each request, and it delays the first byte.
- **Check `Content-Length` only.** This is cheap, but a chunked body has no
  length, and a client or an upstream can state a false length. The count is the
  only check that is always right.
- **Use `tower-http` `RequestBodyLimit`.** It does the same count for requests.
  The proxy does not use `tower`, and the response side needs custom code too,
  so we wrote one small wrapper for both.
- **One limit for both directions.** Requests and responses have different sizes
  in most services (a small request and a large download). Two settings cost
  little.
- **A limit for each path or identity.** This is more flexible, but the policy
  file would need a new field. We can add it later.
