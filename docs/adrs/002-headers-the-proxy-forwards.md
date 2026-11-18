# ADR 002: Which headers the proxy forwards

- Status: Accepted
- Date: 2026-11-18

## Context

The proxy sends an authorized request to the upstream, and sends the response
back to the client. The headers need care in both directions:

- Some headers apply to one connection only (hop-by-hop). A proxy must not pass
  them on.
- Some headers tell the upstream who the client is (`X-Forwarded-For`). A client
  can send them too, so the upstream cannot tell which value is true.
- Some headers hold secrets (`Authorization`, `Cookie`). The upstream may need
  them, but they must never be in a log.

## Decision

For a request, the proxy forwards only the headers on an allowlist. It removes
every other header. The reason: the upstream gets only the headers that we know
and that are safe, so a client cannot use the proxy to send a secret or an odd
header (`Authorization`, `Cookie`, a custom header) to the upstream.

For a response, the proxy removes the hop-by-hop headers and forwards the rest.

### Request, from the client to the upstream

The allowlist (`ALLOWED_REQUEST` in `src/headers.rs`):

| Header | Why |
| ------ | --- |
| `Accept`, `Accept-Encoding`, `Accept-Language` | Content negotiation. |
| `Content-Type`, `Content-Encoding`, `Content-Length` | The description of the body. |
| `Cache-Control`, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, `Range` | Conditional and partial requests. |
| `User-Agent` | Helps the upstream to diagnose a problem. |
| `X-Request-Id` | Kept if it is valid (1 to 128 characters: letters, digits, `-`, `_`, `.`, `:`). Otherwise replaced with a new UUID. |

The proxy sets these headers itself (it always removes the values from the
client):

| Header | Value |
| ------ | ----- |
| `Host` | The address of the upstream (`SERVER_ADDR`). |
| `X-Forwarded-For` | The IP address of the client connection. The proxy does not add to a value from the client, because it does not trust it. |
| `X-Forwarded-Proto` | Always `https`, because every client connection uses TLS. |
| `X-Forwarded-Host` | The `Host` header of the client request, or the authority of the URI (HTTP/2). Not set if there is neither. |
| `Via` | The HTTP version of the client request and the name `reverse-proxy`, for example `1.1 reverse-proxy`. |

The proxy also removes the hop-by-hop headers (`Connection`, `Keep-Alive`,
`Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`,
`Transfer-Encoding`, `Upgrade`) and each header that a `Connection` header
names. The allowlist has none of them, but the proxy removes them first, so a
future change to the list cannot let one through.

The standard `Forwarded` header is removed and is not set. We set the
`X-Forwarded-*` headers only.

The proxy also changes the request line: the method, the path and the query
stay as they are, and the request goes to the upstream as HTTP/1.1, also when
the client used HTTP/2.

### Response, from the upstream to the client

| Header | What the proxy does |
| ------ | ------------------- |
| The hop-by-hop headers (same list as above), and the headers that `Connection` names | Removed. |
| `X-Request-Id` | Set to the request ID of this request. |
| All other headers | Forwarded without a change. |

The proxy does not add a `Via` header to a response.

### Logs

No header is in a log or in an audit event. This is true also for the headers
that the proxy forwards. See `src/audit.rs`.

## Consequences

- The upstream gets one trusted `X-Forwarded-For`, and the client cannot make a
  false one. An upstream that reads `X-Forwarded-For` must trust the proxy
  only.
- `Authorization` and `Cookie` do not reach the upstream. An upstream that
  needs a client token or a session cookie does not work behind this proxy
  until we add that header to the list. The identity of the client is in
  `X-Forwarded-For` and in the audit event only. The proxy does not send the
  SPIFFE ID to the upstream.
- A custom header (`X-Tenant`, `X-Api-Version`) does not reach the upstream.
  To allow one, add it to `ALLOWED_REQUEST`.
- `X-Forwarded-Host` comes from the client. A client can send any `Host`
  value, so the upstream must not use `X-Forwarded-Host` to make a decision
  about security, for example to build a link in a password reset message.
- A new header in a future HTTP standard is not forwarded until we add it. This
  is the safe direction.
- The proxy does not stop a loop yet. A request that the proxy sends to itself
  gets a new `Via` value, and nothing counts the hops. This is a known gap.
- The response is not filtered with a list. An upstream can send any
  end-to-end header to the client.

## Alternatives considered

- **A blocklist: remove the hop-by-hop and forwarding headers, and forward
  all others.** This keeps every upstream working, including those that need
  `Authorization`, `Cookie` or a custom header. We rejected it because the
  upstream then gets any header that a client sends. A header that we did not
  think of passes. We chose the smaller surface, and we accept that some
  upstreams need a change to the list.
- **Append to `X-Forwarded-For`, as many proxies do.** This keeps the chain of
  addresses, but the client controls the first values. The proxy is the first
  hop and has no trusted proxy in front of it, so a chain has no value here.
- **Set the standard `Forwarded` header.** It carries the same data in a
  better format. Many upstreams read only `X-Forwarded-*`, so we kept those.
  We can add `Forwarded` later.
- **Reject a request when `Host` and the URI authority differ.** This would
  make `X-Forwarded-Host` more reliable. We have not decided this. The client
  can still send a `Host` that the upstream does not expect.
