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
| `Via` | The chain of proxies. The proxy keeps the values and adds its own (see below). It needs the chain to find a loop. |
| `X-Request-Id` | Kept if it is valid (1 to 128 characters: letters, digits, `-`, `_`, `.`, `:`). Otherwise replaced with a new UUID. |

The proxy sets these headers itself (it always removes the values from the
client):

| Header | Value |
| ------ | ----- |
| `Host` | The address of the upstream (`SERVER_ADDR`). |
| `X-Forwarded-For` | The IP address of the client connection. The proxy does not add to a value from the client, because it does not trust it. |
| `X-Forwarded-Proto` | Always `https`, because every client connection uses TLS. |
| `X-Forwarded-Host` | The `Host` header of the client request, or the authority of the URI (HTTP/2). Not set if there is neither. |
| `Via` | The proxy adds one value after the values that the request has: the HTTP version of the client request and its own name, for example `1.1 reverse-proxy-1a2b3c4d`. |

The proxy also removes the hop-by-hop headers (`Connection`, `Keep-Alive`,
`Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`,
`Transfer-Encoding`, `Upgrade`) and each header that a `Connection` header
names. The allowlist has none of them, but the proxy removes them first, so a
future change to the list cannot let one through.

The proxy name is `reverse-proxy-` and 8 random hexadecimal digits. Each start
of the proxy makes a new name. A request that comes back to the same proxy has
its name in `Via`. A request from another proxy of this program has a different
name, so it is not a loop.

The standard `Forwarded` header is removed and is not set. We set the
`X-Forwarded-*` headers only.

The proxy also changes the request line: the method, the path and the query
stay as they are, and the request goes to the upstream as HTTP/1.1, also when
the client used HTTP/2.

### Loops

A proxy loop is a request that comes back to the proxy that already sent it on.
The proxy looks for its own name in the `Via` header of each request, before
it adds its name. If it finds the name, the proxy:

- answers `508 Loop Detected` with an empty body;
- does not send the request to the upstream;
- writes an audit event with `decision` `DENY` and `reason` `loop`.

The check comes after the identity check (`401`) and before the path check
(`400`) and the policy check (`403`).

The proxy also stops at start (exit code 1) if `SERVER_ADDR` and `PROXY_ADDR`
are the same text. The check does not know that `localhost:8080` and
`127.0.0.1:8080` are the same address.

A client can put any `Via` value in a request. It cannot cause a `508` for
another client, because the name is random and the proxy never sends it to a
client. A client that sends the name of the proxy only makes its own request
fail.

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
- The proxy stops a loop only if every proxy in the loop keeps the `Via`
  header and adds to it. A hop that removes `Via` hides the loop. Nothing counts
  the hops, so a loop that passes through such a hop is not found.
- A direct loop (`SERVER_ADDR` is the proxy) already fails by itself: the proxy
  sends plain HTTP, and its own port needs TLS, so the handshake fails and the
  client gets `502`. The `Via` check matters when a hop in the loop ends TLS.
- The proxy keeps the `Via` values of the client and sends them to the upstream.
  The upstream must not trust them.
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
- **Replace `Via` with one value, as the first version did.** The proxy then
  never sees its own name in a chain, so it cannot find a loop through another
  proxy.
- **Count hops with `Max-Forwards` or a hop counter header.** It stops all
  loops, but it needs a limit that is right for each setup, and a client can
  reset a header that the proxy does not control. We can add it later.
- **A fixed proxy name (`reverse-proxy`).** Another proxy of this program, which
  is a legal hop, would then look like a loop. A random name for each start
  avoids this.
- **Set the standard `Forwarded` header.** It carries the same data in a
  better format. Many upstreams read only `X-Forwarded-*`, so we kept those.
  We can add `Forwarded` later.
- **Reject a request when `Host` and the URI authority differ.** This would
  make `X-Forwarded-Host` more reliable. We have not decided this. The client
  can still send a `Host` that the upstream does not expect.
