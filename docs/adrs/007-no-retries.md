# ADR 007: The proxy does not retry requests

- Status: Accepted
- Date: 2026-11-19

## Context

A request to the upstream can fail. The upstream can refuse the connection, close it, send an error, or not answer in time. A proxy can send the request again, and some clients do this to hide short failures.

A retry is not always safe:

- The proxy streams the request body and does not keep it (see ADR 005). After the proxy sends part of the body, it cannot send the body again.
- A request that changes data (`POST`, `PATCH`) can run twice if the first attempt reached the upstream but the answer was lost. The upstream is an HSM signing service, so a second request can sign a second time.
- The proxy does not know which requests are idempotent. The policy has no such setting.
- A retry uses more of the upstream time budget (`PROXY_UPSTREAM_TIMEOUT_SECS`). When the upstream is slow or overloaded, retries add load and make the failure worse.

## Decision

1. The proxy does not retry a request that it has sent to the upstream. One request from the client makes at most one request to the upstream.
2. A failure goes to the client at once:

   | Failure | What the client gets |
   | --- | --- |
   | The proxy cannot connect, or the connection fails or closes before a response head. | `502` |
   | The upstream does not send a response head in time. | `504` |
   | The upstream sends an error status (for example `500`). | The same status, forwarded. |

   The client decides if it sends the request again.

3. The proxy has no retry setting, no back-off and no circuit breaker.

### One case that the HTTP client library retries

The proxy uses the pooled client of `hyper-util`. It keeps idle connections to the upstream. An idle connection can close at the upstream side without the proxy seeing it. Then the library finds the problem when it tries to use the connection. In this case, and only in this case, the library sends the request again, on a new connection. This is the `retry_canceled_requests` setting. It is on by default and the proxy does not change it.

This retry is safe because:

- it happens only when the connection was already in the pool (a reused connection), and the library did not start to send the request on it;
- the upstream never received the request, so it cannot run twice;
- it does not happen for a new connection, or after the proxy sent any part of the request.

This is not a retry of a failed request. It is the recovery from a stale pool entry. It is inside the upstream timeout: the timer covers all attempts, so a request never waits longer than `PROXY_UPSTREAM_TIMEOUT_SECS`.

## Consequences

- The behavior is simple and easy to predict. A request cannot run twice because of the proxy, and the proxy adds no load to a failing upstream.
- A short failure of the upstream (for example a restart) shows to the client as `502` or `504`. The client must send the request again, with its own rules and its own knowledge of which requests are safe.
- The proxy does not buffer the request body, so a retry would need a new design for the body. This decision keeps the streaming model of ADR 005.
- The proxy has one upstream and no pool of upstream servers, so a retry would go to the same server. It would not help when that server is down.

## Alternatives

- **Retry idempotent methods only (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`).** This is safer, but the proxy must still handle a body for `PUT` and `DELETE`, and an upstream can break the rule that `GET` has no effect. It also needs a limit on the number of attempts, a back-off, and a retry budget, so that retries do not overload the upstream.
- **Retry only when the connection fails before the proxy sends anything.** This is nearly what the library does for a stale pool entry. A connection that cannot open is usually a real outage, and a second attempt gives the same result.
- **Buffer the request body and retry all methods.** This removes the streaming design, needs a size limit in memory, and can run a non-idempotent request twice.
- **Add a circuit breaker.** This protects an upstream under load, but it adds state and settings that the proxy does not need with one upstream.
