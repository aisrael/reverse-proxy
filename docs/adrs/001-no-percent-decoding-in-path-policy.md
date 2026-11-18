# ADR 001: Do not decode the request path for the policy

- Status: Accepted
- Date: 2026-11-18

## Context

The policy decides, for each client identity, which method and path it may
use. A rule path is an exact path (`/payments`) or a prefix (`/reports/*`).

The proxy sends the path of the request to the upstream without a change. The
upstream can decode `%` sequences (percent-encoding). If the policy checks one
form of the path and the upstream uses another form, a client can pass the
check with one path and reach a different resource.

Example: the rule `/reports/*` allows `/reports/%2e%2e/admin`, because the text
starts with `/reports/`. An upstream that decodes the path reads
`/reports/../admin`, which is `/admin`. The client has now reached a resource
that the policy does not allow.

## Decision

1. The policy compares the path exactly as the client sent it. We do not decode
   `%` sequences before the comparison.
2. The proxy answers `400` and does not forward the request if the path (the
   part before `?`):
   - does not start with `/`;
   - has an empty segment (`//`), except one at the end (`/reports/`);
   - has a segment that is `.` or `..`;
   - has a NUL character, or `%00` (an encoded NUL);
   - has `%2f`, `%2e` or `%5c` in any letter case (an encoded `/`, `.` or `\`).
3. The query (the part after `?`) is not part of the path. The policy ignores
   it.
4. A prefix rule matches whole segments only. `/reports/*` matches
   `/reports/1`. It does not match `/reports`, `/reports/` or
   `/reports-old/1`.
5. The method match is exact and case-sensitive.

The code is in `src/policy.rs`: `Policy::authorize` and `is_valid_path`.

## Consequences

- The policy and the upstream always see the same bytes, so a client cannot
  hide a dot segment or a slash in an encoded form.
- We reject the encodings that can change the structure of the path (`%2f`,
  `%2e`, `%5c`) or cut it (`%00`). We do not need a decoder, and there is no
  decoder to get wrong.
- Other encoded characters stay as literal text. `/a%20b` is valid, and it
  matches only a rule that has `%20`. `/%61dmin` does not match a rule for
  `/admin`. The result is a `403`. This is safe, but it can surprise people.
- A valid request with an encoded slash, for example `/files/a%2fb`, gets
  `400`. We accept this cost.
- Double encoding (`%252e`) is not rejected. It is literal text to the proxy.
  It is a problem only if the upstream decodes the path two times. The proxy
  cannot prevent that.

## Alternatives considered

- **Decode the path, then check it.** The check is then correct only if the
  decoder is the same as the one in the upstream. Decoders differ in how they
  treat invalid sequences, double encoding and `%00`. A difference is a bypass.
- **Decode the path and forward the decoded form.** This changes the request
  that the client sent, and it breaks upstreams that need the encoded form,
  for example for an encoded slash in an ID.
- **Allow the three encodings and match them as text.** A prefix rule would then
  allow `/reports/%2e%2e/admin`. This is the case that we want to prevent.
