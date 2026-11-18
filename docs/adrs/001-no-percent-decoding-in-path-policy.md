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
5. The method match is exact. A method in the policy file can have any letter
   case (`get`, `GET`). We read it as a `hyper::Method` when we load the file.
   The method of a request is compared as it comes from the client, so `post`
   does not match a rule for `POST`.
6. A rule path is an exact path, or a prefix that ends with `/*`. A `*` in any
   other place is an error when we load the file.
7. The proxy checks the policy file when it starts, and stops at the first
   problem (see "How we prevent ambiguous matching").

The code is in `src/policy.rs`: `Policy::authorize` and `is_valid_path`.

## How we prevent ambiguous matching

A bypass needs two readings of the same request: the policy reads one, the
upstream reads the other. We remove each source of a second reading.

| Risk | What we do |
| ---- | ---------- |
| The upstream decodes the path, and the policy does not. | The policy uses the bytes that the proxy forwards. We never decode. |
| An encoded `/`, `.` or `\` hides a path structure (`/reports/%2e%2e/admin`). | `400` for `%2f`, `%2e` and `%5c` in any letter case. |
| An encoded or raw NUL cuts the path in the upstream. | `400` for `%00` and for a NUL character. |
| A dot segment moves the path (`/reports/../admin`). | `400` for a `.` or `..` segment. |
| An empty segment (`//`) is merged by some upstreams. | `400` for an empty segment, except one at the end. |
| A path without a leading `/` (`*`, or `echo`) is read in another way. | `400` if the path does not start with `/`. |
| An absolute URI as the request target (`GET http://other/echo`). | hyper gives us the path part only, so the policy checks that part. The proxy ignores the host in the URI, and always sends the request to the configured upstream. |
| A query changes what the upstream serves, or hides a path (`?x=/../`). | The policy ignores the query. It is never part of the match. |
| A prefix that matches a part of a segment (`/reports-old` for `/reports/*`). | The prefix keeps its `/`, and a `*` matches whole segments only. |
| A `*` in the middle of a rule (`/a/*/b`) or without `/` (`/reports*`) is read as a wildcard by the author, and as a literal by the matcher. | The proxy does not start. Only a trailing `/*` is a wildcard. |
| A rule that no request can match (for example `/a/../b`) is a mistake that hides as a `403`. | The proxy does not start. We check the literal part of every rule path with the same function that checks the request path. |
| Two readings of an identity (case, a port, a trailing `/`, `..`). | An identity in the policy must parse as a SPIFFE ID, with the same code that reads the certificate. The match is an exact text match. There is no normalisation. |
| Two readings of a method (`get` and `GET`). | The file is read as `hyper::Method` in upper case. A request is compared exactly. |
| A policy entry with a field that we do not know (`methods:` for `method:`) is silently ignored. | The file must follow `policy-schema.yaml`. It has `additionalProperties: false` at each level. |
| An identity with no rule, or an empty `allow`, allows something by mistake. | The default is deny. An empty `allow` is an error at start. |

We apply the same path checks to the request and to the rule. A rule and a
request that look the same are therefore compared in the same way.

The checks happen in this order: the YAML schema (`policy-schema.yaml`), then
the values in Rust (`check_content` in `src/policy.rs`). The first problem stops
the start. The proxy never runs with a policy that we did not check.

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
