# ADR 006: Write the fields of the client certificate to the audit event

- Status: Accepted
- Date: 2026-11-19

## Context

The proxy needs a client certificate (mTLS). Two parts check it:

- The TLS layer (`rustls`, in the handshake) checks the chain, the signatures and the dates (NotBefore and NotAfter). A certificate that fails stops the handshake.
- The application (`src/identity.rs`, after the handshake) reads the SPIFFE ID from the URI SAN. This is the only field that the proxy uses for a decision.

Nothing checks the other fields: the subject, the issuer, the serial number and the DNS SANs. They have no effect on the authorization. But an operator who looks at a request needs them. For example, the operator must know which certificate a client used, when it expires, and who issued it. Two certificates can have the same SPIFFE ID, and the serial number tells them apart.

## Decision

1. The proxy reads these fields of the client certificate when a connection starts: the subject, the issuer, the serial number, NotBefore, NotAfter, all URI SANs and all DNS SANs. The type is `CertificateInfo` in `src/identity.rs`. All requests of the connection share the fields.
2. The proxy writes the fields to the audit event, with the prefix `cert_`:

   | Field | Value |
   | --- | --- |
   | `cert_subject` | The subject. |
   | `cert_issuer` | The issuer. |
   | `cert_serial` | The serial number in hexadecimal, with `:` between bytes. |
   | `cert_not_before` | NotBefore, in RFC 2822 format. |
   | `cert_not_after` | NotAfter, in RFC 2822 format. |
   | `cert_uri_sans` | All URI SANs, separated by `,`. Not in the event if none. |
   | `cert_dns_sans` | All DNS SANs, separated by `,`. Not in the event if none. |

   The `identity` field does not change. It is still the SPIFFE ID.

3. The proxy does not use the fields for a decision. The decision uses the SPIFFE ID only.
4. The proxy never writes the certificate itself (the PEM or the DER bytes).
5. If the proxy cannot read the certificate, or the client has none, the event has no `cert_` field. The proxy writes a `debug` line to STDERR (`client certificate cannot be read`). A client with a certificate that has no valid SPIFFE ID gets `401`, as before, and its event has the `cert_` fields.

The code is in `src/identity.rs` (`CertificateInfo`), `src/audit.rs` (`record`) and `src/proxy.rs` (`client_certificate`).

## Consequences

- An event shows which certificate made the request: its serial number, its issuer and when it expires. An operator can find the requests of one certificate, and a certificate that is about to expire.
- The audit event has more data. The subject and the SANs can have names of people or systems. Anyone who can read the audit events can read them. Give the audit log the same access control as the data that the proxy protects. The event still never has a header, a cookie, a body or a query.
- Each request has the fields, not only the first request of a connection. The events are larger, and a log system stores the same text many times.
- The fields are not checked. A certificate with a subject or a DNS SAN that does not look right still works, if the chain and the dates are valid and the URI SAN is a valid SPIFFE ID that the policy allows.
- The proxy still does not check revocation. The serial number in the event helps an operator to find a certificate that must be revoked, but the proxy does not use a CRL or OCSP.

### Known limit: no fields for a rejected certificate

The proxy reads the fields after the handshake works. The TLS layer rejects a certificate that is expired, not valid yet, or not signed by a trusted CA before the proxy sees it. For these clients:

- there is no HTTP request, so there is no audit event;
- the proxy writes only `TLS handshake failed` and the error to the `debug` log.

So an operator cannot see the serial number or the dates of a certificate that the TLS layer rejected. To see them, the proxy would need to wrap the client certificate verifier, read the fields before the check, and write a log line for each failure. We did not do this in this change. The client can show the certificate with `openssl x509`, and the error text of the handshake says why it failed.

## Alternatives

- **Log the fields at `debug` level, and keep the audit event as it was.** The audit event would have no sensitive names, and the default log would not change. But the fields would not be in the same record as the request, and they would be off in a normal run, so they would not help with an incident that is already over. We first chose this, and then changed it.
- **Add only the serial number and the issuer to the audit event.** This is a smaller set, with fewer names. We chose all the fields because the audit event is where an operator looks first.
- **Write the fields once for each connection.** The log would be smaller, but an operator would need to join a connection line to its requests. The proxy has no connection ID in the event.
- **Use the fields for the policy.** For example, a rule could match the issuer or a DNS SAN. This makes the policy larger and gives a second kind of identity. The SPIFFE ID is the one identity that the policy uses.
- **Do not read the fields.** This is the smallest code. An operator would then need `openssl` and the certificate file to see which certificate a client uses, and the proxy does not have the file of the client.
