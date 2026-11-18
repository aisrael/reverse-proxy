# ADR 003: Reload the client CA bundle while the proxy runs

- Status: Accepted
- Date: 2026-11-18

## Context

The proxy trusts a client certificate only if a CA in `PROXY_CLIENT_CA` signed
it. An operator must be able to add or remove a CA without a restart. A restart
closes all open connections and stops the traffic for a short time.

## Decision

The proxy watches the CA bundle file and loads it again when it changes.

- **Watch.** The `notify` crate watches the directory of the file, not the file.
  A tool can replace a file with a rename, and a Kubernetes volume changes a
  symbolic link. A watch on the file itself would not see the new file.
  Any change in the directory starts a check. The proxy then compares the
  content of the file with the content that it loaded last, so a change to
  another file in the directory does nothing.
- **Wait.** One update can make many events, and the file can be half written.
  The proxy waits 500 ms after the last event before it reads the file.
- **Validate.** The proxy builds a new verifier from the new content first. If
  the file cannot be read, has no certificate, or has a certificate that is not
  valid as a trust anchor, the proxy logs a warning and keeps the old CAs. This
  is the rollback: the old CAs stay in use until a valid file arrives. The
  warning has the error, never the content of the file.
- **Swap.** `ReloadableClientVerifier` (`src/tls.rs`) holds the current verifier
  behind a lock and sends each call to it. The swap replaces one pointer. The
  lock is held only to copy the pointer, so a handshake never waits for a
  reload. A handshake takes a pointer once, so it uses the old or the new CAs,
  never a mix.
- **Start.** If the proxy cannot start the watch (for example, the directory
  does not exist), it exits with code 1.

## Concurrency and open connections

- The CA check happens in the TLS handshake. A connection that is open does not
  check the certificate again, and the policy check uses the identity from the
  handshake. So a reload does not touch a connection that is open, and a request
  that is running finishes normally.
- A new handshake uses the new CAs.
- The proxy does not resume TLS sessions (`NoServerSessionStorage` and no TLS 1.3
  tickets). A resumed session does not check the client certificate again, so
  a client could keep its access after its CA is removed. We found this when the
  test for a removed CA still passed. The cost: each new connection does a full
  handshake.

## Consequences

- A client with a long connection (HTTP/2, or HTTP/1.1 keep-alive) keeps its
  access after its CA is removed, until the connection closes. The proxy does
  not close connections. If a CA is removed because of a compromise, restart
  the proxy, or add a limit on the age of a connection (not done).
- The proxy does not send a list of accepted CAs in the handshake
  (`root_hint_subjects` is empty). The trait needs a borrow, and the list can
  change. A client that has many certificates may then choose the wrong one.
- The server certificate and key (`PROXY_TLS_CERT`, `PROXY_TLS_KEY`) and the
  policy file are not reloaded. They are read at start only.
- If the new file is not valid, the only sign is a warning in the log. There is
  no metric yet.
- A file that changes back and forth in less than 500 ms makes one reload.

## Alternatives considered

- **Reload on `SIGHUP`.** It is simple, and the operator controls when it
  happens. But a person or a tool must send the signal, and a fleet needs
  more work. The watcher also works with a Kubernetes volume update.
- **Poll the file every N seconds.** No dependency, but a delay and wasted work.
- **Build a new `ServerConfig` and swap the acceptor.** It also reloads the
  server certificate, but each connection task must read the current acceptor.
  A wrapper around the verifier changes less code.
- **Close the connections that the new CAs do not trust.** It stops the access
  at once, but it needs a list of open connections and their CAs. We can add it
  later.
- **Watch the file itself.** It loses the file after a rename or a link swap.
