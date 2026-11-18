//! Load the certificate chain and the private key of the proxy, and the CA
//! bundle for the client certificates, from PEM files.

use crate::errors::Error;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::server::NoServerSessionStorage;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerified;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::UnixTime;
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;
use std::sync::PoisonError;
use std::sync::RwLock;

/// The protocols that the proxy offers in the TLS handshake (ALPN), best first.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// A client certificate verifier that can change while the proxy runs.
///
/// It sends each call to the current inner verifier. `replace` changes the
/// inner verifier. A TLS handshake that is already running keeps the verifier
/// that it started with. A connection that is already open does not check the
/// client certificate again. So a change is only for new handshakes.
#[derive(Debug)]
pub struct ReloadableClientVerifier {
    current: RwLock<Arc<dyn ClientCertVerifier>>,
}

impl ReloadableClientVerifier {
    /// Make a verifier that starts with `inner`.
    pub fn new(inner: Arc<dyn ClientCertVerifier>) -> Self {
        Self {
            current: RwLock::new(inner),
        }
    }

    /// Use `inner` for all new calls.
    pub fn replace(&self, inner: Arc<dyn ClientCertVerifier>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = inner;
    }

    /// The current inner verifier. The lock is free when this returns.
    fn snapshot(&self) -> Arc<dyn ClientCertVerifier> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ClientCertVerifier for ReloadableClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.snapshot().offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.snapshot().client_auth_mandatory()
    }

    /// Always empty. The method returns a borrow of `self`, and the list can
    /// change. An empty list is allowed: the client then sends its certificate
    /// if it has one, and the proxy decides if it trusts the CA.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.snapshot()
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.snapshot().verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.snapshot().verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.snapshot().supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.snapshot().requires_raw_public_keys()
    }
}

/// Read a whole file. Return the bytes of the PEM data in it.
/// Return an error if the file cannot be read.
pub fn read_pem_file(path: &str) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|source| pem_error(path, rustls_pki_types::pem::Error::Io(source)))
}

/// Make a verifier from the CA bundle file at `path`. Return it and the number
/// of CAs in the file.
/// Return an error if the file cannot be read, has no certificate, or has a
/// certificate that is not valid as a trust anchor.
pub fn build_client_verifier(path: &str) -> Result<(Arc<dyn ClientCertVerifier>, usize), Error> {
    build_client_verifier_from_pem(path, &read_pem_file(path)?)
}

/// Make a verifier from the PEM data of a CA bundle, as `build_client_verifier`
/// does. `path` is only for the error messages.
pub fn build_client_verifier_from_pem(
    path: &str,
    pem: &[u8],
) -> Result<(Arc<dyn ClientCertVerifier>, usize), Error> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| pem_error(path, source))?;
    if certs.is_empty() {
        return Err(pem_error(path, rustls_pki_types::pem::Error::NoItemsFound));
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert)?;
    }
    let count = roots.len();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
    Ok((verifier, count))
}

/// Make the TLS configuration of the proxy from a certificate file, a key file
/// and a CA bundle file.
///
/// Use the `ring` crypto provider. The configuration offers HTTP/2 and HTTP/1.1.
/// It requires a client certificate that one of the CAs in `client_ca_path`
/// signed. The handshake fails for a client without a valid certificate.
/// The proxy does not resume TLS sessions: every handshake checks the client
/// certificate against the current CAs.
///
/// Also return the verifier. Call `replace` on it to change the trusted CAs
/// while the proxy runs.
pub fn server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<(ServerConfig, Arc<ReloadableClientVerifier>), Error> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let (inner, _) = build_client_verifier(client_ca_path)?;
    let verifier = Arc::new(ReloadableClientVerifier::new(inner));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(certs, key)?;
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|name| name.to_vec()).collect();
    // A resumed session does not check the client certificate again. If the
    // proxy allowed it, a client could keep its access after its CA is removed.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok((config, verifier))
}

/// Read all certificates from the PEM file at `path`. The first one is the
/// certificate of the server. The others are the chain, in order.
/// Return an error if the file has no certificate.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|source| pem_error(path, source))?;
    if certs.is_empty() {
        return Err(pem_error(path, rustls_pki_types::pem::Error::NoItemsFound));
    }
    Ok(certs)
}

/// Read the first private key from the PEM file at `path`.
/// The key can be in PKCS#8, PKCS#1 (RSA) or SEC1 (EC) format.
/// Return an error if the file has no private key.
pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, Error> {
    PrivateKeyDer::from_pem_file(path).map_err(|source| pem_error(path, source))
}

fn pem_error(path: &str, source: rustls_pki_types::pem::Error) -> Error {
    Error::Pem {
        path: path.to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A path in the temporary directory. The name has the ID of the process,
    /// so two test runs do not share files.
    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("reverse-proxy-{}-{name}", std::process::id()))
    }

    #[test]
    fn load_certs_fails_when_the_file_does_not_exist() {
        let path = temp_path("no-such-file.pem");

        let err = load_certs(path.to_str().unwrap()).unwrap_err();

        assert!(matches!(err, Error::Pem { .. }), "got: {err}");
        assert!(err.to_string().contains("no-such-file.pem"), "got: {err}");
    }

    #[test]
    fn load_certs_fails_when_the_file_has_no_certificate() {
        let path = temp_path("empty-certs.pem");
        std::fs::write(&path, "no pem sections here\n").unwrap();

        let err = load_certs(path.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(err.to_string().contains("no items found"), "got: {err}");
    }

    #[test]
    fn build_client_verifier_loads_the_dev_ca() {
        // `scripts/gen-dev-certs.sh` makes this file. It holds no secret.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/ca.pem");

        let (_, count) = build_client_verifier(path).unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn build_client_verifier_fails_when_the_file_does_not_exist() {
        let path = temp_path("no-such-ca.pem");

        let err = build_client_verifier(path.to_str().unwrap())
            .map(|_| ())
            .unwrap_err();

        assert!(matches!(err, Error::Pem { .. }), "got: {err}");
        assert!(err.to_string().contains("no-such-ca.pem"), "got: {err}");
    }

    #[test]
    fn build_client_verifier_fails_when_the_file_has_no_certificate() {
        let path = temp_path("empty-ca.pem");
        std::fs::write(&path, "no pem sections here\n").unwrap();

        let err = build_client_verifier(path.to_str().unwrap())
            .map(|_| ())
            .unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(err.to_string().contains("no items found"), "got: {err}");
    }

    fn dev_cert(name: &str) -> CertificateDer<'static> {
        let path = format!("{}/dev-certs/{name}.pem", env!("CARGO_MANIFEST_DIR"));
        load_certs(&path).unwrap().remove(0)
    }

    fn dev_verifier(ca: &str) -> Arc<dyn ClientCertVerifier> {
        let path = format!("{}/dev-certs/{ca}.pem", env!("CARGO_MANIFEST_DIR"));
        build_client_verifier(&path).unwrap().0
    }

    #[test]
    fn build_client_verifier_counts_the_cas() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/ca.pem");

        let (_, count) = build_client_verifier(path).unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn reloadable_verifier_uses_the_new_inner_verifier_after_replace() {
        let verifier = ReloadableClientVerifier::new(dev_verifier("ca"));
        let trusted = dev_cert("payment-agent");
        let untrusted = dev_cert("untrusted-agent");
        let now = UnixTime::now();
        assert!(verifier.verify_client_cert(&trusted, &[], now).is_ok());
        assert!(verifier.verify_client_cert(&untrusted, &[], now).is_err());

        verifier.replace(dev_verifier("other-ca"));

        assert!(verifier.verify_client_cert(&trusted, &[], now).is_err());
        assert!(verifier.verify_client_cert(&untrusted, &[], now).is_ok());
    }

    #[test]
    fn load_key_fails_when_the_file_has_no_key() {
        let path = temp_path("empty-key.pem");
        std::fs::write(&path, "no pem sections here\n").unwrap();

        let err = load_key(path.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(err.to_string().contains("no items found"), "got: {err}");
    }
}
