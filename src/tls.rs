//! Load the certificate chain and the private key of the proxy, and the CA
//! bundle for the client certificates, from PEM files.

use crate::errors::Error;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;

/// The protocols that the proxy offers in the TLS handshake (ALPN), best first.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Make the TLS configuration of the proxy from a certificate file, a key file
/// and a CA bundle file.
///
/// Use the `ring` crypto provider. The configuration offers HTTP/2 and HTTP/1.1.
/// It requires a client certificate that one of the CAs in `client_ca_path`
/// signed. The handshake fails for a client without a valid certificate.
pub fn server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<ServerConfig, Error> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let roots = load_client_ca(client_ca_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|name| name.to_vec()).collect();
    Ok(config)
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

/// Read the CA certificates from the PEM file at `path`. The proxy trusts a
/// client certificate only if one of these CAs signed it.
/// Return an error if the file has no certificate, or if a certificate is not
/// valid as a trust anchor.
pub fn load_client_ca(path: &str) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
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
    fn load_client_ca_loads_the_dev_ca() {
        // `scripts/gen-dev-certs.sh` makes this file. It holds no secret.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/dev-certs/ca.pem");

        let roots = load_client_ca(path).unwrap();

        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn load_client_ca_fails_when_the_file_does_not_exist() {
        let path = temp_path("no-such-ca.pem");

        let err = load_client_ca(path.to_str().unwrap()).unwrap_err();

        assert!(matches!(err, Error::Pem { .. }), "got: {err}");
        assert!(err.to_string().contains("no-such-ca.pem"), "got: {err}");
    }

    #[test]
    fn load_client_ca_fails_when_the_file_has_no_certificate() {
        let path = temp_path("empty-ca.pem");
        std::fs::write(&path, "no pem sections here\n").unwrap();

        let err = load_client_ca(path.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(err.to_string().contains("no items found"), "got: {err}");
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
