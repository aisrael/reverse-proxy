//! Load the certificate chain and the private key of the proxy from PEM files.

use crate::errors::Error;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;

/// The protocols that the proxy offers in the TLS handshake (ALPN), best first.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Make the TLS configuration of the proxy from a certificate file and a key file.
///
/// Use the `ring` crypto provider. The configuration offers HTTP/2 and HTTP/1.1,
/// and it does not ask the client for a certificate.
pub fn server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, Error> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
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
    fn load_key_fails_when_the_file_has_no_key() {
        let path = temp_path("empty-key.pem");
        std::fs::write(&path, "no pem sections here\n").unwrap();

        let err = load_key(path.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(err.to_string().contains("no items found"), "got: {err}");
    }
}
