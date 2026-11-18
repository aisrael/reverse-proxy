//! Load the certificate chain and the private key of the proxy from PEM files.

use crate::errors::Error;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;

/// Read all certificates from the PEM file at `path`. The first one is the
/// certificate of the server. The others are the chain, in order.
/// Return an error if the file has no certificate.
#[cfg_attr(not(test), expect(dead_code, reason = "the TLS listener will use it"))]
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
#[cfg_attr(not(test), expect(dead_code, reason = "the TLS listener will use it"))]
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
