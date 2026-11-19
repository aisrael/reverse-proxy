//! The identity of a client. It comes from the SPIFFE ID in the client
//! certificate.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;

const SCHEME: &str = "spiffe://";

/// A SPIFFE ID, for example `spiffe://acme/prod/payment-agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    trust_domain: String,
    path: String,
}

/// The reason why we cannot read an identity from a certificate.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum IdentityError {
    #[error("the certificate cannot be parsed")]
    InvalidCertificate,
    #[error("the certificate has no URI SAN")]
    NoUriSan,
    #[error("the certificate has more than one URI SAN")]
    MultipleUriSans,
    #[error("the URI SAN is not a valid SPIFFE ID")]
    InvalidSpiffeId,
}

impl Identity {
    /// The trust domain, for example `acme`.
    #[allow(dead_code)]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The path, with the first `/`, for example `/prod/payment-agent`.
    #[allow(dead_code)]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Read the identity from the certificate in `der` (DER format).
    /// The certificate must have exactly one URI SAN, and it must be a valid
    /// SPIFFE ID.
    pub fn from_certificate(der: &[u8]) -> Result<Self, IdentityError> {
        let (_, cert) =
            parse_x509_certificate(der).map_err(|_| IdentityError::InvalidCertificate)?;
        let san = cert
            .subject_alternative_name()
            .map_err(|_| IdentityError::InvalidCertificate)?
            .ok_or(IdentityError::NoUriSan)?;
        let mut uris = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            });
        let uri = uris.next().ok_or(IdentityError::NoUriSan)?;
        if uris.next().is_some() {
            return Err(IdentityError::MultipleUriSans);
        }
        uri.parse()
    }
}

/// The fields of a client certificate that go to the audit event. The proxy
/// does not use them to decide anything.
///
/// The TLS layer checks the chain and the dates. See `docs/adrs/006-log-client-certificate-fields.md`.
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The subject, for example `CN=payment-agent`.
    pub subject: String,
    /// The issuer.
    pub issuer: String,
    /// The serial number, in hexadecimal, with `:` between the bytes.
    pub serial: String,
    /// The start of the validity (NotBefore), RFC 2822.
    pub not_before: String,
    /// The end of the validity (NotAfter), RFC 2822.
    pub not_after: String,
    /// All the URI SANs, not only the SPIFFE ID.
    pub uri_sans: Vec<String>,
    /// All the DNS SANs.
    pub dns_sans: Vec<String>,
}

impl CertificateInfo {
    /// Read the fields from the certificate in `der` (DER format).
    pub fn from_certificate(der: &[u8]) -> Result<Self, IdentityError> {
        let (_, cert) =
            parse_x509_certificate(der).map_err(|_| IdentityError::InvalidCertificate)?;
        let mut uri_sans = Vec::new();
        let mut dns_sans = Vec::new();
        let san = cert
            .subject_alternative_name()
            .map_err(|_| IdentityError::InvalidCertificate)?;
        if let Some(san) = san {
            for name in &san.value.general_names {
                match name {
                    GeneralName::URI(uri) => uri_sans.push((*uri).to_owned()),
                    GeneralName::DNSName(dns) => dns_sans.push((*dns).to_owned()),
                    _ => {}
                }
            }
        }
        let validity = cert.validity();
        Ok(Self {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            serial: cert.raw_serial_as_string(),
            not_before: format_time(&validity.not_before),
            not_after: format_time(&validity.not_after),
            uri_sans,
            dns_sans,
        })
    }
}

/// Format a time as RFC 2822, for example `Wed, 01 Jan 2020 00:00:00 +0000`.
fn format_time(time: &ASN1Time) -> String {
    time.to_rfc2822()
        .unwrap_or_else(|_| "(invalid time)".to_owned())
}

impl FromStr for Identity {
    type Err = IdentityError;

    /// Parse a SPIFFE ID. The ID must have a trust domain and a path. It must
    /// not have user info, a port, a query or a fragment.
    fn from_str(uri: &str) -> Result<Self, IdentityError> {
        let rest = uri
            .strip_prefix(SCHEME)
            .ok_or(IdentityError::InvalidSpiffeId)?;
        // `path` starts with the first `/`.
        let slash = rest.find('/').ok_or(IdentityError::InvalidSpiffeId)?;
        let (trust_domain, path) = rest.split_at(slash);
        let valid = !trust_domain.is_empty()
            && trust_domain.chars().all(is_trust_domain_char)
            && path[1..].split('/').all(is_path_segment);
        if !valid {
            return Err(IdentityError::InvalidSpiffeId);
        }
        Ok(Self {
            trust_domain: trust_domain.to_owned(),
            path: path.to_owned(),
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}{}", self.trust_domain, self.path)
    }
}

fn is_trust_domain_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
}

/// A path segment is not empty, is not `.` or `..`, and has only these
/// characters: letters, digits, `.`, `-` and `_`.
fn is_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::load_certs;

    fn dev_cert(name: &str) -> Vec<u8> {
        // `scripts/gen-dev-certs.sh` makes these files. They hold no secret.
        let path = format!("{}/dev-certs/{name}.pem", env!("CARGO_MANIFEST_DIR"));
        load_certs(&path).unwrap().remove(0).to_vec()
    }

    #[test]
    fn reads_the_spiffe_id_from_a_client_certificate() {
        let identity = Identity::from_certificate(&dev_cert("payment-agent")).unwrap();

        assert_eq!(identity.trust_domain(), "acme");
        assert_eq!(identity.path(), "/prod/payment-agent");
        assert_eq!(identity.to_string(), "spiffe://acme/prod/payment-agent");
    }

    #[test]
    fn reads_the_other_client_certificate() {
        let identity = Identity::from_certificate(&dev_cert("reporting-agent")).unwrap();

        assert_eq!(identity.to_string(), "spiffe://acme/prod/reporting-agent");
    }

    #[test]
    fn reads_the_fields_of_a_client_certificate() {
        let info = CertificateInfo::from_certificate(&dev_cert("payment-agent")).unwrap();

        assert!(info.subject.contains("payment-agent"), "{}", info.subject);
        assert!(!info.issuer.is_empty());
        assert!(!info.serial.is_empty());
        assert!(!info.not_before.is_empty());
        assert!(!info.not_after.is_empty());
        assert_ne!(info.not_before, info.not_after);
        assert_eq!(info.uri_sans, ["spiffe://acme/prod/payment-agent"]);
        assert!(info.dns_sans.is_empty());
    }

    #[test]
    fn reads_the_dns_sans_of_a_server_certificate() {
        let info = CertificateInfo::from_certificate(&dev_cert("server")).unwrap();

        assert!(info.dns_sans.contains(&"localhost".to_owned()));
        assert!(info.uri_sans.is_empty());
    }

    #[test]
    fn reads_the_fields_of_a_certificate_without_a_uri_san() {
        let info = CertificateInfo::from_certificate(&dev_cert("no-uri-agent")).unwrap();

        assert!(info.uri_sans.is_empty());
    }

    #[test]
    fn cannot_read_the_fields_of_bytes_that_are_not_a_certificate() {
        let err = CertificateInfo::from_certificate(b"not a certificate").unwrap_err();

        assert_eq!(err, IdentityError::InvalidCertificate);
    }

    #[test]
    fn rejects_a_certificate_without_a_uri_san() {
        // The server certificate has DNS and IP SANs only.
        let err = Identity::from_certificate(&dev_cert("server")).unwrap_err();

        assert_eq!(err, IdentityError::NoUriSan);
    }

    #[test]
    fn rejects_bytes_that_are_not_a_certificate() {
        let err = Identity::from_certificate(b"not a certificate").unwrap_err();

        assert_eq!(err, IdentityError::InvalidCertificate);
    }

    #[test]
    fn accepts_valid_spiffe_ids() {
        for uri in [
            "spiffe://acme/a",
            "spiffe://acme.example.com/prod/payment-agent",
            "spiffe://a-b_c/x.y/z_1",
        ] {
            assert!(uri.parse::<Identity>().is_ok(), "{uri}");
        }
    }

    #[test]
    fn rejects_invalid_spiffe_ids() {
        for uri in [
            "",
            "https://acme/prod/agent",
            "SPIFFE://acme/prod/agent",
            "spiffe://",
            "spiffe://acme",
            "spiffe://acme/",
            "spiffe:///prod/agent",
            "spiffe://acme/prod/",
            "spiffe://acme//agent",
            "spiffe://acme/prod/../agent",
            "spiffe://acme/./agent",
            "spiffe://user@acme/agent",
            "spiffe://acme:8080/agent",
            "spiffe://acme/agent?x=1",
            "spiffe://acme/agent#frag",
            "spiffe://Acme/agent",
            "spiffe://acme/ag%2Fent",
            "spiffe://acme/ag ent",
        ] {
            assert_eq!(
                uri.parse::<Identity>().unwrap_err(),
                IdentityError::InvalidSpiffeId,
                "{uri:?}"
            );
        }
    }
}
