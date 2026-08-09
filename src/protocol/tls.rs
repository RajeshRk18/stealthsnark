//! TLS and mutual TLS for the data plane.
//!
//! # Why this drives its own accept loop
//!
//! `axum::serve` cannot expose the peer certificate to a handler, and mTLS
//! identity is useless if the handler cannot see who connected. So the listener
//! here accepts the TCP connection, completes the TLS handshake, reads the peer
//! certificate from the finished [`rustls::ServerConnection`], and inserts its
//! digest into the request extensions before hyper serves the connection. The
//! authentication middleware then reads it like any other request state.
//!
//! # Identity from a certificate
//!
//! A client is identified by the SHA-256 digest of its whole certificate in DER
//! form. Two properties matter. It survives re-issue by nothing at all — a
//! renewed certificate is a new identity and must be re-registered, which is the
//! honest behaviour for pinning. And it needs no X.509 parsing, so there is no
//! attack surface in extracting a subject name.
//!
//! Trust is still anchored properly: rustls verifies the chain against the
//! configured client CA first. The digest only maps an already-verified
//! certificate to a principal.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};

use super::config::TlsPaths;
use super::secret::sha256_hex;

/// Request extension holding the verified peer certificate digest.
///
/// Absent when the connection is plain HTTP, or when TLS carried no client
/// certificate. A present value always means rustls accepted the chain.
#[derive(Clone, Debug)]
pub struct PeerCertDigest(pub String);

/// Build a rustls server configuration.
///
/// `require_client_cert` maps to the two useful mTLS postures. When true, a
/// client with no certificate fails the handshake. When false with a CA present,
/// a certificate is requested and verified if offered, but its absence is
/// tolerated — which is what `AuthMode::Any` needs, since such a caller may
/// authenticate with an API key instead.
pub fn server_config(
    paths: &TlsPaths,
    require_client_cert: bool,
) -> anyhow::Result<RustlsServerConfig> {
    let certs = load_certs(&paths.cert)?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", paths.cert.display());
    }
    let key = load_private_key(&paths.key)?;

    let builder = match &paths.client_ca {
        Some(ca_path) => {
            let mut roots = RootCertStore::empty();
            let ca_certs = load_certs(ca_path)?;
            if ca_certs.is_empty() {
                anyhow::bail!("no CA certificates found in {}", ca_path.display());
            }
            for cert in ca_certs {
                roots.add(cert).map_err(|e| {
                    anyhow::anyhow!("invalid client CA in {}: {e}", ca_path.display())
                })?;
            }

            let verifier = if require_client_cert {
                WebPkiClientVerifier::builder(Arc::new(roots)).build()
            } else {
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .allow_unauthenticated()
                    .build()
            }
            .map_err(|e| anyhow::anyhow!("cannot build client certificate verifier: {e}"))?;

            RustlsServerConfig::builder().with_client_cert_verifier(verifier)
        }
        None => {
            if require_client_cert {
                anyhow::bail!(
                    "auth mode mtls requires a client CA; set STEALTHSNARK_TLS_CLIENT_CA"
                );
            }
            RustlsServerConfig::builder().with_no_client_auth()
        }
    };

    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid server certificate or key: {e}"))?;

    // Advertise HTTP/2 and HTTP/1.1. hyper's auto builder serves whichever the
    // client negotiates.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// SHA-256 of a certificate in DER form, hex-encoded.
pub fn cert_digest(cert: &CertificateDer<'_>) -> String {
    sha256_hex(cert.as_ref())
}

/// Digest of the leaf certificate from a finished handshake, when present.
pub fn peer_digest(conn: &rustls::ServerConnection) -> Option<String> {
    conn.peer_certificates()
        .and_then(|chain| chain.first())
        .map(cert_digest)
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read certificate file {}: {e}", path.display()))?;
    let mut reader = io::BufReader::new(&data[..]);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("cannot parse certificates in {}: {e}", path.display()))
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read key file {}: {e}", path.display()))?;
    let mut reader = io::BufReader::new(&data[..]);

    // Accept any of the three encodings a key is plausibly delivered in, rather
    // than making an operator convert the file.
    while let Some(item) = rustls_pemfile::read_one(&mut reader)
        .map_err(|e| anyhow::anyhow!("cannot parse key file {}: {e}", path.display()))?
    {
        match item {
            rustls_pemfile::Item::Pkcs8Key(k) => return Ok(PrivateKeyDer::Pkcs8(k)),
            rustls_pemfile::Item::Pkcs1Key(k) => return Ok(PrivateKeyDer::Pkcs1(k)),
            rustls_pemfile::Item::Sec1Key(k) => return Ok(PrivateKeyDer::Sec1(k)),
            _ => continue,
        }
    }
    anyhow::bail!(
        "no PKCS#8, PKCS#1, or SEC1 private key found in {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway CA, a server certificate, and a client certificate.
    ///
    /// Generated in memory so that no private key is ever committed to the
    /// repository.
    struct Pki {
        dir: std::path::PathBuf,
        client_cert_der: Vec<u8>,
    }

    fn write_pki() -> Pki {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        };

        let dir = std::env::temp_dir().join(format!(
            "stealthsnark-tls-{}",
            super::super::secret::random_hex(8)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "stealthsnark-test-ca");
        ca_params.distinguished_name = ca_dn;
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::new()).unwrap();
        let mut client_dn = DistinguishedName::new();
        client_dn.push(DnType::CommonName, "test-client");
        client_params.distinguished_name = client_dn;
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();

        std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
        std::fs::write(dir.join("server.pem"), server_cert.pem()).unwrap();
        std::fs::write(dir.join("server.key"), server_key.serialize_pem()).unwrap();
        std::fs::write(dir.join("client.pem"), client_cert.pem()).unwrap();

        Pki {
            dir,
            client_cert_der: client_cert.der().to_vec(),
        }
    }

    impl Drop for Pki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn paths(pki: &Pki, with_ca: bool) -> TlsPaths {
        TlsPaths {
            cert: pki.dir.join("server.pem"),
            key: pki.dir.join("server.key"),
            client_ca: with_ca.then(|| pki.dir.join("ca.pem")),
        }
    }

    #[test]
    fn server_only_tls_builds_and_offers_alpn() {
        let pki = write_pki();
        let cfg = server_config(&paths(&pki, false), false).unwrap();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn mtls_builds_with_a_client_ca() {
        let pki = write_pki();
        assert!(server_config(&paths(&pki, true), true).is_ok());
        // Optional client auth is also valid: `AuthMode::Any` needs it.
        assert!(server_config(&paths(&pki, true), false).is_ok());
    }

    #[test]
    fn mtls_without_a_client_ca_is_refused_at_startup() {
        let pki = write_pki();
        let err = server_config(&paths(&pki, false), true).unwrap_err();
        assert!(
            err.to_string().contains("requires a client CA"),
            "got: {err}"
        );
    }

    #[test]
    fn missing_or_malformed_files_are_reported_clearly() {
        let pki = write_pki();

        let mut missing = paths(&pki, false);
        missing.cert = pki.dir.join("absent.pem");
        let err = server_config(&missing, false).unwrap_err();
        assert!(err.to_string().contains("cannot read certificate file"));

        // A key file that holds a certificate rather than a key.
        let mut swapped = paths(&pki, false);
        swapped.key = pki.dir.join("server.pem");
        let err = server_config(&swapped, false).unwrap_err();
        assert!(err.to_string().contains("no PKCS#8"), "got: {err}");
    }

    #[test]
    fn cert_digest_is_stable_and_matches_the_file() {
        let pki = write_pki();
        let der = CertificateDer::from(pki.client_cert_der.clone());
        let a = cert_digest(&der);
        let b = cert_digest(&der);
        assert_eq!(a, b, "digest must be deterministic");
        assert_eq!(a.len(), 64);

        // The same certificate read back from PEM must give the same digest, or
        // registering a client from its PEM file would never match.
        let from_pem = load_certs(&pki.dir.join("client.pem")).unwrap();
        assert_eq!(cert_digest(&from_pem[0]), a);
    }

    #[test]
    fn different_certificates_have_different_digests() {
        let pki = write_pki();
        let client = load_certs(&pki.dir.join("client.pem")).unwrap();
        let server = load_certs(&pki.dir.join("server.pem")).unwrap();
        assert_ne!(cert_digest(&client[0]), cert_digest(&server[0]));
    }
}
