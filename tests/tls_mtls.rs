//! TLS and mutual TLS over a real handshake.
//!
//! Every certificate here is generated in memory, so no private key is ever
//! committed to the repository. The suite is skipped when the `tls` feature is
//! off, which is also how the fuzz build stays lean.
//!
//! These tests exist because the mTLS identity path cannot be checked any other
//! way. Whether rustls verified the chain, and whether the resulting certificate
//! digest reaches the authentication middleware, only becomes true after a
//! handshake actually completes.

#![cfg(feature = "tls")]

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ark_bn254::{G1Affine, G1Projective as G1, G2Affine};
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::protocol::auth::{
    generate_api_key, AuthFile, AuthMode, AuthStore, PrincipalSpec, TierSpec,
};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::config::{ServerConfig, TlsPaths};
use stealthsnark::protocol::messages::*;
use stealthsnark::protocol::server::{create_router, AppState};
use stealthsnark::protocol::tls;

/// A throwaway CA with a server certificate and two client certificates.
struct Pki {
    dir: PathBuf,
    ca_pem: String,
    /// Certificate and key concatenated, which is what reqwest wants.
    client_identity_pem: String,
    client_cert_digest: String,
    /// A second client, signed by the same CA but never registered.
    stranger_identity_pem: String,
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn build_pki() -> Pki {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    // A unique directory per call. Sharing one path across tests let parallel
    // runs overwrite each other's certificate and key, which surfaced as
    // KeyMismatch and BadSignature rather than as an obvious collision.
    let dir = std::env::temp_dir().join(format!(
        "stealthsnark-tls-{}-{}",
        std::process::id(),
        stealthsnark::protocol::secret::random_hex(8)
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "stealthsnark-test-ca");
    ca_params.distinguished_name = ca_dn;
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // The SAN must match the host the client dials, or verification fails.
    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let client = |name: &str| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
        let identity = format!("{}{}", cert.pem(), key.serialize_pem());
        (cert, identity)
    };

    let (client_cert, client_identity_pem) = client("registered-client");
    let (_stranger_cert, stranger_identity_pem) = client("stranger-client");

    std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("server.pem"), server_cert.pem()).unwrap();
    std::fs::write(dir.join("server.key"), server_key.serialize_pem()).unwrap();

    let der = rustls::pki_types::CertificateDer::from(client_cert.der().to_vec());
    Pki {
        ca_pem: ca_cert.pem(),
        client_identity_pem,
        client_cert_digest: tls::cert_digest(&der),
        stranger_identity_pem,
        dir,
    }
}

fn paths(pki: &Pki, with_client_ca: bool) -> TlsPaths {
    TlsPaths {
        cert: pki.dir.join("server.pem"),
        key: pki.dir.join("server.key"),
        client_ca: with_client_ca.then(|| pki.dir.join("ca.pem")),
    }
}

fn roomy_tier() -> HashMap<String, TierSpec> {
    let mut t = HashMap::new();
    t.insert(
        "roomy".to_string(),
        TierSpec {
            max_sessions: 32,
            max_body_bytes: 64 * 1024 * 1024,
            requests_per_sec: 1000.0,
            burst: 1000,
        },
    );
    t
}

/// Serve the data plane over TLS on an ephemeral port. Returns the base URL.
///
/// This mirrors `protocol::server::serve_tls`: accept, handshake, insert the peer
/// certificate digest, then hand the connection to hyper. Reimplemented here
/// because the test needs the bound port back, which `serve` does not return.
async fn spawn_tls(cfg: ServerConfig, auth: AuthStore) -> (String, AppState) {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use tower::Service;

    let tls_paths = cfg.tls.clone().expect("test config must carry TLS paths");
    let require_cert = cfg.auth_mode.requires_client_cert();
    let state = AppState::with_auth(cfg, auth);

    let tls_config = tls::server_config(&tls_paths, require_cert).expect("valid TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = create_router(state.clone());

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let digest = tls::peer_digest(tls_stream.get_ref().1);
                let io = TokioIo::new(tls_stream);
                let service = hyper::service::service_fn(move |mut req: axum::http::Request<_>| {
                    if let Some(d) = digest.clone() {
                        req.extensions_mut().insert(tls::PeerCertDigest(d));
                    }
                    router.clone().call(req)
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await;
            });
        }
    });

    // `localhost`, not 127.0.0.1: the server certificate's SAN says localhost, and
    // dialling the IP would fail verification for the wrong reason.
    (format!("https://localhost:{port}"), state)
}

fn generators_body(n: usize, seed: u64) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let g1: Vec<G1Affine> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let g2: Vec<G2Affine> = Vec::new();
    bincode::serialize(&SetupRequest::encode(&g1, &g1, &g1, &g1, &g2).unwrap()).unwrap()
}

fn tls_config(pki: &Pki, mode: AuthMode, with_client_ca: bool) -> ServerConfig {
    ServerConfig {
        auth_mode: mode,
        auth_file: Some(PathBuf::from("/dev/null")),
        tls: Some(paths(pki, with_client_ca)),
        ..ServerConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Server-authenticated TLS
// ---------------------------------------------------------------------------

/// TLS works, and the client verifies the server against the private CA.
#[tokio::test]
async fn tls_serves_a_client_that_trusts_the_ca() {
    let pki = build_pki();
    let (auth, keys) = api_key_auth(&["alice"], None);
    let (url, state) = spawn_tls(tls_config(&pki, AuthMode::ApiKey, false), auth).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let resp = client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .bearer_auth(&keys[0])
        .body(generators_body(8, 1))
        .send()
        .await
        .expect("TLS request failed");

    assert!(resp.status().is_success(), "status {}", resp.status());
    assert_eq!(state.sessions.count_for("alice"), 1);
}

/// A client that does not trust the CA must refuse to connect.
///
/// If this ever passes, certificate verification is not happening.
#[tokio::test]
async fn tls_rejects_a_client_that_does_not_trust_the_ca() {
    let pki = build_pki();
    let (auth, keys) = api_key_auth(&["alice"], None);
    let (url, _state) = spawn_tls(tls_config(&pki, AuthMode::ApiKey, false), auth).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let err = client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .bearer_auth(&keys[0])
        .body(generators_body(8, 2))
        .send()
        .await
        .expect_err("an untrusted server certificate must not be accepted");
    assert!(
        err.is_connect() || err.is_request(),
        "unexpected error: {err}"
    );
}

/// The high-level client reaches a TLS server when given the CA.
#[tokio::test]
async fn the_emsm_client_speaks_tls() {
    let pki = build_pki();
    let (auth, keys) = api_key_auth(&["alice"], None);
    let (url, state) = spawn_tls(tls_config(&pki, AuthMode::ApiKey, false), auth).await;

    let mut client = EmsmClient::builder(&url)
        .api_key(keys[0].clone())
        .root_certificate_pem(pki.ca_pem.as_bytes().to_vec())
        .request_timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let g1: Vec<G1Affine> = Vec::new();
    let g2: Vec<G2Affine> = Vec::new();
    let request = SetupRequest::encode(&g1, &g1, &g1, &g1, &g2).unwrap();
    client.send_setup(&request).await.expect("setup over TLS");

    assert!(client.has_session());
    assert_eq!(state.sessions.count_for("alice"), 1);
}

// ---------------------------------------------------------------------------
// Mutual TLS
// ---------------------------------------------------------------------------

/// A registered client certificate authenticates with no API key at all.
#[tokio::test]
async fn mtls_authenticates_a_registered_certificate() {
    let pki = build_pki();
    let auth = cert_auth(&pki.client_cert_digest, "cert-client", AuthMode::MutualTls);
    let (url, state) = spawn_tls(tls_config(&pki, AuthMode::MutualTls, true), auth).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .identity(reqwest::Identity::from_pem(pki.client_identity_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let resp = client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(generators_body(8, 3))
        .send()
        .await
        .expect("mTLS request failed");

    assert!(resp.status().is_success(), "status {}", resp.status());
    // The identity came from the handshake, not from a header.
    assert_eq!(state.sessions.count_for("cert-client"), 1);
}

/// A certificate the CA signed but the service does not know is refused.
///
/// Chain validity is necessary but not sufficient: the CA decides who may
/// connect, and this service decides who is a principal.
#[tokio::test]
async fn mtls_refuses_an_unregistered_certificate() {
    let pki = build_pki();
    let auth = cert_auth(&pki.client_cert_digest, "cert-client", AuthMode::MutualTls);
    let (url, state) = spawn_tls(tls_config(&pki, AuthMode::MutualTls, true), auth).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .identity(reqwest::Identity::from_pem(pki.stranger_identity_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let resp = client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(generators_body(8, 4))
        .send()
        .await
        .expect("the handshake itself should succeed");

    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(state.sessions.len(), 0);
}

/// Under mTLS-only, a client with no certificate cannot complete a handshake.
#[tokio::test]
async fn mtls_requires_a_certificate() {
    let pki = build_pki();
    let auth = cert_auth(&pki.client_cert_digest, "cert-client", AuthMode::MutualTls);
    let (url, _state) = spawn_tls(tls_config(&pki, AuthMode::MutualTls, true), auth).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // rustls demands a certificate, so this fails during the handshake rather
    // than reaching any handler.
    let result = client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(generators_body(8, 5))
        .send()
        .await;
    assert!(
        result.is_err(),
        "a certificate-less client must not be served under mTLS"
    );
}

/// `Any` accepts either credential on the same port.
///
/// The certificate is requested but optional, so an API-key client still works.
#[tokio::test]
async fn any_mode_accepts_a_certificate_or_a_key() {
    let pki = build_pki();

    // One principal per credential kind.
    let generated = generate_api_key();
    let spec = AuthFile {
        tiers: roomy_tier(),
        principals: vec![
            PrincipalSpec {
                id: "cert-client".to_string(),
                tier: Some("roomy".to_string()),
                api_key_id: None,
                api_key_sha256: None,
                tls_cert_sha256: Some(pki.client_cert_digest.clone()),
            },
            PrincipalSpec {
                id: "key-client".to_string(),
                tier: Some("roomy".to_string()),
                api_key_id: Some(generated.key_id.clone()),
                api_key_sha256: Some(generated.sha256.clone()),
                tls_cert_sha256: None,
            },
        ],
    };
    let auth = AuthStore::from_spec(spec, AuthMode::Any).unwrap();
    let (url, state) = spawn_tls(tls_config(&pki, AuthMode::Any, true), auth).await;

    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();

    // With a certificate.
    let cert_client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca.clone())
        .identity(reqwest::Identity::from_pem(pki.client_identity_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let resp = cert_client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(generators_body(8, 6))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "cert client: {}", resp.status());

    // With an API key and no certificate. The handshake must still succeed,
    // which is why `Any` requests a certificate without requiring one.
    let key_client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let resp = key_client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .bearer_auth(&generated.key)
        .body(generators_body(8, 7))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "key client: {}", resp.status());

    assert_eq!(state.sessions.count_for("cert-client"), 1);
    assert_eq!(state.sessions.count_for("key-client"), 1);
}

/// A certificate-authenticated principal cannot use another's session token.
///
/// The ownership rule is independent of how identity was established.
#[tokio::test]
async fn mtls_identity_is_bound_to_its_sessions() {
    let pki = build_pki();
    let generated = generate_api_key();
    let spec = AuthFile {
        tiers: roomy_tier(),
        principals: vec![
            PrincipalSpec {
                id: "cert-client".to_string(),
                tier: Some("roomy".to_string()),
                api_key_id: None,
                api_key_sha256: None,
                tls_cert_sha256: Some(pki.client_cert_digest.clone()),
            },
            PrincipalSpec {
                id: "key-client".to_string(),
                tier: Some("roomy".to_string()),
                api_key_id: Some(generated.key_id.clone()),
                api_key_sha256: Some(generated.sha256.clone()),
                tls_cert_sha256: None,
            },
        ],
    };
    let auth = AuthStore::from_spec(spec, AuthMode::Any).unwrap();
    let (url, _state) = spawn_tls(tls_config(&pki, AuthMode::Any, true), auth).await;
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();

    // The certificate client opens a session.
    let cert_client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca.clone())
        .identity(reqwest::Identity::from_pem(pki.client_identity_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let resp = cert_client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(generators_body(8, 8))
        .send()
        .await
        .unwrap();
    let issued: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();

    // The key client presents that token.
    let key_client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let resp = key_client
        .post(format!("{url}/v1/prove"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .header(SESSION_HEADER, &issued.session_token)
        .bearer_auth(&generated.key)
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn api_key_auth(ids: &[&str], tier: Option<&str>) -> (AuthStore, Vec<String>) {
    let tier = tier.unwrap_or("roomy");
    let mut keys = Vec::new();
    let mut principals = Vec::new();
    for id in ids {
        let g = generate_api_key();
        principals.push(PrincipalSpec {
            id: (*id).to_string(),
            tier: Some(tier.to_string()),
            api_key_id: Some(g.key_id.clone()),
            api_key_sha256: Some(g.sha256.clone()),
            tls_cert_sha256: None,
        });
        keys.push(g.key);
    }
    let store = AuthStore::from_spec(
        AuthFile {
            tiers: roomy_tier(),
            principals,
        },
        AuthMode::ApiKey,
    )
    .unwrap();
    (store, keys)
}

fn cert_auth(digest: &str, id: &str, mode: AuthMode) -> AuthStore {
    AuthStore::from_spec(
        AuthFile {
            tiers: roomy_tier(),
            principals: vec![PrincipalSpec {
                id: id.to_string(),
                tier: Some("roomy".to_string()),
                api_key_id: None,
                api_key_sha256: None,
                tls_cert_sha256: Some(digest.to_string()),
            }],
        },
        mode,
    )
    .unwrap()
}
