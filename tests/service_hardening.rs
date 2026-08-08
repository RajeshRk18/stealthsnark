//! Service-layer hardening suite.
//!
//! The cryptographic suites (`differential`, `privacy`, `malicious_soundness`)
//! all exercise tiny circuits, which is how a hard functional ceiling in the
//! transport went unnoticed: axum's default 2 MiB body limit rejected any circuit
//! needing more than roughly 16k generators per MSM — that is, every circuit
//! worth outsourcing. Each test here pins one service property that no
//! cryptographic test can see.

mod common;

use std::time::Duration;

use ark_bn254::{G1Affine, G1Projective as G1, G2Affine};
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use common::{error_code, raw, spawn_admin, spawn_server, spawn_server_with};
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::messages::*;

/// Byte size of a generator payload with `n` G1 points per set (4 sets) plus a
/// G2 set, which is what `/v1/setup` uploads.
fn generators_body(n: usize, seed: u64) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let g1: Vec<G1Affine> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let g2: Vec<G2Affine> = Vec::new();
    let req = SetupRequest::encode(&g1, &g1, &g1, &g1, &g2).unwrap();
    bincode::serialize(&req).unwrap()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap()
}

async fn post_setup(url: &str, body: Vec<u8>, version: Option<&str>) -> reqwest::Response {
    let mut req = client().post(format!("{url}/v1/setup")).body(body);
    if let Some(v) = version {
        req = req.header(VERSION_HEADER, v);
    }
    req.send().await.unwrap()
}

// ---------------------------------------------------------------------------
// The functional ceiling
// ---------------------------------------------------------------------------

/// Regression guard for the 2 MiB default body limit.
///
/// 20,000 generators per set produced a ~2.44 MiB body, which the old server
/// rejected with 413. Anything at or beyond this size must now succeed.
#[tokio::test]
async fn setup_accepts_payload_above_the_old_2mib_ceiling() {
    let (url, state) = spawn_server().await;

    let body = generators_body(20_000, 1);
    assert!(
        body.len() > 2 * 1024 * 1024,
        "test is not exercising the old ceiling: body is only {} bytes",
        body.len()
    );

    let resp = post_setup(&url, body, Some(&PROTOCOL_VERSION.to_string())).await;
    assert!(
        resp.status().is_success(),
        "a {:.2} MiB generator upload must be accepted, got {}",
        2.44,
        resp.status()
    );
    assert_eq!(state.sessions.len(), 1);
}

/// The limit is configurable, and exceeding it is a clean 413 rather than a hang
/// or a truncated read.
#[tokio::test]
async fn setup_rejects_payload_above_configured_limit() {
    let cfg = ServerConfig {
        max_body_bytes: 64 * 1024,
        ..ServerConfig::default()
    };
    let (url, state) = spawn_server_with(cfg).await;

    let resp = post_setup(
        &url,
        generators_body(20_000, 2),
        Some(&PROTOCOL_VERSION.to_string()),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 413);
    assert_eq!(state.sessions.len(), 0);
}

// ---------------------------------------------------------------------------
// Session credentials
// ---------------------------------------------------------------------------

/// A client cannot act on a session it was not issued. This is the property the
/// old client-chosen `session_id` lacked: a second `/setup` reusing an id
/// silently replaced the first client's generators.
#[tokio::test]
async fn forged_and_missing_tokens_are_refused() {
    let (url, _state) = spawn_server().await;

    let prove_body = bincode::serialize(&ProveRequest {
        v_h: ark_vec_to_bytes::<ark_bn254::Fr>(&[]).unwrap(),
        v_l: ark_vec_to_bytes::<ark_bn254::Fr>(&[]).unwrap(),
        v_a: ark_vec_to_bytes::<ark_bn254::Fr>(&[]).unwrap(),
        v_b_g1: ark_vec_to_bytes::<ark_bn254::Fr>(&[]).unwrap(),
        v_b_g2: ark_vec_to_bytes::<ark_bn254::Fr>(&[]).unwrap(),
    })
    .unwrap();

    // No Authorization header at all.
    let resp = client()
        .post(format!("{url}/v1/prove"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(prove_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(error_code(resp).await, "missing_token");

    // A well-formed but never-issued token.
    let resp = client()
        .post(format!("{url}/v1/prove"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .header(SESSION_HEADER, "f".repeat(64))
        .body(prove_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(error_code(resp).await, "unknown_session");
}

/// Two setups yield two independent tokens; neither replaces the other.
#[tokio::test]
async fn concurrent_setups_do_not_clobber_each_other() {
    let (url, state) = spawn_server().await;

    let mut tokens = Vec::new();
    for seed in 0..3u64 {
        let resp = post_setup(
            &url,
            generators_body(8, seed),
            Some(&PROTOCOL_VERSION.to_string()),
        )
        .await;
        assert!(resp.status().is_success());
        let parsed: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();
        assert_eq!(parsed.session_token.len(), 64, "expected 256 bits of hex");
        tokens.push(parsed.session_token);
    }

    assert_eq!(
        state.sessions.len(),
        3,
        "a setup replaced an existing session"
    );
    tokens.sort();
    let unique = {
        let mut t = tokens.clone();
        t.dedup();
        t.len()
    };
    assert_eq!(unique, 3, "duplicate session tokens issued");
}

/// A session past its idle TTL stops resolving, and sweeping frees its memory.
#[tokio::test]
async fn expired_sessions_are_refused_and_freed() {
    let cfg = ServerConfig {
        session_ttl: Duration::from_millis(50),
        ..ServerConfig::default()
    };
    let (url, state) = spawn_server_with(cfg).await;

    let resp = post_setup(
        &url,
        generators_body(8, 7),
        Some(&PROTOCOL_VERSION.to_string()),
    )
    .await;
    let parsed: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();
    assert!(state.sessions.get(&parsed.session_token).is_some());

    tokio::time::sleep(Duration::from_millis(120)).await;

    assert!(
        state.sessions.get(&parsed.session_token).is_none(),
        "an expired session must not resolve"
    );
    assert_eq!(
        state.sessions.sweep(),
        1,
        "expired session was not reclaimed"
    );
    assert_eq!(state.sessions.resident_bytes(), 0);
}

/// The session cap is enforced, and refusal is a distinct, retryable status.
#[tokio::test]
async fn session_cap_is_enforced() {
    let cfg = ServerConfig {
        max_sessions: 2,
        ..ServerConfig::default()
    };
    let (url, state) = spawn_server_with(cfg).await;

    for seed in 0..2u64 {
        assert!(post_setup(
            &url,
            generators_body(4, seed),
            Some(&PROTOCOL_VERSION.to_string())
        )
        .await
        .status()
        .is_success());
    }

    let resp = post_setup(
        &url,
        generators_body(4, 99),
        Some(&PROTOCOL_VERSION.to_string()),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 429);
    assert!(
        resp.headers().contains_key("retry-after"),
        "a retryable refusal should tell the client when to come back"
    );
    assert_eq!(error_code(resp).await, "session_limit");
    assert_eq!(state.sessions.len(), 2);
}

// ---------------------------------------------------------------------------
// Protocol versioning and error reporting
// ---------------------------------------------------------------------------

/// bincode is not self-describing, so a shape change would otherwise decode as
/// garbage rather than failing. The version header turns that into a clean 400.
#[tokio::test]
async fn version_header_is_required_and_enforced() {
    let (url, _state) = spawn_server().await;

    for version in [None, Some("0"), Some("1"), Some("99"), Some("banana")] {
        let resp = post_setup(&url, generators_body(4, 11), version).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "version {version:?} should have been rejected"
        );
        assert_eq!(error_code(resp).await, "unsupported_version");
    }
}

/// Distinct failures must be distinguishable. Previously every one of these
/// returned a bare 400 with no body.
#[tokio::test]
async fn failure_modes_are_distinguishable() {
    let (url, _state) = spawn_server().await;

    // Corrupt bincode framing.
    let resp = post_setup(&url, vec![0xff; 64], Some(&PROTOCOL_VERSION.to_string())).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(error_code(resp).await, "malformed_body");

    // Valid framing, but the point blobs are not decodable curve points.
    let bad_points = bincode::serialize(&SetupRequest {
        h_generators: vec![0xAA; 128],
        l_generators: vec![0xAA; 128],
        a_generators: vec![0xAA; 128],
        b_g1_generators: vec![0xAA; 128],
        b_g2_generators: vec![0xAA; 128],
    })
    .unwrap();
    let resp = post_setup(&url, bad_points, Some(&PROTOCOL_VERSION.to_string())).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(error_code(resp).await, "invalid_input");
}

/// A scalar/generator length mismatch is a client error with a specific code,
/// and it must not take the session or the process down.
#[tokio::test]
async fn length_mismatch_is_reported_as_invalid_input() {
    let (url, state) = spawn_server().await;

    let resp = post_setup(
        &url,
        generators_body(8, 21),
        Some(&PROTOCOL_VERSION.to_string()),
    )
    .await;
    let parsed: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();

    // 8 generators were registered; send 3 scalars.
    let scalars: Vec<ark_bn254::Fr> = (0..3).map(ark_bn254::Fr::from).collect();
    let empty = ark_vec_to_bytes::<ark_bn254::Fr>(&[]).unwrap();
    let body = bincode::serialize(&ProveRequest {
        v_h: ark_vec_to_bytes(&scalars).unwrap(),
        v_l: empty.clone(),
        v_a: empty.clone(),
        v_b_g1: empty.clone(),
        v_b_g2: empty,
    })
    .unwrap();

    let resp = client()
        .post(format!("{url}/v1/prove"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .header(SESSION_HEADER, &parsed.session_token)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(error_code(resp).await, "invalid_input");

    // The session survives a bad request.
    assert!(state.sessions.get(&parsed.session_token).is_some());
}

/// Releasing a session frees it immediately and invalidates the token.
#[tokio::test]
async fn release_frees_the_session_and_invalidates_the_token() {
    let (url, state) = spawn_server().await;

    let resp = post_setup(
        &url,
        generators_body(16, 33),
        Some(&PROTOCOL_VERSION.to_string()),
    )
    .await;
    let parsed: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();
    assert!(state.sessions.resident_bytes() > 0);

    let resp = client()
        .delete(format!("{url}/v1/session"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .header(SESSION_HEADER, &parsed.session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    assert_eq!(state.sessions.len(), 0);
    assert_eq!(state.sessions.resident_bytes(), 0);

    // Double release is refused rather than silently accepted.
    let resp = client()
        .delete(format!("{url}/v1/session"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .header(SESSION_HEADER, &parsed.session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// Operability
// ---------------------------------------------------------------------------

/// Health endpoints live on the admin plane, answer without a credential, and
/// need no version header — a probe must not have to know the protocol.
///
/// They are deliberately absent from the data plane: that port requires a
/// credential, and a probe that had to authenticate would be one more thing to
/// get wrong during an incident.
#[tokio::test]
async fn health_endpoints_are_on_the_admin_plane_only() {
    let (data_url, state) = spawn_server().await;
    let admin_url = spawn_admin(state).await;

    for path in ["/livez", "/readyz"] {
        let resp = client()
            .get(format!("{admin_url}{path}"))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "admin {path} returned {}",
            resp.status()
        );

        // Not routable on the data plane, so scrape traffic and client traffic
        // cannot be confused for one another. The version header is supplied so
        // that a 404 proves the route is absent, rather than the middleware
        // having refused the request before routing.
        let resp = raw(
            &client(),
            reqwest::Method::GET,
            format!("{data_url}{path}"),
            None,
            None,
        )
        .send()
        .await
        .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "data plane must not serve {path}"
        );
    }
}

/// `/metrics` is admin-plane only. Exposing it on the data port would publish
/// internal state to every client that can reach the service.
#[tokio::test]
async fn metrics_are_not_exposed_on_the_data_plane() {
    let (data_url, state) = spawn_server().await;
    let admin_url = spawn_admin(state).await;

    let resp = raw(
        &client(),
        reqwest::Method::GET,
        format!("{data_url}/metrics"),
        None,
        None,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    // Without a version header the middleware refuses before routing, so an
    // unauthenticated caller cannot even enumerate which paths exist.
    let probe = client()
        .get(format!("{data_url}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(
        probe.status().is_client_error() && probe.status().as_u16() != 404,
        "path existence must not leak to an unversioned caller, got {}",
        probe.status()
    );

    let resp = client()
        .get(format!("{admin_url}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

/// `/metrics` reflects real traffic, including the cheating-server counter that
/// previously existed only as a client-side `Result`.
#[tokio::test]
async fn metrics_reflect_traffic() {
    let (data_url, state) = spawn_server().await;
    let admin_url = spawn_admin(state).await;

    let scrape = |url: String| async move {
        client()
            .get(format!("{url}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    };

    let before = scrape(admin_url.clone()).await;
    assert!(before.contains("stealthsnark_setup_requests_ok_total 0"));
    assert!(before.contains("stealthsnark_active_sessions 0"));
    assert!(
        before.contains("stealthsnark_consistency_check_failures_total 0"),
        "the cheating-server counter must be exported"
    );

    let version = PROTOCOL_VERSION.to_string();
    post_setup(&data_url, generators_body(8, 55), Some(&version)).await;
    // One refused request, to prove rejections are counted separately.
    post_setup(&data_url, vec![0xff; 32], Some(&version)).await;

    let after = scrape(admin_url).await;
    assert!(
        after.contains("stealthsnark_setup_requests_ok_total 1"),
        "{after}"
    );
    assert!(
        after.contains("stealthsnark_setup_requests_err_total 1"),
        "{after}"
    );
    assert!(after.contains("stealthsnark_active_sessions 1"), "{after}");
}
