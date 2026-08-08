//! Client authentication and per-principal quota, end to end over HTTP.
//!
//! The unit tests in `protocol::auth` and `protocol::quota` check the rules in
//! isolation. These check that the rules are actually *wired in*: a route that
//! skipped the middleware, or a handler that forgot to charge quota, passes every
//! unit test and fails here.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use ark_bn254::{G1Affine, G1Projective as G1, G2Affine};
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use common::{auth_store_with_keys, error_code, raw, spawn_admin, spawn_with_auth, tier};
use stealthsnark::protocol::auth::{AuthMode, AuthStore};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::messages::*;

fn generators_body(n: usize, seed: u64) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let g1: Vec<G1Affine> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let g2: Vec<G2Affine> = Vec::new();
    let req = SetupRequest::encode(&g1, &g1, &g1, &g1, &g2).unwrap();
    bincode::serialize(&req).unwrap()
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap()
}

/// Generous quota, so a test measuring something else is never rate-limited.
fn roomy() -> HashMap<String, stealthsnark::protocol::auth::TierSpec> {
    tier("roomy", 32, 64 * 1024 * 1024, 1000.0, 1000)
}

async fn setup_as(url: &str, key: Option<&str>, body: Vec<u8>) -> reqwest::Response {
    raw(
        &http(),
        reqwest::Method::POST,
        format!("{url}/v1/setup"),
        key,
        None,
    )
    .body(body)
    .send()
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Every data-plane route requires a credential. A route added outside the
/// authenticate layer would pass unit tests and fail here.
#[tokio::test]
async fn every_data_plane_route_requires_a_credential() {
    let (auth, _keys) = auth_store_with_keys(&["alice"], Some("roomy"), roomy(), AuthMode::ApiKey);
    let (url, _state) = spawn_with_auth(ServerConfig::default(), auth).await;

    let routes = [
        (reqwest::Method::POST, "/v1/setup"),
        (reqwest::Method::POST, "/v1/prove"),
        (reqwest::Method::DELETE, "/v1/session"),
    ];

    for (method, path) in routes {
        let resp = raw(&http(), method.clone(), format!("{url}{path}"), None, None)
            .body(Vec::new())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            401,
            "{method} {path} served without a credential"
        );
        // RFC 9110 requires a challenge on a 401, and it tells the client which
        // credential to present rather than making it guess.
        assert!(
            resp.headers().contains_key("www-authenticate"),
            "{method} {path} 401 carried no WWW-Authenticate"
        );
        assert_eq!(error_code(resp).await, "unauthenticated");
    }
}

/// A valid key works; a wrong or malformed one does not, and neither says why.
#[tokio::test]
async fn api_keys_are_verified() {
    let (auth, keys) = auth_store_with_keys(&["alice"], Some("roomy"), roomy(), AuthMode::ApiKey);
    let (url, state) = spawn_with_auth(ServerConfig::default(), auth).await;
    let good = &keys[0].key;

    let resp = setup_as(&url, Some(good), generators_body(8, 1)).await;
    assert!(resp.status().is_success(), "valid key refused");
    assert_eq!(state.sessions.len(), 1);

    // Same key id, tampered secret.
    let mut chars: Vec<char> = good.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    let tampered: String = chars.into_iter().collect();

    for bad in [
        tampered.as_str(),
        "ssk_0000000000000000_0000000000000000000000000000000000000000000000000000000000000000",
        "not-a-key",
        "",
    ] {
        let resp = setup_as(&url, Some(bad), generators_body(8, 2)).await;
        assert_eq!(resp.status().as_u16(), 401, "accepted key {bad:?}");
        assert_eq!(error_code(resp).await, "unauthenticated");
    }
    assert_eq!(state.sessions.len(), 1, "a refused key created a session");
}

/// A session token is bound to the principal that created it.
///
/// This is the property the two-header split exists for: even with the exact
/// token, another client cannot use it.
#[tokio::test]
async fn a_session_token_is_useless_to_another_principal() {
    let (auth, keys) =
        auth_store_with_keys(&["alice", "bob"], Some("roomy"), roomy(), AuthMode::ApiKey);
    let (url, state) = spawn_with_auth(ServerConfig::default(), auth).await;
    let (alice, bob) = (&keys[0].key, &keys[1].key);

    let resp = setup_as(&url, Some(alice), generators_body(8, 3)).await;
    let issued: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();

    // Bob authenticates correctly but presents Alice's session token.
    let resp = raw(
        &http(),
        reqwest::Method::POST,
        format!("{url}/v1/prove"),
        Some(bob),
        Some(&issued.session_token),
    )
    .body(Vec::new())
    .send()
    .await
    .unwrap();

    // 403, not 401: Bob's credential is valid, it just does not reach this
    // session. Retrying as Bob can never succeed.
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(error_code(resp).await, "forbidden");

    // Bob cannot delete it either.
    let resp = raw(
        &http(),
        reqwest::Method::DELETE,
        format!("{url}/v1/session"),
        Some(bob),
        Some(&issued.session_token),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(
        state.sessions.len(),
        1,
        "a forbidden release deleted the session"
    );

    // Alice still owns it.
    let resp = raw(
        &http(),
        reqwest::Method::DELETE,
        format!("{url}/v1/session"),
        Some(alice),
        Some(&issued.session_token),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    assert_eq!(state.sessions.len(), 0);
}

/// With auth disabled every caller is `anonymous`, and no credential is needed.
#[tokio::test]
async fn disabled_auth_still_serves_loopback_development() {
    let (url, state) = spawn_with_auth(ServerConfig::default(), AuthStore::disabled()).await;

    let resp = setup_as(&url, None, generators_body(8, 4)).await;
    assert!(resp.status().is_success());
    assert_eq!(state.sessions.count_for("anonymous"), 1);
}

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

/// A principal's request rate is capped, and the refusal carries `Retry-After`.
#[tokio::test]
async fn rate_limit_is_enforced_per_principal() {
    // Burst of 2 and a very slow refill, so the third request must be refused.
    let (auth, keys) = auth_store_with_keys(
        &["alice", "bob"],
        Some("slow"),
        tier("slow", 32, 64 * 1024 * 1024, 0.01, 2),
        AuthMode::ApiKey,
    );
    let (url, state) = spawn_with_auth(ServerConfig::default(), auth).await;
    let (alice, bob) = (&keys[0].key, &keys[1].key);

    for i in 0..2 {
        let resp = setup_as(&url, Some(alice), generators_body(4, 10 + i)).await;
        assert!(resp.status().is_success(), "burst request {i} refused");
    }

    let resp = setup_as(&url, Some(alice), generators_body(4, 99)).await;
    assert_eq!(resp.status().as_u16(), 429);
    assert!(
        resp.headers().contains_key("retry-after"),
        "a rate-limited client must be told when to return"
    );
    assert_eq!(error_code(resp).await, "rate_limited");

    // Bob is unaffected: one noisy client must degrade only itself.
    let resp = setup_as(&url, Some(bob), generators_body(4, 20)).await;
    assert!(resp.status().is_success(), "bob paid for alice's traffic");

    let admin_url = spawn_admin(state).await;
    let metrics = http()
        .get(format!("{admin_url}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("stealthsnark_rejected_rate_limited_total 1"),
        "{metrics}"
    );
}

/// A principal may hold only its tier's number of sessions.
#[tokio::test]
async fn session_quota_is_enforced_per_principal() {
    let (auth, keys) = auth_store_with_keys(
        &["alice", "bob"],
        Some("two"),
        tier("two", 2, 64 * 1024 * 1024, 1000.0, 1000),
        AuthMode::ApiKey,
    );
    let (url, state) = spawn_with_auth(ServerConfig::default(), auth).await;
    let (alice, bob) = (&keys[0].key, &keys[1].key);

    let mut tokens = Vec::new();
    for i in 0..2 {
        let resp = setup_as(&url, Some(alice), generators_body(4, 30 + i)).await;
        assert!(resp.status().is_success());
        let issued: SetupResponse = bincode::deserialize(&resp.bytes().await.unwrap()).unwrap();
        tokens.push(issued.session_token);
    }

    let resp = setup_as(&url, Some(alice), generators_body(4, 40)).await;
    assert_eq!(resp.status().as_u16(), 429);
    assert_eq!(error_code(resp).await, "session_quota_exceeded");
    assert_eq!(state.sessions.count_for("alice"), 2);

    // Bob has his own allowance.
    let resp = setup_as(&url, Some(bob), generators_body(4, 50)).await;
    assert!(resp.status().is_success());

    // Releasing one frees the allowance again, so the quota is not a lifetime cap.
    let resp = raw(
        &http(),
        reqwest::Method::DELETE,
        format!("{url}/v1/session"),
        Some(alice),
        Some(&tokens[0]),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 204);

    let resp = setup_as(&url, Some(alice), generators_body(4, 60)).await;
    assert!(
        resp.status().is_success(),
        "freeing a session must restore the allowance"
    );
}

/// A tier's body limit is applied before the body is read.
#[tokio::test]
async fn body_size_quota_is_enforced_per_tier() {
    let (auth, keys) = auth_store_with_keys(
        &["alice"],
        Some("tiny"),
        tier("tiny", 4, 4096, 1000.0, 1000),
        AuthMode::ApiKey,
    );
    let (url, state) = spawn_with_auth(ServerConfig::default(), auth).await;
    let key = &keys[0].key;

    // Comfortably under 4096 bytes.
    let small = generators_body(8, 70);
    assert!(small.len() < 4096, "fixture is not small enough");
    assert!(setup_as(&url, Some(key), small).await.status().is_success());

    // Well over the tier limit, but far under the server-wide transport limit,
    // so only the per-principal check can reject it.
    let big = generators_body(2000, 71);
    assert!(big.len() > 4096);
    let resp = setup_as(&url, Some(key), big).await;
    assert_eq!(resp.status().as_u16(), 413);
    assert_eq!(error_code(resp).await, "body_too_large");

    assert_eq!(state.sessions.count_for("alice"), 1);
}

/// An unauthenticated flood must not consume a real principal's rate allowance.
///
/// Order of checks matters: authenticate first, then charge quota.
#[tokio::test]
async fn unauthenticated_traffic_does_not_spend_a_principals_allowance() {
    let (auth, keys) = auth_store_with_keys(
        &["alice"],
        Some("slow"),
        tier("slow", 32, 64 * 1024 * 1024, 0.01, 2),
        AuthMode::ApiKey,
    );
    let (url, _state) = spawn_with_auth(ServerConfig::default(), auth).await;
    let key = &keys[0].key;

    // Twenty refused requests, ten times Alice's whole burst.
    for _ in 0..20 {
        let resp = setup_as(
            &url,
            Some("ssk_deadbeefdeadbeef_00"),
            generators_body(4, 80),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 401);
    }

    // Alice's burst must be untouched.
    for i in 0..2 {
        let resp = setup_as(&url, Some(key), generators_body(4, 90 + i)).await;
        assert!(
            resp.status().is_success(),
            "unauthenticated traffic consumed alice's allowance"
        );
    }
}

/// The full client flow works against an authenticated server.
#[tokio::test]
async fn the_client_completes_a_session_with_an_api_key() {
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::r1cs_to_qap::LibsnarkReduction;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use common::{decode_response, prove_request, setup_request};
    use stealthsnark::groth16::circuit::CubeCircuit;
    use stealthsnark::groth16::server_aided::{
        client_decrypt, client_encrypt, ServerAidedProvingKey,
    };

    let (auth, keys) = auth_store_with_keys(&["alice"], Some("roomy"), roomy(), AuthMode::ApiKey);
    let (url, state) = spawn_with_auth(ServerConfig::default(), auth).await;

    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let mut client = EmsmClient::builder(&url)
        .api_key(keys[0].key.clone())
        .build()
        .unwrap();

    client.send_setup(&setup_request(&sapk)).await.unwrap();
    assert_eq!(state.sessions.count_for("alice"), 1);

    let circuit = CubeCircuit {
        x: Some(Fr::from(3u64)),
    };
    let (req, enc_state) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();
    let resp = client.send_prove(&prove_request(&req)).await.unwrap();

    let proof = client_decrypt(&sapk, &decode_response(&resp), &enc_state);
    assert!(Groth16::<Bn254>::verify(&vk, &[Fr::from(35u64)], &proof).unwrap());

    client.release().await.unwrap();
    assert_eq!(state.sessions.count_for("alice"), 0);
}

/// A client with no key gets a clear error against an authenticated server,
/// rather than a confusing failure deep in the flow.
#[tokio::test]
async fn a_client_without_a_key_is_refused_clearly() {
    use common::setup_request;
    use stealthsnark::groth16::circuit::CubeCircuit;
    use stealthsnark::groth16::server_aided::ServerAidedProvingKey;

    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    let (auth, _keys) = auth_store_with_keys(&["alice"], Some("roomy"), roomy(), AuthMode::ApiKey);
    let (url, _state) = spawn_with_auth(ServerConfig::default(), auth).await;

    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (pk, _vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let mut client = EmsmClient::new(&url).unwrap();
    let err = client
        .send_setup(&setup_request(&sapk))
        .await
        .expect_err("an unauthenticated client must be refused");

    let text = err.to_string();
    assert!(text.contains("401"), "got: {text}");
    assert!(text.contains("unauthenticated"), "got: {text}");
}
