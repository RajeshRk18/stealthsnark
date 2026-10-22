//! Server throughput over the HTTP path.
//!
//! Run: `cargo bench --bench throughput`

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ark_bn254::{Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use axum::body::Bytes;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::emsm::pedersen::Pedersen;
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::messages::*;
use stealthsnark::protocol::server::{create_router, AppState};

struct Fixture {
    n: usize,
    setup_body: Vec<u8>,
    prove_body: Bytes,
    expected: (G1, G1, G1, G1, G2),
}


fn fixture(n: usize, seed: u64) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let g1 = |rng: &mut ChaCha20Rng| -> Vec<G1Affine> {
        (0..n).map(|_| G1::rand(rng).into_affine()).collect()
    };
    let scalars = |rng: &mut ChaCha20Rng| -> Vec<Fr> { (0..n).map(|_| Fr::rand(rng)).collect() };

    let (gh, gl, ga, gb1) = (g1(&mut rng), g1(&mut rng), g1(&mut rng), g1(&mut rng));
    let gb2: Vec<G2Affine> = (0..n).map(|_| G2::rand(&mut rng).into_affine()).collect();

    let (vh, vl, va, vb1, vb2) = (
        scalars(&mut rng),
        scalars(&mut rng),
        scalars(&mut rng),
        scalars(&mut rng),
        scalars(&mut rng),
    );

    let expected = (
        Pedersen::<G1>::from_generators(gh.clone()).commit(&vh).unwrap(),
        Pedersen::<G1>::from_generators(gl.clone()).commit(&vl).unwrap(),
        Pedersen::<G1>::from_generators(ga.clone()).commit(&va).unwrap(),
        Pedersen::<G1>::from_generators(gb1.clone()).commit(&vb1).unwrap(),
        Pedersen::<G2>::from_generators(gb2.clone()).commit(&vb2).unwrap(),
    );

    let setup_body =
        stealthsnark::protocol::messages::wire_encode(&SetupRequest::encode(&gh, &gl, &ga, &gb1, &gb2).unwrap()).unwrap();
    let prove_body = Bytes::from(
        stealthsnark::protocol::messages::wire_encode(&ProveRequest::encode(&vh, &vl, &va, &vb1, &vb2).unwrap()).unwrap(),
    );

    Fixture { n, setup_body, prove_body, expected }
}

async fn spawn(cfg: ServerConfig) -> (String, AppState) {
    let state = AppState::new(cfg);
    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), state)
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .pool_max_idle_per_host(64)
        .build()
        .unwrap()
}

/// One measurement: warm a session, verify, then drive `workers * per_worker` proves.
struct Run {
    label: String,
    n: usize,
    workers: usize,
    requests: usize,
    elapsed: Duration,
    latencies: Vec<Duration>,
    non_200: usize,
    server_mean: Duration,
}

async fn measure(label: &str, fx: &Fixture, cfg: ServerConfig, workers: usize, per_worker: usize) -> Run {
    let (url, state) = spawn(cfg).await;
    let client = http();

    let resp = client
        .post(format!("{url}/v1/setup"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .body(fx.setup_body.clone())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "setup failed: {}", resp.status());
    let setup: SetupResponse = stealthsnark::protocol::messages::wire_decode(&resp.bytes().await.unwrap()).unwrap();
    let token = Arc::new(setup.session_token);

    let probe = client
        .post(format!("{url}/v1/prove"))
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
        .header(SESSION_HEADER, token.as_str())
        .body(fx.prove_body.clone())
        .send()
        .await
        .unwrap();
    assert!(probe.status().is_success(), "prove failed: {}", probe.status());
    let pr: ProveResponse = stealthsnark::protocol::messages::wire_decode(&probe.bytes().await.unwrap()).unwrap();
    let got = (
        G1::from(ark_from_bytes::<G1Affine>(&pr.em_h).unwrap()),
        G1::from(ark_from_bytes::<G1Affine>(&pr.em_l).unwrap()),
        G1::from(ark_from_bytes::<G1Affine>(&pr.em_a).unwrap()),
        G1::from(ark_from_bytes::<G1Affine>(&pr.em_b_g1).unwrap()),
        G2::from(ark_from_bytes::<G2Affine>(&pr.em_b_g2).unwrap()),
    );
    assert_eq!(got, fx.expected, "server result differs from a local MSM; it did not do the work");

    let before_ok = state.metrics.prove_ok.load(Ordering::Relaxed);
    let before_micros = state.metrics.prove_micros_total.load(Ordering::Relaxed);

    let started = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (client, url, token, body) =
            (client.clone(), url.clone(), token.clone(), fx.prove_body.clone());
        handles.push(tokio::spawn(async move {
            let mut out = Vec::with_capacity(per_worker);
            for _ in 0..per_worker {
                let t = Instant::now();
                let r = client
                    .post(format!("{url}/v1/prove"))
                    .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
                    .header(SESSION_HEADER, token.as_str())
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                let status = r.status();
                let _ = r.bytes().await;
                out.push((t.elapsed(), status));
            }
            out
        }));
    }

    let mut latencies = Vec::new();
    let mut non_200 = 0;
    for h in handles {
        for (d, status) in h.await.unwrap() {
            if !status.is_success() {
                non_200 += 1;
            }
            latencies.push(d);
        }
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();

    let requests = workers * per_worker;
    let did_ok = state.metrics.prove_ok.load(Ordering::Relaxed) - before_ok;
    let errs = state.metrics.prove_err.load(Ordering::Relaxed);
    assert_eq!(errs, 0, "server counted {errs} failed proves");
    assert_eq!(did_ok as usize, requests, "server counted {did_ok} proves, driver sent {requests}");
    let micros = state.metrics.prove_micros_total.load(Ordering::Relaxed) - before_micros;

    Run {
        label: label.to_string(),
        n: fx.n,
        workers,
        requests,
        elapsed,
        latencies,
        non_200,
        server_mean: Duration::from_micros(micros / did_ok.max(1)),
    }
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    sorted[(((sorted.len() - 1) as f64) * p).round() as usize]
}

fn header(title: &str) {
    println!("\n{title}");
    println!(
        "{:<14} {:>8} {:>5} {:>6} {:>9} {:>9} {:>9} {:>9} {:>6}",
        "case", "n", "conc", "reqs", "req/s", "p50", "p95", "max", "srv/req"
    );
}

fn row(r: &Run) {
    let ms = |d: Duration| format!("{:.1}ms", d.as_secs_f64() * 1000.0);
    println!(
        "{:<14} {:>8} {:>5} {:>6} {:>9.2} {:>9} {:>9} {:>9} {:>9}{}",
        r.label,
        r.n,
        r.workers,
        r.requests,
        r.requests as f64 / r.elapsed.as_secs_f64(),
        ms(pct(&r.latencies, 0.50)),
        ms(pct(&r.latencies, 0.95)),
        ms(*r.latencies.last().unwrap()),
        ms(r.server_mean),
        if r.non_200 > 0 { format!("  ({} shed)", r.non_200) } else { String::new() },
    );
}

async fn run() {
    let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(1);
    println!("cores: {cores}   default max_concurrent_msm: {}", ServerConfig::default().max_concurrent_msm);

    header("circuit size with default admission");
    for (i, &n) in [4096usize, 16384, 65536].iter().enumerate() {
        let fx = fixture(n, 100 + i as u64);
        let r = measure(&format!("n={n}"), &fx, ServerConfig::default(), 8, 4).await;
        row(&r);
    }

    header("various admission bounds at n=16384");
    let fx = fixture(16384, 200);
    for slots in [1usize, 2, 4, 8] {
        let cfg = ServerConfig { max_concurrent_msm: slots, ..ServerConfig::default() };
        let r = measure(&format!("slots={slots}"), &fx, cfg, 8, 4).await;
        row(&r);
    }
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}
