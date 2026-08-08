//! Session storage: server-issued tokens, prebuilt commitment keys, TTL eviction.
//!
//! Three problems in the original design are addressed here.
//!
//! **The session id was chosen by the client.** A second `/setup` carrying an
//! id already in use silently replaced the first client's generators, so anyone
//! who could guess or observe an id could make a victim's `/prove` return results
//! computed against attacker-supplied bases. In malicious-secure mode the
//! double-query check would detect that; in semi-honest mode it would silently
//! yield a garbage proof. Now the server mints the token and the client never
//! chooses it.
//!
//! **Sessions were never released.** The map had no TTL, no cap, and no teardown
//! endpoint, so every `/setup` pinned its generators for the life of the process.
//!
//! **Every `/prove` cloned the generators.** The old handler called
//! `generators.clone()` five times and rebuilt all five `Pedersen` structs per
//! request — tens of MiB of memcpy for a large circuit. The `Pedersen` instances
//! are now built once at setup and handed out behind an `Arc`, so `/prove` does
//! no allocation on that path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ark_bn254::{G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use rand::rngs::OsRng;
use rand::RngCore;

use super::error::ApiError;
use crate::emsm::pedersen::Pedersen;

/// Bytes of entropy in a session token. 256 bits makes guessing infeasible, which
/// is what lets us skip a constant-time lookup (see [`SessionStore::get`]).
const TOKEN_BYTES: usize = 32;

/// Hex characters in the short, non-secret log label.
const LABEL_HEX_CHARS: usize = 12;

/// Commitment keys for the five outsourced MSMs, built once at setup.
pub struct Generators {
    pub ped_h: Pedersen<G1>,
    pub ped_l: Pedersen<G1>,
    pub ped_a: Pedersen<G1>,
    pub ped_b_g1: Pedersen<G1>,
    pub ped_b_g2: Pedersen<G2>,
}

impl Generators {
    pub fn from_points(
        h: Vec<G1Affine>,
        l: Vec<G1Affine>,
        a: Vec<G1Affine>,
        b_g1: Vec<G1Affine>,
        b_g2: Vec<G2Affine>,
    ) -> Self {
        Self {
            ped_h: Pedersen::from_generators(h),
            ped_l: Pedersen::from_generators(l),
            ped_a: Pedersen::from_generators(a),
            ped_b_g1: Pedersen::from_generators(b_g1),
            ped_b_g2: Pedersen::from_generators(b_g2),
        }
    }

    /// Approximate resident size, for capacity logging and the metrics gauge.
    pub fn resident_bytes(&self) -> usize {
        let g1 = std::mem::size_of::<G1Affine>();
        let g2 = std::mem::size_of::<G2Affine>();
        (self.ped_h.generators.len()
            + self.ped_l.generators.len()
            + self.ped_a.generators.len()
            + self.ped_b_g1.generators.len())
            * g1
            + self.ped_b_g2.generators.len() * g2
    }

    /// Generator counts per MSM, for structured logging.
    pub fn counts(&self) -> [usize; 5] {
        [
            self.ped_h.generators.len(),
            self.ped_l.generators.len(),
            self.ped_a.generators.len(),
            self.ped_b_g1.generators.len(),
            self.ped_b_g2.generators.len(),
        ]
    }
}

/// A live session. Shared behind an `Arc` so `/prove` clones a pointer, not
/// hundreds of MiB of curve points.
pub struct Session {
    /// Short, non-secret identifier for logs and metrics.
    ///
    /// The token is a bearer credential, so it must never reach a log sink; this
    /// label exists so that requests remain traceable without leaking it.
    pub label: String,
    /// Id of the principal that created this session.
    ///
    /// This is what makes the session token second-factor rather than sufficient:
    /// [`SessionStore::get_owned`] refuses a token presented by any other
    /// principal, so a leaked token is useless without the owner's credential.
    pub owner: String,
    pub generators: Generators,
    pub resident_bytes: usize,
    /// Milliseconds since the store's epoch at last successful lookup.
    last_seen_ms: AtomicU64,
}

impl Session {
    fn touch(&self, now_ms: u64) {
        self.last_seen_ms.store(now_ms, Ordering::Relaxed);
    }
}

/// Hand-written to print a summary.
///
/// A derived implementation would dump every generator — millions of curve points
/// for a real circuit — which turns one stray `{:?}` into an unusable log and a
/// memory spike. Counts carry all the diagnostic value.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("label", &self.label)
            .field("owner", &self.owner)
            .field("generator_counts", &self.generators.counts())
            .field("resident_bytes", &self.resident_bytes)
            .finish()
    }
}

/// Token-keyed session map with an idle TTL and a hard capacity cap.
pub struct SessionStore {
    inner: RwLock<HashMap<String, Arc<Session>>>,
    epoch: Instant,
    max_sessions: usize,
    ttl: Duration,
    evicted: AtomicU64,
}

impl SessionStore {
    pub fn new(max_sessions: usize, ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            epoch: Instant::now(),
            max_sessions,
            ttl,
            evicted: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Store generators and return `(token, label)`.
    ///
    /// The token is freshly minted from the OS CSPRNG; the client has no say in
    /// it. Expired sessions are swept first so that a full map caused purely by
    /// abandoned sessions does not reject a legitimate new one.
    pub fn insert(
        &self,
        owner: &str,
        generators: Generators,
    ) -> Result<(String, String), ApiError> {
        self.sweep();

        let resident_bytes = generators.resident_bytes();
        let token = mint_hex(TOKEN_BYTES);
        let label = mint_hex(LABEL_HEX_CHARS / 2);

        let session = Arc::new(Session {
            label: label.clone(),
            owner: owner.to_string(),
            generators,
            resident_bytes,
            last_seen_ms: AtomicU64::new(self.now_ms()),
        });

        let mut map = self.write();
        if map.len() >= self.max_sessions {
            return Err(ApiError::SessionLimit);
        }
        map.insert(token.clone(), session);
        Ok((token, label))
    }

    /// Look up a session by token, refreshing its idle timer.
    ///
    /// A `HashMap` probe is not constant-time, so this technically leaks timing
    /// information about the key. With 256 bits of entropy an attacker has
    /// nothing to walk toward, so the simplicity is worth more than a
    /// constant-time map here. Revisit if tokens ever become shorter or derived.
    pub fn get(&self, token: &str) -> Option<Arc<Session>> {
        let now = self.now_ms();
        let map = self.read();
        let session = map.get(token)?;
        if self.is_expired(session, now) {
            // Leave removal to the sweeper; treating it as absent is enough here
            // and keeps this path on a read lock.
            return None;
        }
        session.touch(now);
        Some(session.clone())
    }

    /// Look up a session and require that `principal_id` owns it.
    ///
    /// Ownership is checked separately from existence, and the two produce
    /// different errors on purpose. An unknown token is a 401 — the credential
    /// may simply be stale. A valid token belonging to somebody else is a 403,
    /// because no retry with the same identity can ever succeed.
    pub fn get_owned(&self, token: &str, principal_id: &str) -> Result<Arc<Session>, ApiError> {
        let session = self.get(token).ok_or(ApiError::UnknownSession)?;
        if session.owner != principal_id {
            // The log records the mismatch; the client is told nothing about the
            // real owner.
            tracing::warn!(
                session = %session.label,
                owner = %session.owner,
                presented_by = %principal_id,
                "session token presented by a different principal"
            );
            return Err(ApiError::Forbidden(
                "this session belongs to another client".to_string(),
            ));
        }
        Ok(session)
    }

    /// Explicitly drop a session. Returns whether it existed.
    pub fn remove(&self, token: &str) -> Option<Arc<Session>> {
        self.write().remove(token)
    }

    /// Remove a session only if `principal_id` owns it.
    pub fn remove_owned(&self, token: &str, principal_id: &str) -> Result<Arc<Session>, ApiError> {
        // Resolve ownership first, so a wrong principal cannot delete a session
        // it does not own.
        self.get_owned(token, principal_id)?;
        self.remove(token).ok_or(ApiError::UnknownSession)
    }

    /// Live sessions held by one principal, for quota accounting.
    ///
    /// Expired-but-unswept sessions are excluded, so a principal is not charged
    /// for allowance it no longer holds.
    pub fn count_for(&self, principal_id: &str) -> usize {
        let now = self.now_ms();
        self.read()
            .values()
            .filter(|s| s.owner == principal_id && !self.is_expired(s, now))
            .count()
    }

    /// Evict every session past its idle TTL. Returns how many were dropped.
    ///
    /// Called on insert and by the background sweeper — the latter matters
    /// because an otherwise idle server should still release memory.
    pub fn sweep(&self) -> usize {
        let now = self.now_ms();
        let mut map = self.write();
        let before = map.len();
        map.retain(|_, s| !self.is_expired(s, now));
        let dropped = before - map.len();
        if dropped > 0 {
            self.evicted.fetch_add(dropped as u64, Ordering::Relaxed);
        }
        dropped
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn evicted_total(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    /// Total generator bytes currently pinned across all sessions.
    pub fn resident_bytes(&self) -> usize {
        self.read().values().map(|s| s.resident_bytes).sum()
    }

    fn is_expired(&self, s: &Session, now_ms: u64) -> bool {
        let last = s.last_seen_ms.load(Ordering::Relaxed);
        Duration::from_millis(now_ms.saturating_sub(last)) > self.ttl
    }

    // A panic while holding this lock cannot leave the map structurally invalid —
    // the only operations performed are insert/remove/retain on owned values — so
    // recovering the guard is preferable to letting one poisoned lock take every
    // subsequent request down with it.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Arc<Session>>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Arc<Session>>> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// Hex-encode `n` bytes from the OS CSPRNG.
fn mint_hex(n: usize) -> String {
    let mut raw = vec![0u8; n];
    OsRng.fill_bytes(&mut raw);
    let mut s = String::with_capacity(n * 2);
    for b in raw {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_generators() -> Generators {
        Generators::from_points(vec![], vec![], vec![], vec![], vec![])
    }

    fn store(max: usize, ttl_ms: u64) -> SessionStore {
        SessionStore::new(max, Duration::from_millis(ttl_ms))
    }

    #[test]
    fn tokens_are_unpredictable_and_unique() {
        let s = store(100, 60_000);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let (token, label) = s.insert("owner", tiny_generators()).unwrap();
            assert_eq!(
                token.len(),
                TOKEN_BYTES * 2,
                "token must be 256 bits of hex"
            );
            assert_eq!(label.len(), LABEL_HEX_CHARS);
            assert!(seen.insert(token.clone()), "token collision: {token}");
            // The public label must not expose any part of the secret token.
            assert!(!token.contains(&label));
        }
    }

    #[test]
    fn a_client_cannot_overwrite_another_session() {
        // The hijack that the old client-chosen session_id allowed: two setups
        // must yield two independent sessions, never a replacement.
        let s = store(100, 60_000);
        let (token_a, _) = s.insert("owner", tiny_generators()).unwrap();
        let (token_b, _) = s.insert("owner", tiny_generators()).unwrap();
        assert_ne!(token_a, token_b);
        assert_eq!(s.len(), 2);
        assert!(s.get(&token_a).is_some());
        assert!(s.get(&token_b).is_some());
    }

    #[test]
    fn unknown_token_is_refused() {
        let s = store(100, 60_000);
        s.insert("owner", tiny_generators()).unwrap();
        assert!(s.get("not-a-real-token").is_none());
        assert!(s.get("").is_none());
    }

    #[test]
    fn capacity_is_enforced() {
        let s = store(2, 60_000);
        s.insert("owner", tiny_generators()).unwrap();
        s.insert("owner", tiny_generators()).unwrap();
        let err = s.insert("owner", tiny_generators()).unwrap_err();
        assert_eq!(err.code(), "session_limit");
        assert_eq!(s.len(), 2, "a refused insert must not grow the map");
    }

    #[test]
    fn idle_sessions_expire_and_free_memory() {
        let s = store(100, 0); // everything older than 0ms is expired
        let (token, _) = s.insert("owner", tiny_generators()).unwrap();
        std::thread::sleep(Duration::from_millis(5));

        assert!(s.get(&token).is_none(), "expired session must not resolve");
        assert_eq!(s.sweep(), 1);
        assert!(s.is_empty());
        assert_eq!(s.evicted_total(), 1);
    }

    #[test]
    fn active_use_refreshes_the_idle_timer() {
        let s = store(100, 200);
        let (token, _) = s.insert("owner", tiny_generators()).unwrap();
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(60));
            assert!(s.get(&token).is_some(), "in-use session was evicted");
        }
        // Total elapsed (~240ms) exceeds the 200ms TTL, but each lookup touched it.
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn explicit_release_frees_immediately() {
        let s = store(100, 60_000);
        let (token, _) = s.insert("owner", tiny_generators()).unwrap();
        assert!(s.remove(&token).is_some());
        assert!(s.is_empty());
        assert!(s.remove(&token).is_none(), "double release must be a no-op");
    }

    #[test]
    fn capacity_refusal_does_not_outlive_expiry() {
        // A map full of abandoned sessions must not reject a legitimate new one.
        let s = store(1, 0);
        s.insert("owner", tiny_generators()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            s.insert("owner", tiny_generators()).is_ok(),
            "insert must sweep expired sessions before refusing on capacity"
        );
    }

    #[test]
    fn a_session_token_is_useless_to_another_principal() {
        // This is what makes the session token a second factor rather than a
        // sufficient credential. Even with the exact token, a different principal
        // cannot use it.
        let s = store(100, 60_000);
        let (token, _) = s.insert("alice", tiny_generators()).unwrap();

        assert!(s.get_owned(&token, "alice").is_ok());

        let err = s.get_owned(&token, "bob").unwrap_err();
        assert_eq!(err.code(), "forbidden");
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(!err.is_retryable(), "bob retrying as bob can never succeed");

        // The message must not disclose the real owner.
        assert!(!err.to_string().contains("alice"));
    }

    #[test]
    fn ownership_and_existence_produce_different_errors() {
        let s = store(100, 60_000);
        let (token, _) = s.insert("alice", tiny_generators()).unwrap();

        // Unknown token: 401, because the credential may merely be stale.
        assert_eq!(
            s.get_owned("00".repeat(32).as_str(), "alice")
                .unwrap_err()
                .code(),
            "unknown_session"
        );
        // Real token, wrong owner: 403, because no retry can help.
        assert_eq!(s.get_owned(&token, "bob").unwrap_err().code(), "forbidden");
    }

    #[test]
    fn only_the_owner_can_release_a_session() {
        let s = store(100, 60_000);
        let (token, _) = s.insert("alice", tiny_generators()).unwrap();

        assert_eq!(
            s.remove_owned(&token, "bob").unwrap_err().code(),
            "forbidden"
        );
        assert_eq!(s.len(), 1, "a refused release must not delete the session");

        assert!(s.remove_owned(&token, "alice").is_ok());
        assert!(s.is_empty());
        assert_eq!(
            s.remove_owned(&token, "alice").unwrap_err().code(),
            "unknown_session",
            "double release must not succeed"
        );
    }

    #[test]
    fn sessions_are_counted_per_principal_for_quota() {
        let s = store(100, 60_000);
        s.insert("alice", tiny_generators()).unwrap();
        s.insert("alice", tiny_generators()).unwrap();
        s.insert("bob", tiny_generators()).unwrap();

        assert_eq!(s.count_for("alice"), 2);
        assert_eq!(s.count_for("bob"), 1);
        assert_eq!(s.count_for("carol"), 0);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn expired_sessions_do_not_count_against_quota() {
        // A principal must not be charged for allowance it no longer holds, even
        // before the sweeper has run.
        let s = store(100, 0);
        s.insert("alice", tiny_generators()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(s.count_for("alice"), 0);
        // The entry is still physically present until the sweep.
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn resident_bytes_tracks_generator_sizes() {
        let s = store(10, 60_000);
        assert_eq!(s.resident_bytes(), 0);

        let g = Generators::from_points(
            vec![G1Affine::identity(); 10],
            vec![],
            vec![],
            vec![],
            vec![G2Affine::identity(); 4],
        );
        let expected = 10 * std::mem::size_of::<G1Affine>() + 4 * std::mem::size_of::<G2Affine>();
        assert_eq!(g.resident_bytes(), expected);
        assert_eq!(g.counts(), [10, 0, 0, 0, 4]);

        s.insert("owner", g).unwrap();
        assert_eq!(s.resident_bytes(), expected);
    }
}
