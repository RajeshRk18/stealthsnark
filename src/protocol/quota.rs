//! Per-principal quota: request rate, body size, and concurrent sessions.
//!
//! The server-wide limits in [`crate::protocol::config`] protect the process.
//! They cannot stop one caller from consuming everything, because they do not
//! know who is calling. These limits are per principal, so one noisy client
//! degrades only itself.
//!
//! Three limits, each stopping a different failure:
//!
//! - **Request rate** — a token bucket. Absorbs a legitimate burst, then holds
//!   the caller to a sustained rate.
//! - **Body size** — checked from `Content-Length` before the body is read, so an
//!   over-quota upload is refused rather than buffered and then discarded.
//! - **Concurrent sessions** — bounds how much memory one principal can pin.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::auth::Principal;
use super::error::ApiError;

/// A token bucket.
///
/// Chosen over a fixed window because a fixed window lets a caller send two full
/// windows' worth of traffic across a boundary. A bucket has no boundary.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_seen: Instant,
}

impl Bucket {
    fn new(burst: u32) -> Self {
        Self {
            // Start full, so a first request never waits.
            tokens: f64::from(burst),
            last_seen: Instant::now(),
        }
    }

    /// Refill for elapsed time, then try to spend one token.
    fn try_spend(&mut self, now: Instant, rate_per_sec: f64, burst: u32) -> bool {
        let elapsed = now.saturating_duration_since(self.last_seen).as_secs_f64();
        self.last_seen = now;
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(f64::from(burst));

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Tracks per-principal usage.
#[derive(Debug)]
pub struct QuotaEnforcer {
    buckets: RwLock<HashMap<String, Bucket>>,
}

impl Default for QuotaEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaEnforcer {
    pub fn new() -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Charge one request against the principal's rate limit.
    pub fn check_rate(&self, principal: &Principal) -> Result<(), ApiError> {
        self.check_rate_at(principal, Instant::now())
    }

    /// [`Self::check_rate`] with an explicit clock, so tests do not sleep.
    pub fn check_rate_at(&self, principal: &Principal, now: Instant) -> Result<(), ApiError> {
        let tier = &principal.tier;
        let mut buckets = self.write();
        let bucket = buckets
            .entry(principal.id.clone())
            .or_insert_with(|| Bucket::new(tier.burst));

        if bucket.try_spend(now, tier.requests_per_sec, tier.burst) {
            Ok(())
        } else {
            // Time until one token is available, for a useful Retry-After.
            let deficit = 1.0 - bucket.tokens;
            let wait = (deficit / tier.requests_per_sec).clamp(1.0, 3600.0);
            Err(ApiError::RateLimited {
                retry_after_secs: wait.ceil() as u64,
            })
        }
    }

    /// Reject an upload larger than the principal's tier allows.
    ///
    /// A missing `Content-Length` is permitted here; the transport body limit is
    /// the backstop for a chunked or lying sender.
    pub fn check_body_size(
        &self,
        principal: &Principal,
        content_length: Option<u64>,
    ) -> Result<(), ApiError> {
        let limit = principal.tier.max_body_bytes as u64;
        match content_length {
            Some(len) if len > limit => Err(ApiError::BodyTooLarge {
                limit_bytes: limit,
                got_bytes: len,
            }),
            _ => Ok(()),
        }
    }

    /// Reject a new session when the principal already holds its allowance.
    pub fn check_session_allowance(
        &self,
        principal: &Principal,
        held: usize,
    ) -> Result<(), ApiError> {
        if held >= principal.tier.max_sessions {
            return Err(ApiError::SessionQuotaExceeded {
                limit: principal.tier.max_sessions,
            });
        }
        Ok(())
    }

    /// Drop buckets untouched for `idle` and already refilled to full.
    ///
    /// Without this the map grows once per distinct principal and never shrinks.
    /// A bucket below full is kept regardless of age: discarding it would hand
    /// back a free burst and defeat the limit.
    pub fn sweep(&self, idle: Duration) -> usize {
        self.sweep_at(idle, Instant::now())
    }

    pub fn sweep_at(&self, idle: Duration, now: Instant) -> usize {
        let mut buckets = self.write();
        let before = buckets.len();
        buckets.retain(|_, b| {
            let age = now.saturating_duration_since(b.last_seen);
            age < idle || b.tokens < 1.0
        });
        before - buckets.len()
    }

    pub fn tracked_principals(&self) -> usize {
        self.read().len()
    }

    // A panic while the lock is held cannot corrupt the map: the only operations
    // are insert, retain, and arithmetic on owned values. Recovering the guard is
    // better than failing every later request on a poisoned lock.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Bucket>> {
        self.buckets.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Bucket>> {
        self.buckets.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::{AuthMethod, Tier};

    fn principal(rate: f64, burst: u32, max_sessions: usize, max_body: usize) -> Principal {
        Principal {
            id: "tester".to_string(),
            tier: Tier {
                name: "test".to_string(),
                max_sessions,
                max_body_bytes: max_body,
                requests_per_sec: rate,
                burst,
            },
            method: AuthMethod::ApiKey,
        }
    }

    #[test]
    fn a_burst_is_allowed_then_the_rate_binds() {
        let q = QuotaEnforcer::new();
        let p = principal(1.0, 3, 4, 1024);
        let t0 = Instant::now();

        // The bucket starts full: three requests pass immediately.
        for i in 0..3 {
            assert!(q.check_rate_at(&p, t0).is_ok(), "burst request {i} refused");
        }
        // The fourth has no token.
        let err = q.check_rate_at(&p, t0).unwrap_err();
        assert_eq!(err.code(), "rate_limited");
        assert!(err.is_retryable());
    }

    #[test]
    fn tokens_refill_over_time() {
        let q = QuotaEnforcer::new();
        let p = principal(2.0, 2, 4, 1024);
        let t0 = Instant::now();

        assert!(q.check_rate_at(&p, t0).is_ok());
        assert!(q.check_rate_at(&p, t0).is_ok());
        assert!(q.check_rate_at(&p, t0).is_err(), "bucket should be empty");

        // At 2 tokens/sec, half a second buys exactly one request.
        let t1 = t0 + Duration::from_millis(500);
        assert!(q.check_rate_at(&p, t1).is_ok());
        assert!(q.check_rate_at(&p, t1).is_err());
    }

    #[test]
    fn refill_never_exceeds_the_burst_ceiling() {
        let q = QuotaEnforcer::new();
        let p = principal(10.0, 2, 4, 1024);
        let t0 = Instant::now();

        assert!(q.check_rate_at(&p, t0).is_ok());
        // A long idle period must not accumulate unlimited credit.
        let t1 = t0 + Duration::from_secs(3600);
        assert!(q.check_rate_at(&p, t1).is_ok());
        assert!(q.check_rate_at(&p, t1).is_ok());
        assert!(
            q.check_rate_at(&p, t1).is_err(),
            "idle time bought more than one burst"
        );
    }

    #[test]
    fn principals_have_independent_buckets() {
        let q = QuotaEnforcer::new();
        let mut a = principal(1.0, 1, 4, 1024);
        a.id = "a".to_string();
        let mut b = principal(1.0, 1, 4, 1024);
        b.id = "b".to_string();
        let t0 = Instant::now();

        assert!(q.check_rate_at(&a, t0).is_ok());
        assert!(q.check_rate_at(&a, t0).is_err());
        // b must be unaffected by a exhausting its allowance.
        assert!(q.check_rate_at(&b, t0).is_ok());
        assert_eq!(q.tracked_principals(), 2);
    }

    #[test]
    fn retry_after_is_present_and_sane() {
        let q = QuotaEnforcer::new();
        let p = principal(0.5, 1, 4, 1024);
        let t0 = Instant::now();
        assert!(q.check_rate_at(&p, t0).is_ok());

        match q.check_rate_at(&p, t0).unwrap_err() {
            ApiError::RateLimited { retry_after_secs } => {
                assert!(
                    (1..=3600).contains(&retry_after_secs),
                    "implausible retry hint: {retry_after_secs}"
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn body_size_is_checked_against_the_tier() {
        let q = QuotaEnforcer::new();
        let p = principal(1.0, 1, 4, 1024);

        assert!(q.check_body_size(&p, Some(1024)).is_ok(), "at the limit");
        assert!(q.check_body_size(&p, Some(0)).is_ok());
        // No Content-Length: the transport limit is the backstop.
        assert!(q.check_body_size(&p, None).is_ok());

        let err = q.check_body_size(&p, Some(1025)).unwrap_err();
        assert_eq!(err.code(), "body_too_large");
        assert_eq!(err.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        // The message must state the limit, so a client can adapt.
        assert!(err.to_string().contains("1024"));
    }

    #[test]
    fn session_allowance_is_enforced() {
        let q = QuotaEnforcer::new();
        let p = principal(1.0, 1, 2, 1024);

        assert!(q.check_session_allowance(&p, 0).is_ok());
        assert!(q.check_session_allowance(&p, 1).is_ok());

        let err = q.check_session_allowance(&p, 2).unwrap_err();
        assert_eq!(err.code(), "session_quota_exceeded");
        assert!(err.is_retryable(), "freeing a session makes this succeed");
        // Already over the limit, for example after a tier downgrade.
        assert!(q.check_session_allowance(&p, 9).is_err());
    }

    #[test]
    fn sweep_drops_idle_full_buckets_but_keeps_indebted_ones() {
        let q = QuotaEnforcer::new();
        let mut idle = principal(100.0, 4, 4, 1024);
        idle.id = "idle".to_string();
        let mut spent = principal(0.001, 1, 4, 1024);
        spent.id = "spent".to_string();

        let t0 = Instant::now();
        assert!(q.check_rate_at(&idle, t0).is_ok());
        assert!(q.check_rate_at(&spent, t0).is_ok());
        assert_eq!(q.tracked_principals(), 2);

        // Long after: `idle` has refilled to full and can be forgotten. `spent`
        // refills very slowly, so dropping it would gift it a fresh burst.
        let t1 = t0 + Duration::from_secs(600);
        assert_eq!(q.sweep_at(Duration::from_secs(300), t1), 1);
        assert_eq!(q.tracked_principals(), 1);

        // The retained bucket still remembers that it is out of credit.
        assert!(q.check_rate_at(&spent, t1).is_err());
    }
}
