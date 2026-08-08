//! Lightweight process metrics in Prometheus text format.
//!
//! Hand-rolled over atomics rather than pulling in a metrics framework: the
//! surface is nine counters and the render is a `write!` loop, which is a lot
//! cheaper than the dependency.
//!
//! The counter that matters most is [`Metrics::consistency_check_failures`].
//! In malicious-secure mode the client cross-checks two independent queries per
//! MSM; a mismatch means the server returned inconsistent results, i.e. it
//! cheated or corrupted data. That is the single most important signal this
//! system can emit, and until now it existed only as a `Result` on the client
//! side that nothing aggregated.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Monotonic counters for the service. Cheap enough to update on every request.
#[derive(Debug, Default)]
pub struct Metrics {
    pub setup_ok: AtomicU64,
    pub setup_err: AtomicU64,
    pub prove_ok: AtomicU64,
    pub prove_err: AtomicU64,

    /// Total time spent inside MSM evaluation, in microseconds. Paired with
    /// `prove_ok` this gives a mean; a histogram would need a real metrics crate.
    pub prove_micros_total: AtomicU64,
    /// Slowest single MSM evaluation observed, in microseconds.
    pub prove_micros_max: AtomicU64,

    pub rejected_overloaded: AtomicU64,
    pub rejected_session_limit: AtomicU64,
    pub rejected_unknown_session: AtomicU64,
    pub sessions_evicted: AtomicU64,

    /// Malicious-mode consistency check failures. Non-zero means a server
    /// returned inconsistent MSM results. Alert on any increase.
    pub consistency_check_failures: AtomicU64,
}

impl Metrics {
    pub fn record_prove_ok(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.prove_ok.fetch_add(1, Ordering::Relaxed);
        self.prove_micros_total.fetch_add(micros, Ordering::Relaxed);
        self.prove_micros_max.fetch_max(micros, Ordering::Relaxed);
    }

    /// Record the outcome of a rejected request against the matching counter, so
    /// that load-shedding is visible separately from client errors.
    pub fn record_rejection(&self, err: &super::error::ApiError) {
        use super::error::ApiError as E;
        match err {
            E::Overloaded | E::ShuttingDown => &self.rejected_overloaded,
            E::SessionLimit => &self.rejected_session_limit,
            E::UnknownSession | E::MissingToken => &self.rejected_unknown_session,
            _ => return,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Render Prometheus text format. `active_sessions` and `msm_slots_free` are
    /// live gauges passed in by the caller rather than stored here.
    pub fn render(&self, active_sessions: usize, msm_slots_free: usize) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut out = String::with_capacity(2048);

        let counters: [(&str, &str, u64); 10] = [
            (
                "stealthsnark_setup_requests_ok_total",
                "Successful /v1/setup requests.",
                g(&self.setup_ok),
            ),
            (
                "stealthsnark_setup_requests_err_total",
                "Failed /v1/setup requests.",
                g(&self.setup_err),
            ),
            (
                "stealthsnark_prove_requests_ok_total",
                "Successful /v1/prove requests.",
                g(&self.prove_ok),
            ),
            (
                "stealthsnark_prove_requests_err_total",
                "Failed /v1/prove requests.",
                g(&self.prove_err),
            ),
            (
                "stealthsnark_prove_duration_micros_total",
                "Cumulative MSM evaluation time in microseconds.",
                g(&self.prove_micros_total),
            ),
            (
                "stealthsnark_rejected_overloaded_total",
                "Requests shed because no MSM slot was available.",
                g(&self.rejected_overloaded),
            ),
            (
                "stealthsnark_rejected_session_limit_total",
                "Setups refused because max_sessions was reached.",
                g(&self.rejected_session_limit),
            ),
            (
                "stealthsnark_rejected_unknown_session_total",
                "Requests refused for a missing or expired session token.",
                g(&self.rejected_unknown_session),
            ),
            (
                "stealthsnark_sessions_evicted_total",
                "Sessions evicted after exceeding their idle TTL.",
                g(&self.sessions_evicted),
            ),
            (
                "stealthsnark_consistency_check_failures_total",
                "Malicious-mode consistency check failures. Non-zero means a server cheated.",
                g(&self.consistency_check_failures),
            ),
        ];

        for (name, help, value) in counters {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {value}");
        }

        let gauges: [(&str, &str, u64); 3] = [
            (
                "stealthsnark_active_sessions",
                "Sessions currently holding generators in memory.",
                active_sessions as u64,
            ),
            (
                "stealthsnark_msm_slots_free",
                "Free MSM admission slots. Zero means requests are being shed.",
                msm_slots_free as u64,
            ),
            (
                "stealthsnark_prove_duration_micros_max",
                "Slowest single MSM evaluation observed, in microseconds.",
                g(&self.prove_micros_max),
            ),
        ];

        for (name, help, value) in gauges {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name} {value}");
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_valid_prometheus_shape() {
        let m = Metrics::default();
        m.record_prove_ok(Duration::from_millis(5));
        let text = m.render(3, 1);

        assert!(text.contains("stealthsnark_prove_requests_ok_total 1"));
        assert!(text.contains("stealthsnark_active_sessions 3"));
        assert!(text.contains("stealthsnark_msm_slots_free 1"));
        assert!(text.contains("stealthsnark_prove_duration_micros_total 5000"));
        // Every metric line must be preceded by HELP and TYPE metadata.
        let helps = text.matches("# HELP ").count();
        let types = text.matches("# TYPE ").count();
        assert_eq!(helps, types);
        assert_eq!(helps, 13);
    }

    #[test]
    fn max_duration_tracks_the_slowest() {
        let m = Metrics::default();
        m.record_prove_ok(Duration::from_micros(100));
        m.record_prove_ok(Duration::from_micros(900));
        m.record_prove_ok(Duration::from_micros(400));
        assert_eq!(m.prove_micros_max.load(Ordering::Relaxed), 900);
        assert_eq!(m.prove_micros_total.load(Ordering::Relaxed), 1400);
    }

    #[test]
    fn rejections_land_in_distinct_buckets() {
        use super::super::error::ApiError;
        let m = Metrics::default();
        m.record_rejection(&ApiError::Overloaded);
        m.record_rejection(&ApiError::SessionLimit);
        m.record_rejection(&ApiError::UnknownSession);
        m.record_rejection(&ApiError::MissingToken);
        // Not a rejection category — must not inflate any bucket.
        m.record_rejection(&ApiError::MalformedBody(String::new()));

        assert_eq!(m.rejected_overloaded.load(Ordering::Relaxed), 1);
        assert_eq!(m.rejected_session_limit.load(Ordering::Relaxed), 1);
        assert_eq!(m.rejected_unknown_session.load(Ordering::Relaxed), 2);
    }
}
