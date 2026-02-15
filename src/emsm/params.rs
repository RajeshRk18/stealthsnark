/// LPN parameters for 100-bit security.
/// Based on Table 3 of the paper (R = 1/4, delta = 0.05).
#[derive(Debug, Clone, Copy)]
pub struct LpnParams {
    /// Original vector length
    pub n: usize,
    /// Expanded length: N = 4n (rate R = 1/4)
    pub big_n: usize,
    /// Sparsity parameter (number of nonzero entries in error vector)
    pub t: usize,
}

/// Get LPN parameters for a given vector length n.
/// Returns (N = 4n, t) from Table 3 of the paper for 100-bit security.
pub fn get_lpn_params(n: usize) -> LpnParams {
    // Table 3 values from the paper for 100-bit security, R=1/4, delta=0.05
    // n -> t (approximate, interpolated for sizes not in table)
    // For very small n, we clamp t so that N = 4n >= t (needed for error_vec chunking)
    let big_n = 4 * n;
    let raw_t = match n {
        0..=1024 => 29,           // 2^10
        1025..=2048 => 33,        // 2^11
        2049..=4096 => 38,        // 2^12
        4097..=8192 => 43,        // 2^13
        8193..=16384 => 48,       // 2^14
        16385..=32768 => 54,      // 2^15
        32769..=65536 => 60,      // 2^16
        65537..=131072 => 67,     // 2^17
        131073..=262144 => 74,    // 2^18
        262145..=524288 => 82,    // 2^19
        524289..=1048576 => 90,   // 2^20
        1048577..=2097152 => 99,  // 2^21
        2097153..=4194304 => 108, // 2^22
        4194305..=8388608 => 118, // 2^23
        _ => 128,                 // 2^24+
    };

    // Clamp t so that the expanded vector size N = 4n >= t
    // (for tiny circuits, security is naturally limited by the small dimension)
    let t = raw_t.min(big_n.max(1));
    LpnParams { n, big_n, t }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_basic() {
        let p = get_lpn_params(1024);
        assert_eq!(p.n, 1024);
        assert_eq!(p.big_n, 4096);
        assert_eq!(p.t, 29);
    }

    #[test]
    fn test_params_monotonic() {
        // t should increase with n
        let t1 = get_lpn_params(1024).t;
        let t2 = get_lpn_params(65536).t;
        let t3 = get_lpn_params(1048576).t;
        assert!(t1 < t2);
        assert!(t2 < t3);
    }

    #[test]
    fn test_rate() {
        let p = get_lpn_params(4096);
        assert_eq!(p.big_n, 4 * p.n); // R = 1/4
    }
}
