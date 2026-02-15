pragma circom 2.0.0;

// Prove that `value` fits in `n` bits (default 8).
// Decomposes value into n bit signals and checks each is 0 or 1.
template RangeCheck(n) {
    signal input value;
    signal output out;

    signal bits[n];

    var lc = 0;
    for (var i = 0; i < n; i++) {
        bits[i] <-- (value >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;  // each bit is 0 or 1
        lc += bits[i] * (1 << i);
    }

    // Enforce value == sum of bits * powers of 2
    value === lc;

    out <== value;
}

component main = RangeCheck(8);
