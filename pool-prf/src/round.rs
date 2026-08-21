use crate::modular::reduce_p;
use crate::params::{DELTA_ZQ, Q, Zp, Zq};

/// Round a Zq element to Zp by computing (p/q)*v, rounding to the nearest integer.
/// On a tie, we round down.
#[inline]
pub fn round_zq_to_zp(v: Zq) -> Zp {
    assert!(v < Q, "v must be reduced mod q");
    let quotient = v / DELTA_ZQ;
    let remainder = v % DELTA_ZQ;
    // Remainder runs from 0 to DELTA - 1. If it is more than half, round up.
    // Else round down, with exactly half rounding down.
    // The arithmetic stays in Zq, so both branches reduce into [0, p) before
    // the cast, which is then a plain narrowing.
    if remainder > DELTA_ZQ / 2 {
        reduce_p(quotient + 1)
    } else {
        quotient as Zp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::P;

    #[test]
    fn rounding_boundaries() {
        // The tie point: a remainder above this rounds up, and exactly this
        // rounds down.
        const HALF: Zq = DELTA_ZQ / 2;

        // The first HALF + 1 values map to 0, the last of them by the tie.
        for v in 0..=HALF {
            assert_eq!(round_zq_to_zp(v), 0, "v={v}");
        }
        // The next DELTA values map to 1: HALF + 1 is the first to round up,
        // and DELTA + HALF is the next tie, which rounds back down.
        for v in HALF + 1..=DELTA_ZQ + HALF {
            assert_eq!(round_zq_to_zp(v), 1, "v={v}");
        }
        // One past that tie rounds up to 2.
        assert_eq!(round_zq_to_zp(DELTA_ZQ + HALF + 1), 2);
        // The last value that maps to p - 1.
        assert_eq!(round_zq_to_zp(Q - DELTA_ZQ + HALF), (P - 1) as Zp);
        // Everything past that tie rounds up to p, which wraps to 0.
        for v in Q - HALF + 1..Q {
            assert_eq!(round_zq_to_zp(v), 0, "v={v}");
        }
    }
}
