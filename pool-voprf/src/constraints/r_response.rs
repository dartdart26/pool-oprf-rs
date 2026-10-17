//! Constraint (R) from `docs/voprf.md`. Every entry of the response is
//! computed correctly.
//!
//! ```text
//! y^{v, k}_j = ⌈(ã^{v, k}_Σ - j) mod q⌋ + r′^{v, k}_{(j - b̄′^{v, k}) mod Δ}   mod p,   j = 0 .. Δ-1
//! ```

use crate::traits::Constraint;
use pool_prf::params::{DELTA, Q, Zdelta, Zp, Zq};

pub struct Response<'a> {
    /// `y^{v, k}_0 .. y^{v, k}_{Δ-1}`.
    pub y: &'a [Zp; DELTA],
    /// `b̄′^{v, k}`, in `0 .. Δ-1`.
    pub b_bar_prime: Zdelta,
    /// `ã^{v, k}_Σ`: terms summed over all coordinates, mod `q`.
    pub a_sigma_sum: Zq,
    /// `r′^{v, k}_0 .. r′^{v, k}_{Δ-1}`.
    pub pads: &'a [Zp; DELTA],
}

impl Constraint for Response<'_> {
    fn holds(&self) -> bool {
        usize::from(self.b_bar_prime) < DELTA
            && self.a_sigma_sum < Q
            && pool_eval::respond(self.a_sigma_sum, self.pads, self.b_bar_prime) == *self.y
    }
}
