//! Constraint (R) from `docs/voprf.md`. Every entry of the response is
//! computed correctly.
//!
//! ```text
//! y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}   mod p,   j = 0 .. Δ-1
//! ```
//!
//! `y` and `b̄′` are public. `ã_Σ` and `r′` are the witness. The proof
//! does not use `b̄′` yet as that is left to (P).

use crate::traits::Constraint;
use pool_prf::params::{DELTA, Q, Zdelta, Zp, Zq};

pub struct Response<'a> {
    /// `y_0 .. y_{Δ-1}`.
    pub y: &'a [Zp; DELTA],
    /// `b̄′`, in `0 .. Δ-1`.
    pub b_bar_prime: Zdelta,
    /// `ã_Σ`: terms summed over all coordinates, mod `q`.
    pub a_sigma_sum: Zq,
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: &'a [Zp; DELTA],
}

impl Constraint for Response<'_> {
    fn holds(&self) -> bool {
        usize::from(self.b_bar_prime) < DELTA
            && self.a_sigma_sum < Q
            && pool_eval::respond(self.a_sigma_sum, self.pads, self.b_bar_prime) == *self.y
    }
}
