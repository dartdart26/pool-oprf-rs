//! Constraint (R) from `docs/voprf.md`. Every entry of the response is
//! computed correctly.
//!
//! ```text
//! y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}   mod p,   j = 0 .. Δ-1
//! ```
//!
//! `y` and `b̄′` are public. `ã_Σ` and `r′` are the witness.

use crate::proof::Statement;
use pool_prf::params::{DELTA, Q, Zdelta, Zp, Zq};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResponseStatement {
    /// `y_0 .. y_{Δ-1}`.
    pub y: [Zp; DELTA],
    /// `b̄′`, in `0 .. Δ-1`.
    pub b_bar_prime: Zdelta,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResponseWitness {
    /// `ã_Σ`: terms summed over all coordinates, mod `q`.
    pub a_sigma_sum: Zq,
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: [Zp; DELTA],
}

impl ResponseStatement {
    /// The statement an honest server makes for `witness` and `b_bar_prime`.
    pub fn for_witness(witness: &ResponseWitness, b_bar_prime: Zdelta) -> Self {
        Self {
            y: pool_eval::respond(witness.a_sigma_sum, &witness.pads, b_bar_prime),
            b_bar_prime,
        }
    }
}

impl Statement for ResponseStatement {
    type Witness = ResponseWitness;

    fn holds_for(&self, witness: &ResponseWitness) -> bool {
        usize::from(self.b_bar_prime) < DELTA
            && witness.a_sigma_sum < Q
            && Self::for_witness(witness, self.b_bar_prime) == *self
    }
}
