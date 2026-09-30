//! Constraint (A) from `docs/voprf.md`.
//!
//! ```text
//! ã_Σ = Σ_i sk_i·e_i + r̃_Σ   mod q
//! ```
//!
//! `e` is public. `sk` and `r̃_Σ` are the witness. `ã_Σ` is neither: the
//! proof computes it for (R) to use.

use crate::proof::Statement;
use pool_prf::params::{N, Q, Zq};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SumStatement {
    pub e: [Zq; N],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SumWitness {
    pub sk: SecretKey,
    pub r_sigma_sum: Zq,
}

impl Statement for SumStatement {
    type Witness = SumWitness;

    /// Every key and every `r̃_Σ` have a sum, so (A) holds for any witness
    /// in range.
    fn holds_for(&self, witness: &SumWitness) -> bool {
        witness.r_sigma_sum < Q && self.e.iter().all(|&x| x < Q)
    }
}
