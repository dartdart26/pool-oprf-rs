//! Constraint (A) from `docs/voprf.md`.
//!
//! ```text
//! ã_Σ = Σ_i sk_i·e_i + r̃_Σ   mod q
//! ```
//!
//! `e` is public. `sk` and `r̃_Σ` are the witness. `ã_Σ` is neither: the
//! proof computes it for (R) to use.

use crate::traits::Constraint;
use pool_prf::params::{N, Q, Zq};
use pool_prf::prf::SecretKey;

pub struct Sum<'a> {
    pub e: &'a [Zq; N],
    pub sk: &'a SecretKey,
    pub r_sigma_sum: Zq,
}

impl Sum<'_> {
    pub fn a_sigma_sum(&self) -> Zq {
        pool_eval::a_sigma_sum(self.sk, self.r_sigma_sum, self.e)
    }
}

impl Constraint for Sum<'_> {
    /// Every key and every `r̃_Σ` have a sum, so (A) holds for any witness
    /// in range.
    fn holds(&self) -> bool {
        self.r_sigma_sum < Q && self.e.iter().all(|&x| x < Q)
    }
}
