//! Constraint (T) from `docs/voprf.md`.
//!
//! ```text
//! r̃^{v, k}_Σ = Σ_i (1 - 2·sk_i)·r^{v, k}_{b_i, i}   mod q
//! ```

use crate::traits::Constraint;
use core::array;
use pool_prf::params::{N, Q, RUNS_PER_EVALUATION, Zq};
use pool_prf::prf::SecretKey;

pub struct SumOfMasks<'a> {
    pub sk: &'a SecretKey,
    /// `r^{v, k}_{b_i, i}` of each `i` and run `k`.
    pub masks: &'a [[Zq; RUNS_PER_EVALUATION]; N],
    /// `r̃^{v, k}_Σ` of each run `k`.
    pub r_sigma_sums: &'a [Zq; RUNS_PER_EVALUATION],
}

impl Constraint for SumOfMasks<'_> {
    fn holds(&self) -> bool {
        self.masks.as_flattened().iter().all(|&r| r < Q)
            && (0..RUNS_PER_EVALUATION).all(|k| {
                let masks = array::from_fn(|i| self.masks[i][k]);
                pool_eval::r_sigma_sum(self.sk, &masks) == self.r_sigma_sums[k]
            })
    }
}
