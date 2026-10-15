//! Constraint (M) from `docs/voprf.md`.
//!
//! ```text
//! m = Commit(Domain::MaskSum, r̃^0_Σ .. r̃^{RUNS_PER_EVALUATION-1}_Σ, randomness)
//! ```

use crate::commitments::{CommitmentRandomness, MaskSumsInput};
use crate::traits::{Commitment, Constraint};
use pool_prf::params::{RUNS_PER_EVALUATION, Zq};

pub struct MaskSum<'a, M> {
    pub m: &'a M,
    /// `r̃_Σ` of each run.
    pub r_sigma_sum: &'a [Zq; RUNS_PER_EVALUATION],
    /// Hashed into `m` with the sums.
    pub randomness: CommitmentRandomness,
}

impl<M: Commitment<Input = MaskSumsInput>> Constraint for MaskSum<'_, M> {
    fn holds(&self) -> bool {
        let input = MaskSumsInput {
            r_sigma_sums: *self.r_sigma_sum,
            randomness: self.randomness,
        };
        M::commit(&input) == *self.m
    }
}
