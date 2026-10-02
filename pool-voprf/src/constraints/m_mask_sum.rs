//! Constraint (M) from `docs/voprf.md`.
//!
//! `m` is a [`Commitment`] to the `r̃_Σ` of every run of an evaluation and
//! a random value.

use crate::CommitmentRandomness;
use crate::traits::{Commitment, Constraint};
use pool_prf::params::{RUNS_PER_EVALUATION, Zq};

pub struct MaskSum<'a, M> {
    pub m: &'a M,
    /// `r̃_Σ` of each run.
    pub r_sigma_sum: &'a [Zq; RUNS_PER_EVALUATION],
    /// Hashed into `m` with with the sums.
    pub randomness: CommitmentRandomness,
}

impl<M: Commitment<Value = ([Zq; RUNS_PER_EVALUATION], CommitmentRandomness)>> Constraint
    for MaskSum<'_, M>
{
    fn holds(&self) -> bool {
        M::commit(&(*self.r_sigma_sum, self.randomness)) == *self.m
    }
}
