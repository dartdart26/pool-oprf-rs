//! Constraint (M) from `docs/voprf.md`.
//!
//! `m` is a [`Commitment`] to the `r̃_Σ` of every run of an evaluation and
//! a random value.

use crate::traits::{Commitment, Constraint};
use crate::{CommitmentRandomness, RUNS};
use pool_prf::params::Zq;

pub struct MaskSum<'a, M> {
    pub m: &'a M,
    /// `r̃_Σ` of each run.
    pub r_sigma_sum: &'a [Zq; RUNS],
    /// Hashed into `m` with them.
    pub randomness: CommitmentRandomness,
}

impl<M: Commitment<Value = ([Zq; RUNS], CommitmentRandomness)>> Constraint for MaskSum<'_, M> {
    fn holds(&self) -> bool {
        M::commit(&(*self.r_sigma_sum, self.randomness)) == *self.m
    }
}
