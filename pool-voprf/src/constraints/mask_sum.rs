//! Constraint (M) from `docs/voprf.md`.
//!
//! `m` is a [`Commitment`] to the pair of `r̃_Σ` and a random value.

use crate::CommitmentRandomness;
use crate::traits::{Commitment, Constraint};
use pool_prf::params::{Q, Zq};

pub struct MaskSum<'a, M> {
    pub m: &'a M,
    /// `r̃_Σ`.
    pub r_sigma_sum: Zq,
    /// Hashed into `m` with `r̃_Σ`.
    pub randomness: CommitmentRandomness,
}

impl<M: Commitment<Value = (Zq, CommitmentRandomness)>> Constraint for MaskSum<'_, M> {
    fn holds(&self) -> bool {
        self.r_sigma_sum < Q && M::commit(&(self.r_sigma_sum, self.randomness)) == *self.m
    }
}
