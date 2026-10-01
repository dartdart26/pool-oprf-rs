//! Constraint (P) from `docs/voprf.md`.
//!
//! Each `d_j` is a [`Commitment`] to the pair of `r′_j` and a random value.

use crate::CommitmentRandomness;
use crate::traits::{Commitment, Constraint};
use pool_prf::params::{DELTA, Zp};

pub struct Pads<'a, D> {
    /// `d_0 .. d_{Δ-1}`.
    pub d: &'a [D; DELTA],
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: &'a [Zp; DELTA],
    /// Hashed into `d_j` with `r′_j`.
    pub randomness: &'a [CommitmentRandomness; DELTA],
}

impl<D: Commitment<Value = (Zp, CommitmentRandomness)>> Constraint for Pads<'_, D> {
    fn holds(&self) -> bool {
        (0..DELTA).all(|j| D::commit(&(self.pads[j], self.randomness[j])) == self.d[j])
    }
}
