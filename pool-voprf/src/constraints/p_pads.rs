//! Constraint (P) from `docs/voprf.md`.
//!
//! ```text
//! d_j = Commit(Domain::Pad, r′_j, randomness_j),   j = 0 .. Δ-1
//! ```

use crate::commitments::{CommitmentRandomness, PadInput};
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

impl<D: Commitment<Input = PadInput>> Constraint for Pads<'_, D> {
    fn holds(&self) -> bool {
        (0..DELTA).all(|j| {
            let input = PadInput {
                pad: self.pads[j],
                randomness: self.randomness[j],
            };
            D::commit(&input) == self.d[j]
        })
    }
}
