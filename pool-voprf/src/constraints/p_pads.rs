//! Constraint (P) from `docs/voprf.md`.
//!
//! ```text
//! d^{v, k}_j = Commit(Domain::Pad, r′^{v, k}_j, ot_block′^{v, k}_j),   j = 0 .. Δ-1
//! ```

use crate::commitments::{CommitmentRandomness, PadInput};
use crate::traits::{Commitment, Constraint};
use pool_prf::params::{DELTA, Zp};

pub struct Pads<'a, D> {
    /// `d^{v, k}_0 .. d^{v, k}_{Δ-1}`.
    pub d: &'a [D; DELTA],
    /// `r′^{v, k}_0 .. r′^{v, k}_{Δ-1}`.
    pub pads: &'a [Zp; DELTA],
    /// Hashed into `d^{v, k}_j` with `r′^{v, k}_j`.
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
