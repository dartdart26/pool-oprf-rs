//! Constraint (S) from `docs/voprf.md`.
//!
//! ```text
//! c^v_{b̄_i ⊕ sk_i, i} = Commit(Domain::Masks, r^{v, 0}_{b_i, i} .. r^{v, RUNS_PER_EVALUATION-1}_{b_i, i}, ot_block_{b_i, i}),   i = 0 .. n-1
//! ```

use crate::commitments::{CommitmentRandomness, MasksInput};
use crate::traits::{Commitment, Constraint};
use pool_prf::params::{N, RUNS_PER_EVALUATION, Zq};
use pool_prf::prf::SecretKey;

pub struct ServerMasks<'a, C> {
    /// `c^v_{0, i}` and `c^v_{1, i}` of each `i`.
    pub c: &'a [[C; 2]; N],
    /// `b̄_i` of each `i`.
    pub b_bar: &'a [u8; N],
    pub sk: &'a SecretKey,
    /// `r^{v, k}_{b_i, i}` of each `i` and run `k`.
    pub masks: &'a [[Zq; RUNS_PER_EVALUATION]; N],
    /// `ot_block_{b_i, i}` of each `i`.
    pub ot_blocks: &'a [CommitmentRandomness; N],
}

impl<C: Commitment<Input = MasksInput>> Constraint for ServerMasks<'_, C> {
    fn holds(&self) -> bool {
        let sk = self.sk.as_bits();
        (0..N).all(|i| {
            let b_bar_i = self.b_bar[i];
            let b_i = usize::from(b_bar_i ^ sk[i]);
            let input = MasksInput {
                masks: self.masks[i],
                randomness: self.ot_blocks[i],
            };
            b_bar_i <= 1 && self.c[i][b_i] == C::commit(&input)
        })
    }
}
