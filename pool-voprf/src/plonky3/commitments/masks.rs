//! `c_{0, i}` and `c_{1, i}` are [`MasksCommitment`]s to the masks of every
//! run of an evaluation and a random value.

use crate::commitments::{CommitmentRandomness, MasksInput};
use crate::hash_domains::Domain;
use crate::plonky3::commitments::{
    Commitment, Element, RANDOMNESS_ELEMENTS, concat, pack_randomness,
};
use p3_field::integers::QuotientMap;
use pool_prf::params::{RUNS_PER_EVALUATION, Zq};

/// The mask of each run, then the random value.
pub const VALUE_ELEMENTS: usize = RUNS_PER_EVALUATION + RANDOMNESS_ELEMENTS;

pub type MasksCommitment = Commitment<{ Domain::Masks as u32 }, VALUE_ELEMENTS>;

/// Domain + the values.
pub const INPUT_ELEMENTS: usize = 1 + VALUE_ELEMENTS;

pub fn elements(
    masks: &[Zq; RUNS_PER_EVALUATION],
    randomness: CommitmentRandomness,
) -> [Element; VALUE_ELEMENTS] {
    concat(masks.map(Element::from_int), pack_randomness(randomness))
}

pub fn commit(
    masks: &[Zq; RUNS_PER_EVALUATION],
    randomness: CommitmentRandomness,
) -> MasksCommitment {
    MasksCommitment::commit(elements(masks, randomness))
}

impl crate::traits::Commitment for MasksCommitment {
    type Input = MasksInput;

    fn commit(input: &MasksInput) -> Self {
        commit(&input.masks, input.randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic_and_depends_on_both() {
        let mut other = [7; RUNS_PER_EVALUATION];
        other[RUNS_PER_EVALUATION - 1] = 8;
        assert_eq!(
            commit(&[7; RUNS_PER_EVALUATION], 8),
            commit(&[7; RUNS_PER_EVALUATION], 8)
        );
        assert_ne!(commit(&[7; RUNS_PER_EVALUATION], 8), commit(&other, 8));
        assert_ne!(
            commit(&[7; RUNS_PER_EVALUATION], 8),
            commit(&[7; RUNS_PER_EVALUATION], 9)
        );
    }
}
