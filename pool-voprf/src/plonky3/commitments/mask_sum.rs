//! `m` is a [`MaskSumCommitment`] to the `r̃_Σ` of every run of an
//! evaluation and a random value.

use crate::CommitmentRandomness;
use crate::plonky3::commitments::{
    Commitment, Domain, Element, RANDOMNESS_ELEMENTS, concat, pack_randomness,
};
use p3_field::integers::QuotientMap;
use pool_prf::params::{RUNS_PER_EVALUATION, Zq};

/// The `r̃_Σ` of each run, then the random value.
pub const VALUE_ELEMENTS: usize = RUNS_PER_EVALUATION + RANDOMNESS_ELEMENTS;

pub type MaskSumCommitment = Commitment<{ Domain::MaskSum as u32 }, VALUE_ELEMENTS>;

/// Domain + the values.
pub const INPUT_ELEMENTS: usize = 1 + VALUE_ELEMENTS;

pub fn elements(
    r_sigma_sum: &[Zq; RUNS_PER_EVALUATION],
    randomness: CommitmentRandomness,
) -> [Element; VALUE_ELEMENTS] {
    concat(
        r_sigma_sum.map(Element::from_int),
        pack_randomness(randomness),
    )
}

pub fn commit(
    r_sigma_sum: &[Zq; RUNS_PER_EVALUATION],
    randomness: CommitmentRandomness,
) -> MaskSumCommitment {
    MaskSumCommitment::commit(elements(r_sigma_sum, randomness))
}

impl crate::traits::Commitment for MaskSumCommitment {
    type Value = ([Zq; RUNS_PER_EVALUATION], CommitmentRandomness);

    fn commit(
        (r_sigma_sum, randomness): &([Zq; RUNS_PER_EVALUATION], CommitmentRandomness),
    ) -> Self {
        commit(r_sigma_sum, *randomness)
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
