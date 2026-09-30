//! `m` is a [`MaskSumCommitment`] to the pair of `r̃_Σ` and a random value.

use crate::CommitmentRandomness;
use crate::plonky3::commitments::{
    Commitment, Domain, Element, RANDOMNESS_ELEMENTS, pack_randomness,
};
use core::{array, iter};
use p3_field::integers::QuotientMap;
use pool_prf::params::Zq;

pub const PAIR_ELEMENTS: usize = 1 + RANDOMNESS_ELEMENTS;

/// `m` - a commitment to the pair.
pub type MaskSumCommitment = Commitment<{ Domain::MaskSum as u32 }, PAIR_ELEMENTS>;

/// Domain + the pair.
pub const INPUT_ELEMENTS: usize = 1 + PAIR_ELEMENTS;

/// `r̃_Σ` then the random value, as one array.
pub fn pair<T>(r_sigma_sum: T, randomness: [T; RANDOMNESS_ELEMENTS]) -> [T; PAIR_ELEMENTS] {
    let mut elements = iter::once(r_sigma_sum).chain(randomness);
    array::from_fn(|_| elements.next().expect("an element"))
}

/// The pair as elements.
pub fn elements(r_sigma_sum: Zq, randomness: CommitmentRandomness) -> [Element; PAIR_ELEMENTS] {
    pair(Element::from_int(r_sigma_sum), pack_randomness(randomness))
}

/// Commit to the pair.
pub fn commit(r_sigma_sum: Zq, randomness: CommitmentRandomness) -> MaskSumCommitment {
    MaskSumCommitment::commit(elements(r_sigma_sum, randomness))
}

impl crate::traits::Commitment for MaskSumCommitment {
    type Value = (Zq, CommitmentRandomness);

    fn commit(&(r_sigma_sum, randomness): &(Zq, CommitmentRandomness)) -> Self {
        commit(r_sigma_sum, randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pair_is_r_sigma_sum_then_the_random_value() {
        let pair = elements(7, 8);
        assert_eq!(pair[0], Element::from_int(7u32));
        assert_eq!(pair[1..], pack_randomness(8));
    }

    #[test]
    fn commitment_is_deterministic_and_depends_on_both() {
        assert_eq!(commit(7, 8), commit(7, 8));
        assert_ne!(commit(7, 8), commit(8, 8));
        assert_ne!(commit(7, 8), commit(7, 9));
    }
}
