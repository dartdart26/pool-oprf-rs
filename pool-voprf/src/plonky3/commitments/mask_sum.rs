//! `m` is a [`MaskSumCommitment`] to the `r̃_Σ` of every run of an
//! evaluation and a random value.

use crate::plonky3::commitments::{
    Commitment, Domain, Element, RANDOMNESS_ELEMENTS, pack_randomness,
};
use crate::{CommitmentRandomness, RUNS};
use core::array;
use p3_field::integers::QuotientMap;
use pool_prf::params::Zq;

/// The `r̃_Σ` of each run, then the random value.
pub const VALUE_ELEMENTS: usize = RUNS + RANDOMNESS_ELEMENTS;

/// `m` - a commitment to the values.
pub type MaskSumCommitment = Commitment<{ Domain::MaskSum as u32 }, VALUE_ELEMENTS>;

/// Domain + the values.
pub const INPUT_ELEMENTS: usize = 1 + VALUE_ELEMENTS;

/// The `r̃_Σ` of each run and the random value as one array.
pub fn values<T>(
    r_sigma_sum: [T; RUNS],
    randomness: [T; RANDOMNESS_ELEMENTS],
) -> [T; VALUE_ELEMENTS] {
    let mut elements = r_sigma_sum.into_iter().chain(randomness);
    array::from_fn(|_| elements.next().expect("an element"))
}

/// The values as elements.
pub fn elements(
    r_sigma_sum: &[Zq; RUNS],
    randomness: CommitmentRandomness,
) -> [Element; VALUE_ELEMENTS] {
    values(
        r_sigma_sum.map(Element::from_int),
        pack_randomness(randomness),
    )
}

/// Commit to the values.
pub fn commit(r_sigma_sum: &[Zq; RUNS], randomness: CommitmentRandomness) -> MaskSumCommitment {
    MaskSumCommitment::commit(elements(r_sigma_sum, randomness))
}

impl crate::traits::Commitment for MaskSumCommitment {
    type Value = ([Zq; RUNS], CommitmentRandomness);

    fn commit((r_sigma_sum, randomness): &([Zq; RUNS], CommitmentRandomness)) -> Self {
        commit(r_sigma_sum, *randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_values_are_the_sums_then_the_random_value() {
        let values = elements(&[7; RUNS], 8);
        assert_eq!(values[..RUNS], [Element::from_int(7u32); RUNS]);
        assert_eq!(values[RUNS..], pack_randomness(8));
    }

    #[test]
    fn commitment_is_deterministic_and_depends_on_both() {
        let mut other = [7; RUNS];
        other[RUNS - 1] = 8;
        assert_eq!(commit(&[7; RUNS], 8), commit(&[7; RUNS], 8));
        assert_ne!(commit(&[7; RUNS], 8), commit(&other, 8));
        assert_ne!(commit(&[7; RUNS], 8), commit(&[7; RUNS], 9));
    }
}
