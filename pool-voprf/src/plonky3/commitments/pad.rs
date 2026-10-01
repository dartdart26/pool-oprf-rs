//! `d_j` is a [`PadCommitment`] to the pair of `r′_j` and a random value.

use crate::CommitmentRandomness;
use crate::plonky3::commitments::{
    Commitment, Domain, Element, PAIR_ELEMENTS, pack_randomness, pair,
};
use p3_field::integers::QuotientMap;
use pool_prf::params::Zp;

/// `d_j`.
pub type PadCommitment = Commitment<{ Domain::Pad as u32 }, PAIR_ELEMENTS>;

/// Domain + the pair.
pub const INPUT_ELEMENTS: usize = 1 + PAIR_ELEMENTS;

pub fn elements(pad: Zp, randomness: CommitmentRandomness) -> [Element; PAIR_ELEMENTS] {
    pair(Element::from_int(pad), pack_randomness(randomness))
}

pub fn commit(pad: Zp, randomness: CommitmentRandomness) -> PadCommitment {
    PadCommitment::commit(elements(pad, randomness))
}

impl crate::traits::Commitment for PadCommitment {
    type Value = (Zp, CommitmentRandomness);

    fn commit(&(pad, randomness): &(Zp, CommitmentRandomness)) -> Self {
        commit(pad, randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::mask_sum;

    #[test]
    fn the_pair_is_the_pad_then_the_random_value() {
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

    #[test]
    fn same_pair_different_domain_commit_differently() {
        assert_ne!(commit(7, 8).0, mask_sum::commit(7, 8).0);
    }
}
