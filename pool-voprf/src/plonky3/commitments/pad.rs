//! `d^{v, k}_j` is a [`PadCommitment`] to the pair of `r′^{v, k}_j` and a
//! random value.

use crate::commitments::{CommitmentRandomness, PadInput};
use crate::hash_domains::Domain;
use crate::plonky3::commitments::{Commitment, Element, PAIR_ELEMENTS, concat, pack_randomness};
use p3_field::integers::QuotientMap;
use pool_prf::params::Zp;

/// `d^{v, k}_j`.
pub type PadCommitment = Commitment<{ Domain::Pad as u32 }, PAIR_ELEMENTS>;

pub fn elements(pad: Zp, randomness: CommitmentRandomness) -> [Element; PAIR_ELEMENTS] {
    concat([Element::from_int(pad)], pack_randomness(randomness))
}

pub fn commit(pad: Zp, randomness: CommitmentRandomness) -> PadCommitment {
    PadCommitment::commit(elements(pad, randomness))
}

impl crate::traits::Commitment for PadCommitment {
    type Input = PadInput;

    fn commit(input: &PadInput) -> Self {
        commit(input.pad, input.randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic_and_depends_on_both() {
        assert_eq!(commit(7, 8), commit(7, 8));
        assert_ne!(commit(7, 8), commit(8, 8));
        assert_ne!(commit(7, 8), commit(7, 9));
    }
}
