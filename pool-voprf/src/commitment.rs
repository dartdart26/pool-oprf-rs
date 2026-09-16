//! Commitments via the Poseidon2 hash over BabyBear.
//!
//! Each kind of commitment includes its [`Domain`], such that no two kinds
//! hash to the same output.

use core::iter;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_32};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use serde::{Deserialize, Serialize};

/// The field the commitments live in.
pub type Element = BabyBear;

pub const WIDTH: usize = 32;
pub const CAPACITY: usize = 8;
pub const DIGEST_ELEMENTS: usize = CAPACITY;
pub const RATE: usize = WIDTH - CAPACITY;

pub type Permutation = Poseidon2BabyBear<WIDTH>;
pub type Sponge = PaddingFreeSponge<Permutation, WIDTH, RATE, DIGEST_ELEMENTS>;

pub fn permutation() -> Permutation {
    default_babybear_poseidon2_32()
}

pub fn sponge() -> Sponge {
    Sponge::new(permutation())
}

// Each commitment has a separate domain to ensure no two kinds hash to the same output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Domain {
    /// (K): the server's key.
    Key = 1,
}

/// A commitment of one kind, to `LEN` elements. Both are in the type, such
/// that kinds cannot be mixed up and within a kind every input has
/// the same length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Commitment<const DOMAIN: u32, const LEN: usize>(pub(crate) [Element; DIGEST_ELEMENTS]);

impl<const DOMAIN: u32, const LEN: usize> Commitment<DOMAIN, LEN> {
    pub fn domain() -> Element {
        Element::from_u32(DOMAIN)
    }

    pub fn input<T: From<Element>>(elements: [T; LEN]) -> impl Iterator<Item = T> {
        iter::once(Self::domain().into()).chain(elements)
    }

    pub fn commit(elements: [Element; LEN]) -> Self {
        Self(sponge().hash_iter(Self::input(elements)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elements<const N: usize>(values: [u32; N]) -> [Element; N] {
        values.map(Element::from_u32)
    }

    #[test]
    fn a_commitment_is_32_bytes() {
        let commitment = Commitment::<1, 2>::commit(elements([7, 8]));
        let bytes = bincode::serialize(&commitment).expect("serializing");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn same_input_commits_the_same_and_different_input_differently() {
        let a = Commitment::<1, 2>::commit(elements([7, 8]));
        assert_eq!(a, Commitment::<1, 2>::commit(elements([7, 8])));
        assert_ne!(a, Commitment::<1, 2>::commit(elements([8, 7])));
    }

    #[test]
    fn the_domain_is_input_too() {
        assert_ne!(
            Commitment::<1, 2>::commit(elements([7, 8])).0,
            Commitment::<2, 2>::commit(elements([7, 8])).0
        );
    }
}
