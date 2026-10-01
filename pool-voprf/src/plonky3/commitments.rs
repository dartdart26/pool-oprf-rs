//! Commitments via the Poseidon2 hash over BabyBear.
//!
//! Each kind of commitment includes its [`Domain`], such that no two kinds
//! hash to the same output.

pub mod key;
pub mod mask_sum;
pub mod pad;

use crate::CommitmentRandomness;
use core::{array, iter};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_32};
use p3_field::PrimeField32;
use p3_field::integers::QuotientMap;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use serde::{Deserialize, Serialize};

/// The field the commitments live in.
pub type Element = BabyBear;

/// How many bits a packed value puts in one [`Element`]: every number of
/// this many bits is below the field's prime.
pub const BITS_PER_ELEMENT: usize = Element::ORDER_U32.ilog2() as usize;

/// How many elements a random value takes, [`BITS_PER_ELEMENT`] bits each.
pub const RANDOMNESS_ELEMENTS: usize =
    (CommitmentRandomness::BITS as usize).div_ceil(BITS_PER_ELEMENT);

/// The random value as [`RANDOMNESS_ELEMENTS`] numbers of
/// [`BITS_PER_ELEMENT`] bits, lowest first.
pub fn pack_randomness(randomness: CommitmentRandomness) -> [Element; RANDOMNESS_ELEMENTS] {
    array::from_fn(|k| {
        let shifted = randomness >> (k * BITS_PER_ELEMENT);
        Element::from_int(shifted % (1 << BITS_PER_ELEMENT))
    })
}

/// A committed value and its random value as one array.
pub const PAIR_ELEMENTS: usize = 1 + RANDOMNESS_ELEMENTS;

pub fn pair<T>(value: T, randomness: [T; RANDOMNESS_ELEMENTS]) -> [T; PAIR_ELEMENTS] {
    let mut elements = iter::once(value).chain(randomness);
    array::from_fn(|_| elements.next().expect("an element"))
}

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
    /// (M): `r̃_Σ` and a random value.
    MaskSum = 2,
    /// (P): a pad and a random value.
    Pad = 3,
}

/// A commitment of one kind, to `LEN` elements. Both are in the type, such
/// that kinds cannot be mixed up and within a kind every input has
/// the same length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Commitment<const DOMAIN: u32, const LEN: usize>(pub(crate) [Element; DIGEST_ELEMENTS]);

impl<const DOMAIN: u32, const LEN: usize> Commitment<DOMAIN, LEN> {
    pub fn domain() -> Element {
        Element::from_int(DOMAIN)
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
    use p3_field::PrimeCharacteristicRing;

    fn elements<const N: usize>(values: [u32; N]) -> [Element; N] {
        values.map(Element::from_int)
    }

    #[test]
    fn randomness_packs_lowest_bits_first() {
        assert_eq!(pack_randomness(1)[0], Element::ONE);
        assert_eq!(pack_randomness(1 << BITS_PER_ELEMENT)[1], Element::ONE);
    }

    /// `count` 1 bits.
    fn ones(count: usize) -> Element {
        Element::from_int((1u32 << count) - 1)
    }

    /// The maximum packs to full elements of ones, then the bits left over.
    #[test]
    fn randomness_packs_every_bit() {
        let packed = pack_randomness(CommitmentRandomness::MAX);
        let (last, full) = packed.split_last().expect("elements");
        let left_over = CommitmentRandomness::BITS as usize % BITS_PER_ELEMENT;
        assert!(
            full.iter()
                .all(|&element| element == ones(BITS_PER_ELEMENT))
        );
        assert_eq!(*last, ones(left_over));
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
