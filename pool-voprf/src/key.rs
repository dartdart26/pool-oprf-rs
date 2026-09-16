//! Constraint (K) from `docs/voprf.md`: `sk` opens `pk`, and each `sk_i` is
//! either 0 or 1.
//!
//! `pk` is a [`KeyCommitment`] to `sk`.
//!
//! [`pack_key`] reads [`BITS_PER_ELEMENT`] bits at a time into an [`Element`],
//! so that the key becomes the [`Element`]s the commitment takes as input.

use crate::commitment::{Commitment, Domain, Element};
use crate::proof::Statement;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pool_prf::params::N;
use pool_prf::prf::SecretKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const BITS_PER_ELEMENT: usize = Element::ORDER_U32.ilog2() as usize;

/// `N` bits, [`BITS_PER_ELEMENT`] per element, rounded up. The last element
/// is padded with zero bits.
pub const PACKED_KEY_ELEMENTS: usize = N.div_ceil(BITS_PER_ELEMENT);

/// `pk`: a commitment to the packed key.
pub type KeyCommitment = Commitment<{ Domain::Key as u32 }, PACKED_KEY_ELEMENTS>;

/// What the commitment ingests - the domain + the packed key.
pub const INPUT_ELEMENTS: usize = 1 + PACKED_KEY_ELEMENTS;

/// The key as [`PACKED_KEY_ELEMENTS`] numbers of [`BITS_PER_ELEMENT`] bits.
pub fn pack_key(sk: &SecretKey) -> Zeroizing<[u32; PACKED_KEY_ELEMENTS]> {
    let mut packed = Zeroizing::new([0u32; PACKED_KEY_ELEMENTS]);
    for (element, bits) in packed.iter_mut().zip(sk.as_bits().chunks(BITS_PER_ELEMENT)) {
        for (position, &bit) in bits.iter().enumerate() {
            *element |= u32::from(bit) << position;
        }
    }
    packed
}

/// A packed key as elements.
pub fn elements(packed: &[u32; PACKED_KEY_ELEMENTS]) -> [Element; PACKED_KEY_ELEMENTS] {
    packed.map(Element::from_u32)
}

/// Commit to a key.
pub fn commit(sk: &SecretKey) -> KeyCommitment {
    KeyCommitment::commit(elements(&pack_key(sk)))
}

/// Constraint (K) as a statement - `pk` is public, the key is the witness.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyStatement {
    pub pk: KeyCommitment,
}

impl KeyStatement {
    pub fn for_key(sk: &SecretKey) -> Self {
        Self { pk: commit(sk) }
    }
}

impl Statement for KeyStatement {
    type Witness = SecretKey;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const ALL_ONES: u32 = (1 << BITS_PER_ELEMENT) - 1;

    fn key_with(set_bits: &[usize]) -> SecretKey {
        let mut bits = [0u8; N];
        for &i in set_bits {
            bits[i] = 1;
        }
        SecretKey::from_bits(bits).expect("bits")
    }

    #[test]
    fn the_first_bit_is_the_lowest() {
        assert_eq!(pack_key(&key_with(&[0]))[0], 1);
    }

    #[test]
    fn element_boundaries_are_correct() {
        let packed = pack_key(&key_with(&[BITS_PER_ELEMENT - 1, BITS_PER_ELEMENT]));
        assert_eq!(packed[0], 1 << (BITS_PER_ELEMENT - 1));
        assert_eq!(packed[1], 1);
    }

    #[test]
    fn the_last_element_is_padded_with_zeros() {
        let packed = pack_key(&SecretKey::from_bits([1; N]).expect("bits"));
        let (last, full) = packed.split_last().expect("elements");
        assert!(full.iter().all(|&element| element == ALL_ONES));
        if N.is_multiple_of(BITS_PER_ELEMENT) {
            assert_eq!(*last, ALL_ONES);
        } else {
            assert_ne!(*last, ALL_ONES);
            assert_ne!(*last, 0);
        }
    }

    #[test]
    fn commitment_is_deterministic_and_key_dependent() {
        let a = SecretKey::random(&mut StdRng::seed_from_u64(1));
        let b = SecretKey::random(&mut StdRng::seed_from_u64(2));
        assert_eq!(commit(&a), commit(&a));
        assert_ne!(commit(&a), commit(&b));
    }
}
