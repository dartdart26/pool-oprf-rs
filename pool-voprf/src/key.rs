//! Constraint (K) from `docs/voprf.md`: `sk` opens `pk`, and each `sk_i` is
//! either 0 or 1.
//!
//! The commitment is a hash, i.e.
//! `pk = BLAKE3.derive_key(DOMAIN_SEPARATOR)(pack_key(sk))`, where
//! [`pack_key`] packs the key bits into bytes for a smaller input.

use crate::proof::Statement;
use pool_prf::params::N;
use pool_prf::prf::SecretKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const DOMAIN_SEPARATOR: &str = "pool-voprf v1 key commitment";

/// `N` bits at 8 per byte, rounded up, so the last byte is padded with zeros.
pub const PACKED_KEY_BYTES: usize = N.div_ceil(8);

pub const COMMITMENT_BYTES: usize = blake3::OUT_LEN;

/// `pk`: the commitment to the server's key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct KeyCommitment(pub [u8; COMMITMENT_BYTES]);

/// `N` bits at 8 per byte, rounded up, so the last byte is padded with zeros.
pub fn pack_key(sk: &SecretKey) -> Zeroizing<[u8; PACKED_KEY_BYTES]> {
    let mut packed = Zeroizing::new([0u8; PACKED_KEY_BYTES]);
    pack_bits(sk.as_bits(), &mut packed[..]);
    packed
}

/// Pack bits into `packed`, 8 per byte, padded with zeroes.
fn pack_bits(bits: &[u8], packed: &mut [u8]) {
    assert_eq!(packed.len(), bits.len().div_ceil(8), "packed size");
    for (byte, bits) in packed.iter_mut().zip(bits.chunks(8)) {
        for (position, &bit) in bits.iter().enumerate() {
            assert!(bit <= 1, "key bits are 0 or 1");
            *byte |= bit << position;
        }
    }
}

/// Commit to a key.
pub fn commit(sk: &SecretKey) -> KeyCommitment {
    let packed = pack_key(sk);
    let digest = blake3::Hasher::new_derive_key(DOMAIN_SEPARATOR)
        .update(&packed[..])
        .finalize();
    KeyCommitment(*digest.as_bytes())
}

/// Constraint (K) as a statement: `pk` is public, the key is the witness.
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

    #[test]
    fn the_first_bit_is_the_lowest() {
        let mut packed = [0u8; 1];
        pack_bits(&[1, 0, 0, 0, 0, 0, 0, 0], &mut packed);
        assert_eq!(packed, [0b0000_0001]);
    }

    #[test]
    fn a_whole_number_of_bytes_has_no_padding() {
        let mut packed = [0u8; 2];
        pack_bits(&[1; 16], &mut packed);
        assert_eq!(packed, [0xff, 0xff]);
    }

    #[test]
    fn a_partial_last_byte_is_padded_with_zeros() {
        let mut packed = [0u8; 2];
        pack_bits(&[1; 10], &mut packed);
        assert_eq!(packed, [0xff, 0b0000_0011]);
    }

    #[test]
    #[should_panic(expected = "key bits are 0 or 1")]
    fn a_non_bit_is_refused() {
        pack_bits(&[1, 2], &mut [0u8; 1]);
    }

    #[test]
    fn commitment_is_deterministic_and_key_dependent() {
        let a = SecretKey::random(&mut StdRng::seed_from_u64(1));
        let b = SecretKey::random(&mut StdRng::seed_from_u64(2));
        assert_eq!(commit(&a), commit(&a));
        assert_ne!(commit(&a), commit(&b));
    }
}
