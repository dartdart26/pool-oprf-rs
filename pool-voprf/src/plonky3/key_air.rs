//! The circuit for constraint (K): `pk` is the BLAKE3 hash of the secret
//! key `sk`.
//!
//! Plonky3 ships the rules that check one BLAKE3 compression. We use them
//! as they are, with the key as the input of the hash. They already require
//! every input bit to be 0 or 1, which is the bit check of (K). Our rules
//! here add:
//!
//! - the hash input is one block of 512 bits and the key is only `N` (`N` <= 512)
//!   bits, with the rest being zero padding;
//! - the hash is set up with the same `derive_key` context, counter, length and flags;
//! - the output equals `pk`, which the verifier supplies.

use crate::key::{DOMAIN_SEPARATOR, KeyCommitment, PACKED_KEY_BYTES, pack_key};
use crate::plonky3::Val;
use crate::plonky3::compress::{
    BLOCK_BYTES, BLOCK_WORDS, DERIVE_KEY_MATERIAL, block_from_bytes, context_key, fill_row,
    single_block_flags,
};
use core::array;
use core::borrow::{Borrow, BorrowMut};
use p3_air::utils::{pack_bits_le, u32_to_bits_le};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3_air::{Blake3Air, Blake3Cols, NUM_BLAKE3_COLS};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::params::N;
use pool_prf::prf::SecretKey;
use zeroize::Zeroizing;

const BLOCK_BITS: usize = BLOCK_BYTES * 8;
const _: () = assert!(N <= BLOCK_BITS, "the key must fit one BLAKE3 block");

const FLAGS: u32 = single_block_flags(DERIVE_KEY_MATERIAL);

/// `pk` split into 16 numbers of 16 bits.
pub const NUM_PUBLIC_VALUES: usize = 16;

/// The AIR. Holds the `derive_key` context key the chaining value must equal.
#[derive(Debug)]
pub struct KeyAir {
    context_key: [u32; 8],
}

impl Default for KeyAir {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyAir {
    pub fn new() -> Self {
        Self {
            context_key: context_key(DOMAIN_SEPARATOR),
        }
    }

    /// The public values for `pk`.
    pub fn public_values(pk: &KeyCommitment) -> [Val; NUM_PUBLIC_VALUES] {
        array::from_fn(|i| Val::from_u16(u16::from_le_bytes([pk.0[2 * i], pk.0[2 * i + 1]])))
    }

    /// The table the prover fills in. It has `rows` rows, and each row holds
    /// one complete hash of `sk`: input, every intermediate value, output.
    /// All rows are the same. Plonky3 needs a few hundred rows for the
    /// hiding to have room to mask.
    ///
    /// Note that the secret key is not zeroized after use here.
    pub fn trace(&self, sk: &SecretKey, rows: usize) -> RowMajorMatrix<Val> {
        assert!(rows.is_power_of_two(), "a trace has a power of two rows");
        let block: Zeroizing<[u32; BLOCK_WORDS]> =
            Zeroizing::new(block_from_bytes(&pack_key(sk)[..]));

        let mut values = Val::zero_vec(rows * NUM_BLAKE3_COLS);
        let (first, rest) = values.split_at_mut(NUM_BLAKE3_COLS);
        let row: &mut Blake3Cols<Val> = first.borrow_mut();
        fill_row(
            row,
            &self.context_key,
            &block,
            0,
            PACKED_KEY_BYTES as u32,
            FLAGS,
        );
        for other in rest.chunks_exact_mut(NUM_BLAKE3_COLS) {
            other.copy_from_slice(first);
        }
        RowMajorMatrix::new(values, NUM_BLAKE3_COLS)
    }
}

impl<F> BaseAir<F> for KeyAir {
    fn width(&self) -> usize {
        NUM_BLAKE3_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // The BLAKE3 AIR's; everything added here is linear.
        Some(3)
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

/// Every bit of a 32-bit column equals the bit of `value`.
fn assert_word<AB: AirBuilder>(builder: &mut AB, bits: &[AB::Var; 32], value: u32) {
    for (bit, expected) in bits.iter().zip(u32_to_bits_le::<AB::Expr>(value)) {
        builder.assert_eq(*bit, expected);
    }
}

impl<AB: AirBuilder> Air<AB> for KeyAir {
    fn eval(&self, builder: &mut AB) {
        // The compression is computed correctly, and every message bit is
        // boolean: with the key as the message, that is the bit check of (K).
        Blake3Air {}.eval(builder);

        let pk: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            array::from_fn(|i| public[i])
        };
        let main = builder.main();
        let local: &Blake3Cols<AB::Var> = main.current_slice().borrow();

        // The message is the packed key: bits past N are the block's padding.
        for bit in N..BLOCK_BITS {
            builder.assert_zero(local.inputs[bit / 32][bit % 32]);
        }

        // The compression is the one `derive_key(DOMAIN_SEPARATOR)` performs on a
        // single block: keyed by the context key, counter zero, the packed
        // length, and the root-block flags of key material.
        for (word, &value) in self.context_key.iter().enumerate() {
            assert_word(builder, &local.chaining_values[word / 4][word % 4], value);
        }
        assert_word(builder, &local.counter_low, 0);
        assert_word(builder, &local.counter_hi, 0);
        assert_word(builder, &local.block_len, PACKED_KEY_BYTES as u32);
        assert_word(builder, &local.flags, FLAGS);

        // The digest is pk. Output words 0..4 sit in outputs[0] and 4..8 in
        // outputs[1], as 32 bits each; pk comes as 16-bit limbs.
        for word in 0..8 {
            let bits = &local.outputs[word / 4][word % 4];
            let low: AB::Expr = pack_bits_le(bits[..16].iter().copied());
            let high: AB::Expr = pack_bits_le(bits[16..].iter().copied());
            builder.assert_eq(low, pk[2 * word]);
            builder.assert_eq(high, pk[2 * word + 1]);
        }
    }
}
