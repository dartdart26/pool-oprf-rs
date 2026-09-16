//! BLAKE3's compression function.
//!
//! Plonky3 does not run BLAKE3. It checks a BLAKE3 computation that has
//! been written out in full: the input, every intermediate value, and the
//! output. This file runs the compression and writes all of that out in the
//! layout Plonky3 expects.
//!
//! One compression only, so messages of at most one block (64 bytes). Every
//! parameter set of the Pool paper packs its key into fewer.
//!
//! Not security critical, because the verifier checks the row against
//! Plonky3's BLAKE3 constraints, not against this code, so a mistake here
//! yields a proof that fails, not one that verifies.
//!
//! This file has been mostly AI-generated. It relies on not being security
//! critical and on the `a_filled_row_hashes_like_the_blake3_crate()` test.

use crate::plonky3::Val;
use core::array;
use p3_air::utils::u32_to_bits_le;
use p3_blake3_air::{Blake3Cols, Blake3State};
use p3_field::PrimeCharacteristicRing;

// No constants for these in blake3 - copy them here and add tests in this file to verify they are correct.
pub(crate) const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub(crate) const CHUNK_START: u32 = 1 << 0;
pub(crate) const CHUNK_END: u32 = 1 << 1;
pub(crate) const ROOT: u32 = 1 << 3;
pub(crate) const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

pub(crate) const BLOCK_BYTES: usize = blake3::BLOCK_LEN;
pub(crate) const BLOCK_WORDS: usize = BLOCK_BYTES / size_of::<u32>();

/// A block from at most 64 bytes, zero-padded, as little-endian words.
pub(crate) fn block_from_bytes(bytes: &[u8]) -> [u32; BLOCK_WORDS] {
    assert!(bytes.len() <= BLOCK_BYTES, "a block is at most 64 bytes");
    let mut padded = [0u8; BLOCK_BYTES];
    padded[..bytes.len()].copy_from_slice(bytes);
    array::from_fn(|i| {
        u32::from_le_bytes([
            padded[4 * i],
            padded[4 * i + 1],
            padded[4 * i + 2],
            padded[4 * i + 3],
        ])
    })
}

/// The flags of the one compression that hashes a message of at most 64
/// bytes.
pub(crate) const fn single_block_flags(mode: u32) -> u32 {
    CHUNK_START | CHUNK_END | ROOT | mode
}

/// The key `derive_key(context)` hashes with, as words.
pub(crate) fn context_key(context: &str) -> [u32; 8] {
    let key = blake3::hazmat::hash_derive_key_context(context);
    array::from_fn(|i| {
        u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
    })
}

/// The state of a compression: `state[r][i]` is word `4r + i`, so the rows
/// are `v[0..4]`, `v[4..8]`, `v[8..12]` and `v[12..16]`. This is how the AIR
/// stores it.
type State = [[u32; 4]; 4];

fn initial_state(cv: &[u32; 8], counter: u64, block_len: u32, flags: u32) -> State {
    [
        [cv[0], cv[1], cv[2], cv[3]],
        [cv[4], cv[5], cv[6], cv[7]],
        [IV[0], IV[1], IV[2], IV[3]],
        [counter as u32, (counter >> 32) as u32, block_len, flags],
    ]
}

const fn half_g(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    m: u32,
    second: bool,
) -> (u32, u32, u32, u32) {
    let (rot_d, rot_b) = if second { (8, 7) } else { (16, 12) };
    a = a.wrapping_add(b).wrapping_add(m);
    d = (d ^ a).rotate_right(rot_d);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(rot_b);
    (a, b, c, d)
}

fn column_half(s: &mut State, m: &[u32; BLOCK_WORDS], second: bool) {
    for i in 0..4 {
        (s[0][i], s[1][i], s[2][i], s[3][i]) = half_g(
            s[0][i],
            s[1][i],
            s[2][i],
            s[3][i],
            m[2 * i + usize::from(second)],
            second,
        );
    }
}

fn diagonal_half(s: &mut State, m: &[u32; BLOCK_WORDS], second: bool) {
    for i in 0..4 {
        let (b, c, d) = ((i + 1) % 4, (i + 2) % 4, (i + 3) % 4);
        (s[0][i], s[1][b], s[2][c], s[3][d]) = half_g(
            s[0][i],
            s[1][b],
            s[2][c],
            s[3][d],
            m[8 + 2 * i + usize::from(second)],
            second,
        );
    }
}

fn permute(m: &mut [u32; BLOCK_WORDS]) {
    *m = array::from_fn(|i| m[MSG_PERMUTATION[i]]);
}

fn digest(s: &State) -> [u32; 8] {
    array::from_fn(|i| {
        if i < 4 {
            s[0][i] ^ s[2][i]
        } else {
            s[1][i - 4] ^ s[3][i - 4]
        }
    })
}

fn limbs(word: u32) -> [Val; 2] {
    [
        Val::from_u16(word as u16),
        Val::from_u16((word >> 16) as u16),
    ]
}

fn save(into: &mut Blake3State<Val>, s: &State) {
    into.row0 = array::from_fn(|i| limbs(s[0][i]));
    into.row1 = array::from_fn(|i| u32_to_bits_le(s[1][i]));
    into.row2 = array::from_fn(|i| limbs(s[2][i]));
    into.row3 = array::from_fn(|i| u32_to_bits_le(s[3][i]));
}

/// Fill one trace row of the BLAKE3 AIR with this compression and return
/// its digest.
pub(crate) fn fill_row(
    row: &mut Blake3Cols<Val>,
    cv: &[u32; 8],
    block: &[u32; BLOCK_WORDS],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 8] {
    row.inputs = array::from_fn(|i| u32_to_bits_le(block[i]));
    row.chaining_values =
        array::from_fn(|half| array::from_fn(|i| u32_to_bits_le(cv[4 * half + i])));
    row.counter_low = u32_to_bits_le(counter as u32);
    row.counter_hi = u32_to_bits_le((counter >> 32) as u32);
    row.block_len = u32_to_bits_le(block_len);
    row.flags = u32_to_bits_le(flags);
    row.initial_row0 = array::from_fn(|i| limbs(cv[i]));
    row.initial_row2 = array::from_fn(|i| limbs(IV[i]));

    let mut s = initial_state(cv, counter, block_len, flags);
    let mut m = *block;
    for round in 0..7 {
        let cols = &mut row.full_rounds[round];
        column_half(&mut s, &m, false);
        save(&mut cols.state_prime, &s);
        column_half(&mut s, &m, true);
        save(&mut cols.state_middle, &s);
        diagonal_half(&mut s, &m, false);
        save(&mut cols.state_middle_prime, &s);
        diagonal_half(&mut s, &m, true);
        save(&mut cols.state_output, &s);
        if round < 6 {
            permute(&mut m);
        }
    }

    row.final_round_helpers = array::from_fn(|i| u32_to_bits_le(s[2][i]));
    row.outputs[0] = array::from_fn(|i| u32_to_bits_le(s[0][i] ^ s[2][i]));
    row.outputs[1] = array::from_fn(|i| u32_to_bits_le(s[1][i] ^ s[3][i]));
    row.outputs[2] = array::from_fn(|i| u32_to_bits_le(s[2][i] ^ cv[i]));
    row.outputs[3] = array::from_fn(|i| u32_to_bits_le(s[3][i] ^ cv[4 + i]));
    digest(&s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::borrow::BorrowMut;
    use p3_blake3_air::NUM_BLAKE3_COLS;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// The digest of a single-block message through our row filler.
    fn row_digest(cv: &[u32; 8], message: &[u8], flags: u32) -> [u8; 32] {
        let mut values = Val::zero_vec(NUM_BLAKE3_COLS);
        let row: &mut Blake3Cols<Val> = values[..].borrow_mut();
        let words = fill_row(
            row,
            cv,
            &block_from_bytes(message),
            0,
            message.len() as u32,
            flags,
        );
        let mut digest = [0u8; 32];
        for (out, word) in digest.chunks_exact_mut(4).zip(words) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    #[test]
    fn a_filled_row_hashes_like_the_blake3_crate() {
        let mut rng = StdRng::seed_from_u64(1);
        let context = "pool-voprf test context";
        let cv = context_key(context);
        for len in [0usize, 1, 31, 32, 61, 63, 64] {
            let mut message = vec![0u8; len];
            rng.fill(&mut message[..]);
            let expected = blake3::Hasher::new_derive_key(context)
                .update(&message)
                .finalize();
            assert_eq!(
                row_digest(&cv, &message, single_block_flags(DERIVE_KEY_MATERIAL)),
                *expected.as_bytes(),
                "len {len}"
            );
        }
    }
}
