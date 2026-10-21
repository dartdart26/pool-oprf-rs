//! Constraint (K) on Plonky3:
//!
//! ```text
//! pk = Commit(Domain::Key, sk),   each sk_i in {0, 1}
//! ```
//!
//! One row holds all of (K) and every row is the same. Domain, values and
//! rest are Poseidon2's input.
//!
//! | row      | key (`n`)          | domain (1)    | values (`PACKED_KEY_ELEMENTS`) | rest  | rounds      |
//! |----------|--------------------|---------------|--------------------------------|-------|-------------|
//! | `0`      | `sk_0 .. sk_{n-1}` | `Domain::Key` | `sk`, packed                   | zeros | end in `pk` |
//! | `1`      | `sk_0 .. sk_{n-1}` | `Domain::Key` | `sk`, packed                   | zeros | end in `pk` |
//! | …        | …                  | …             | …                              | …     | …           |
//! | `ROWS-1` | `sk_0 .. sk_{n-1}` | `Domain::Key` | `sk`, packed                   | zeros | end in `pk` |
//!
//! Plonky3 checks Poseidon2's rounds itself. We add these rules for (K):
//!
//! - every key bit is 0 or 1
//! - the inputs are `Domain::Key`, the key bits packed lowest first, then zeros
//! - the rounds end in `pk`

use crate::plonky3::commitments::key::{KeyCommitment, PACKED_KEY_ELEMENTS, elements, pack_key};
use crate::plonky3::commitments::{BITS_PER_ELEMENT, DIGEST_ELEMENTS};
use crate::plonky3::constraints::common::KEY_BITS;
use crate::plonky3::sponge::{WIDE, Wide};
use crate::plonky3::{ROWS, Val};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::prf::SecretKey;

/// Where each part of the row starts, after the key bits. Poseidon2's input
/// is the domain, the packed key, then zeros.
const SPONGE: usize = KEY_BITS;
const PACKED_KEY: usize = SPONGE + 1;
pub(crate) const NUM_COLS: usize = SPONGE + Wide::COLS;

/// The rules for (K). Its public value is `pk`.
#[derive(Default)]
pub struct KeyAir;

impl KeyAir {
    /// The row for `sk`.
    pub fn row(sk: &SecretKey) -> Vec<Val> {
        let packed = pack_key(sk);
        let bits = sk.as_bits().iter().map(|&bit| Val::from_bool(bit == 1));
        let hash = WIDE.trace(KeyCommitment::input(elements(&packed)));
        bits.chain(hash).collect()
    }

    /// The table for `sk` - `ROWS` copies of the row.
    pub fn trace(sk: &SecretKey) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(Self::row(sk).repeat(ROWS), NUM_COLS)
    }

    /// The rules for (K) on the row, for `pk`.
    pub fn rules<AB: AirBuilder<F = Val>>(builder: &mut AB, pk: [AB::Expr; DIGEST_ELEMENTS]) {
        let main = builder.main();
        let row = main.current_slice();
        let bits = &row[..KEY_BITS];

        // Every key bit is 0 or 1.
        for &bit in bits {
            builder.assert_bool(bit);
        }

        // Poseidon2's input is the key bits, packed.
        for index in 0..PACKED_KEY_ELEMENTS {
            builder.assert_eq(row[PACKED_KEY + index], packed::<AB>(bits, index));
        }
        let domain = KeyCommitment::domain();
        WIDE.eval_commitment(builder, SPONGE, domain, PACKED_KEY_ELEMENTS, pk);
    }
}

impl BaseAir<Val> for KeyAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds all of (K), so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        WIDE.max_constraint_degree()
    }

    fn num_public_values(&self) -> usize {
        DIGEST_ELEMENTS
    }
}

/// Takes the key's bit columns and returns element `index` of the packed
/// key. Works in the same way as `pack_key`.
fn packed<AB: AirBuilder>(bits: &[AB::Var], index: usize) -> AB::Expr {
    let element = bits
        .chunks(BITS_PER_ELEMENT)
        .nth(index)
        .expect("an element's bits");
    element
        .iter()
        .enumerate()
        .map(|(position, &bit)| bit * AB::F::from_u32(1 << position))
        .sum()
}

impl<AB: AirBuilder<F = Val>> Air<AB> for KeyAir {
    fn eval(&self, builder: &mut AB) {
        let pk: [AB::PublicVar; DIGEST_ELEMENTS] = builder.public_values().try_into().expect("pk");
        Self::rules(builder, pk.map(Into::into));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::key::commit;
    use crate::plonky3::sponge::output;
    use p3_air::check_all_constraints;
    use p3_matrix::Matrix;
    use pool_prf::params::N;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn the_trace_ends_in_the_commitment() {
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(1));
        let trace = KeyAir::trace(&sk);
        let row = trace.row_slice(0).expect("a row");
        assert_eq!(
            output(WIDE.permutation(&row[SPONGE..]))[..DIGEST_ELEMENTS],
            commit(&sk).0
        );
    }

    #[test]
    fn a_key_bit_that_is_not_a_bit_is_refused() {
        let mut bits = [0; N];
        bits[1] = 1;
        let sk = SecretKey::from_bits(bits).expect("a key");
        let pk = commit(&sk);

        let mut trace = KeyAir::trace(&sk);
        assert!(check_all_constraints(&KeyAir, &trace, &pk.0, None).is_ok());
        for row in trace.values.chunks_mut(NUM_COLS) {
            row[0] = Val::TWO;
            row[1] = Val::ZERO;
        }
        let failures = check_all_constraints(&KeyAir, &trace, &pk.0, None).failures;
        assert!(!failures.is_empty());
        assert!(
            failures.iter().all(|failure| failure.constraint == 0),
            "{failures:?}"
        );
    }
}
