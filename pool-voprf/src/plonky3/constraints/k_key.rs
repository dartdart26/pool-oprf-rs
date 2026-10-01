//! Constraint (K) on Plonky3.
//!
//! In order, Poseidon2 takes `WIDTH` slots:
//!
//! | slots                 | content                                   |
//! |-----------------------|-------------------------------------------|
//! | 1                     | the domain                                |
//! | `PACKED_KEY_ELEMENTS` | the key, `BITS_PER_ELEMENT` bits per slot |
//! | the rest              | zero                                      |
//!
//! The rest is the `CAPACITY` slots, which never take input, plus the
//! input slots the key does not fill.
//!
//! Plonky3 checks Poseidon2 itself. We add these rules for (K):
//!
//! - every key bit is 0 or 1
//! - Poseidon2's input is what `commit` gives it: the domain, the key bits
//!   read as numbers, and zeros in the other slots
//! - the first `DIGEST_ELEMENTS` of Poseidon2's output are `pk`, which the
//!   verifier supplies

use crate::plonky3::commitments::key::{
    INPUT_ELEMENTS, KeyCommitment, PACKED_KEY_ELEMENTS, elements, pack_key,
};
use crate::plonky3::commitments::{BITS_PER_ELEMENT, DIGEST_ELEMENTS};
use crate::plonky3::sponge::{
    PERMUTATION, PERMUTATION_COLS, eval_sponge, permutations, sponge_trace,
};
use crate::plonky3::{ROWS, Val};
use core::array;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::params::N;
use pool_prf::prf::SecretKey;

// The row, `NUM_COLS` wide. `ROWS` of them, all containing the same values:
//
// | columns             | content                                             |
// |---------------------|-----------------------------------------------------|
// | `N`                 | the key bits, one per column                        |
// | `WIDTH`             | Poseidon2's input: the domain, the key bits, then   |
// |                     | zeros                                               |
// | the rest of the run | Poseidon2's rounds: the helper values and the state |
// |                     | after each round. The last state starts with `pk`   |
//
// The input and the rounds are one run, `PERMUTATION_COLS` together, and
// there are `PERMUTATIONS` runs.
const PERMUTATIONS: usize = permutations(INPUT_ELEMENTS);
pub(crate) const NUM_COLS: usize = N + PERMUTATIONS * PERMUTATION_COLS;

/// The rules for (K). Its public value is `pk`.
#[derive(Default)]
pub struct KeyAir;

impl KeyAir {
    /// The table for `sk` - `ROWS` copies of the row.
    pub fn trace(sk: &SecretKey) -> RowMajorMatrix<Val> {
        let packed = pack_key(sk);
        let bits = sk.as_bits().iter().map(|&bit| Val::from_bool(bit == 1));
        let hash = sponge_trace(KeyCommitment::input(elements(&packed)));
        let row: Vec<Val> = bits.chain(hash).collect();
        RowMajorMatrix::new(row.repeat(ROWS), NUM_COLS)
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
        PERMUTATION.max_constraint_degree()
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
        let main = builder.main();
        let row = main.current_slice();
        let bits = &row[..N];

        // Every key bit is 0 or 1.
        for &bit in bits {
            builder.assert_bool(bit);
        }

        // Poseidon2 over the domain and the key bits ends in pk.
        let elements: [AB::Expr; PACKED_KEY_ELEMENTS] =
            array::from_fn(|index| packed::<AB>(bits, index));
        eval_sponge(builder, N, KeyCommitment::input(elements), pk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::key::commit;
    use crate::plonky3::sponge::{last_run, output};
    use p3_air::check_all_constraints;
    use p3_matrix::Matrix;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn the_trace_ends_in_the_commitment() {
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(1));
        let trace = KeyAir::trace(&sk);
        let row = trace.row_slice(0).expect("a row");
        assert_eq!(
            output(last_run(&row[N..]))[..DIGEST_ELEMENTS],
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
