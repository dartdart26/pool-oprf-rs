//! Constraint (M) on Plonky3: `r̃_Σ` opens `m` and `r̃_Σ` is in `ℤ_q`.
//!
//! # Layout
//!
//! One row holds all of (M). Its columns, in order:
//!
//! | columns               | content                                              |
//! |-----------------------|------------------------------------------------------|
//! | `LOG_Q`               | the bits of `r̃_Σ`, lowest first                      |
//! | `RANDOMNESS_ELEMENTS` | the random value                                     |
//! | the rest              | Poseidon2's columns                                  |
//!
//! # 1. `r̃_Σ` in `ℤ_q`
//!
//! `r̃_Σ` in `LOG_Q` bit columns forces it in `ℤ_q`.
//!
//! # 2. The hash
//!
//! In order, Poseidon2 takes `WIDTH` slots:
//!
//! | slots                 | content                                            |
//! |-----------------------|----------------------------------------------------|
//! | 1                     | the domain                                         |
//! | 1                     | `r̃_Σ`, its bit columns read as one number          |
//! | `RANDOMNESS_ELEMENTS` | the random value, one column per slot              |
//! | the rest              | zero                                               |
//!
//! No rule checks the random value. It is there to hide `r̃_Σ`, so a bad one
//! only harms the server.

use crate::CommitmentRandomness;
use crate::plonky3::commitments::mask_sum::{INPUT_ELEMENTS, MaskSumCommitment, elements};
use crate::plonky3::commitments::{DIGEST_ELEMENTS, RANDOMNESS_ELEMENTS, pack_randomness, pair};
use crate::plonky3::sponge::{
    PERMUTATION, PERMUTATION_COLS, eval_sponge, permutations, sponge_trace,
};
use crate::plonky3::{ROWS, Val};
use core::array;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::params::{LOG_Q, Zq};

const R_SIGMA_BITS: usize = LOG_Q as usize;
const PERMUTATIONS: usize = permutations(INPUT_ELEMENTS);

/// Where each part of the row starts.
pub(crate) const R_SIGMA: usize = 0;
pub(crate) const RANDOMNESS: usize = R_SIGMA + R_SIGMA_BITS;
const SPONGE: usize = RANDOMNESS + RANDOMNESS_ELEMENTS;
pub(crate) const NUM_COLS: usize = SPONGE + PERMUTATIONS * PERMUTATION_COLS;

/// The rules for (M).
pub struct MaskSumAir;

impl MaskSumAir {
    pub fn trace(r_sigma_sum: Zq, randomness: CommitmentRandomness) -> RowMajorMatrix<Val> {
        let bits = (0..R_SIGMA_BITS).map(|k| Val::from_int((r_sigma_sum >> k) & 1));
        let hash = sponge_trace(MaskSumCommitment::input(elements(r_sigma_sum, randomness)));
        let row: Vec<Val> = bits
            .chain(pack_randomness(randomness))
            .chain(hash)
            .collect();
        RowMajorMatrix::new(row.repeat(ROWS), NUM_COLS)
    }
}

impl BaseAir<Val> for MaskSumAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds all of (M), so no rule reads the next row.
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

impl<AB: AirBuilder<F = Val>> Air<AB> for MaskSumAir {
    fn eval(&self, builder: &mut AB) {
        let m: [AB::PublicVar; DIGEST_ELEMENTS] = builder.public_values().try_into().expect("m");
        let main = builder.main();
        let row = main.current_slice();
        let bits = &row[R_SIGMA..RANDOMNESS];

        // 1. r̃_Σ in ℤ_q
        for &bit in bits {
            builder.assert_bool(bit);
        }

        // 2. The hash
        let r_sigma_sum = pack_bits_le::<AB::Expr, _, _>(bits.iter().copied());
        let randomness = array::from_fn(|k| row[RANDOMNESS + k].into());
        let input = MaskSumCommitment::input(pair(r_sigma_sum, randomness));
        eval_sponge(builder, SPONGE, input, m);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::mask_sum::commit;
    use crate::plonky3::sponge::{last_run, output};
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use pool_prf::params::Q;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// A random pair, from `seed`.
    fn random(seed: u64) -> (Zq, CommitmentRandomness) {
        let mut rng = StdRng::seed_from_u64(seed);
        (rng.random_range(0..Q), rng.random())
    }

    #[test]
    fn the_trace_ends_in_the_commitment() {
        let (r_sigma_sum, randomness) = random(1);
        let trace = MaskSumAir::trace(r_sigma_sum, randomness);
        let row = trace.row_slice(0).expect("a row");
        assert_eq!(
            output(last_run(&row[SPONGE..]))[..DIGEST_ELEMENTS],
            commit(r_sigma_sum, randomness).0
        );
    }

    #[test]
    fn the_rules_hold() {
        let (r_sigma_sum, randomness) = random(2);
        let trace = MaskSumAir::trace(r_sigma_sum, randomness);
        let m = commit(r_sigma_sum, randomness);
        assert!(check_all_constraints(&MaskSumAir, &trace, &m.0, None).is_ok());
    }

    #[test]
    fn another_random_value_is_refused() {
        let (r_sigma_sum, randomness) = random(3);
        let trace = MaskSumAir::trace(r_sigma_sum, randomness);
        let m = commit(r_sigma_sum, randomness ^ 1);
        assert!(!check_all_constraints(&MaskSumAir, &trace, &m.0, None).is_ok());
    }

    /// Bits 2 and 0 read as the same number as bits 0 and 1, so the hash
    /// still ends in `m` and only the bit rule refuses it.
    #[test]
    fn an_r_sigma_sum_bit_that_is_not_a_bit_is_refused() {
        let (_, randomness) = random(4);
        let r_sigma_sum = 2;
        let m = commit(r_sigma_sum, randomness);

        let mut trace = MaskSumAir::trace(r_sigma_sum, randomness);
        assert!(check_all_constraints(&MaskSumAir, &trace, &m.0, None).is_ok());
        for row in trace.values.chunks_mut(NUM_COLS) {
            row[R_SIGMA] = Val::TWO;
            row[R_SIGMA + 1] = Val::ZERO;
        }
        let failures = check_all_constraints(&MaskSumAir, &trace, &m.0, None).failures;
        assert!(!failures.is_empty());
        assert!(
            failures.iter().all(|failure| failure.constraint == 0),
            "{failures:?}"
        );
    }
}
