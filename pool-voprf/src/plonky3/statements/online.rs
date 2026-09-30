//! The online statement on Plonky3. Its constraints are (K), (A), (R), (M)
//! and (P).
//!
//! # Layout
//!
//! One row holds the whole statement. Its columns, in order:
//!
//! | columns              | content            |
//! |----------------------|--------------------|
//! | `key::NUM_COLS`      | the columns of (K) |
//! | `mask_sum::NUM_COLS` | the columns of (M) |
//! | `sum::NUM_COLS`      | the columns of (A) |
//! | `response::NUM_COLS` | the columns of (R) |
//!
//! The public values are in the same order: `pk`, `m`, `e`, `y`.
//!
//! # 1. the constraints
//!
//! Each constraint checks its own columns against its own public values,
//! with its own rules.
//!
//! # 2. the values they share
//!
//! Some constraints share a value. Each keeps it in its own columns, so a
//! rule makes the copies equal:
//!
//! | value | held by                  | and by                   |
//! |-------|--------------------------|--------------------------|
//! | `sk`  | (K), as bits             | (A), as bits             |
//! | `r̃_Σ` | (M), as bits             | (A), one column          |
//! | `ã_Σ` | (A), as bits             | (R), one column          |
//! | pads  | (P), one column per `j`  | (R), one column per `j`  |

use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
use crate::plonky3::constraints::{key, mask_sum, response, sum};
use crate::plonky3::statements::sub_air::eval_sub_air;
use crate::plonky3::{
    KeyAir, MaskSumAir, Plonky3, Proof, ProveError, ROWS, ResponseAir, SumAir, Val, VerifyError,
};
use crate::statements::online::{OnlineStatement, OnlineWitness};
use crate::traits::{ProofSystem, Statement};
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use pool_prf::params::{DELTA, N};

type Online = OnlineStatement<KeyCommitment, MaskSumCommitment>;

/// Where the columns of each constraint start.
const KEY: usize = 0;
const MASK_SUM: usize = KEY + key::NUM_COLS;
const SUM: usize = MASK_SUM + mask_sum::NUM_COLS;
const RESPONSE: usize = SUM + sum::NUM_COLS;
const NUM_COLS: usize = RESPONSE + response::NUM_COLS;

/// Where the public values of each constraint start.
const PK: usize = 0;
const M: usize = PK + DIGEST_ELEMENTS;
const E: usize = M + DIGEST_ELEMENTS;
const Y: usize = E + N;
const NUM_PUBLIC_VALUES: usize = Y + DELTA;

/// The row of each constraint side by side, `ROWS` times. Each table is
/// `ROWS` copies of its row.
fn side_by_side(
    key: &RowMajorMatrix<Val>,
    mask_sum: &RowMajorMatrix<Val>,
    sum: &RowMajorMatrix<Val>,
    response: &RowMajorMatrix<Val>,
) -> RowMajorMatrix<Val> {
    let row = [
        &key.values[..key::NUM_COLS],
        &mask_sum.values[..mask_sum::NUM_COLS],
        &sum.values[..sum::NUM_COLS],
        &response.values[..response::NUM_COLS],
    ]
    .concat();
    RowMajorMatrix::new(row.repeat(ROWS), NUM_COLS)
}

// TODO: (P).
struct OnlineAir;

impl OnlineAir {
    fn trace(statement: &Online, witness: &OnlineWitness) -> RowMajorMatrix<Val> {
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &statement.e);
        side_by_side(
            &KeyAir::trace(&witness.sk),
            &MaskSumAir::trace(witness.r_sigma_sum, witness.m_randomness),
            &SumAir::trace(&witness.sk, witness.r_sigma_sum, &statement.e),
            &ResponseAir::trace(a_sigma_sum, &witness.pads, statement.b_bar_prime),
        )
    }
}

impl BaseAir<Val> for OnlineAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds the whole statement, so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for OnlineAir {
    fn eval(&self, builder: &mut AB) {
        // 1. the constraints
        eval_sub_air(builder, &KeyAir, KEY..MASK_SUM, PK..M);
        eval_sub_air(builder, &MaskSumAir, MASK_SUM..SUM, M..E);
        eval_sub_air(builder, &SumAir, SUM..RESPONSE, E..Y);
        eval_sub_air(
            builder,
            &ResponseAir,
            RESPONSE..NUM_COLS,
            Y..NUM_PUBLIC_VALUES,
        );

        // 2. the values they share
        let main = builder.main();
        let row = main.current_slice();
        let key_columns = &row[KEY..MASK_SUM];
        let mask_sum_columns = &row[MASK_SUM..SUM];
        let sum_columns = &row[SUM..RESPONSE];
        let response_columns = &row[RESPONSE..NUM_COLS];

        // The key bits are the first columns of (K) and of (A).
        let key_sk = &key_columns[..N];
        let sum_sk = &sum_columns[sum::SK..sum::R_SIGMA];
        for (&key_bit, &sum_bit) in key_sk.iter().zip(sum_sk) {
            builder.assert_eq(sum_bit, key_bit);
        }

        // `r̃_Σ` is one column in (A) and bits in (M).
        let r_sigma_bits = &mask_sum_columns[mask_sum::R_SIGMA..mask_sum::RANDOMNESS];
        let r_sigma_sum = pack_bits_le::<AB::Expr, _, _>(r_sigma_bits.iter().copied());
        builder.assert_eq(sum_columns[sum::R_SIGMA], r_sigma_sum);

        // `ã_Σ` is bits in (A) and the first column of (R).
        let a_sigma_bits = &sum_columns[sum::A_SIGMA..sum::QUOTIENT];
        let a_sigma_sum = pack_bits_le::<AB::Expr, _, _>(a_sigma_bits.iter().copied());
        builder.assert_eq(response_columns[0], a_sigma_sum);
    }
}

fn public_values(statement: &Online) -> Vec<Val> {
    let mut values = statement.pk.0.to_vec();
    values.extend(statement.m.0);
    values.extend(sum::public_values(&statement.e));
    values.extend(response::public_values(&statement.y));
    values
}

impl ProofSystem<Online> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(&self, statement: &Online, witness: &OnlineWitness) -> Result<Proof, ProveError> {
        if !statement.holds_for(witness) {
            return Err(ProveError::WrongWitness);
        }
        let trace = OnlineAir::trace(statement, witness);
        prove(&self.config, &OnlineAir, trace, &public_values(statement))
            .map_err(ProveError::Prover)
    }

    fn verify(&self, statement: &Online, proof: &Proof) -> Result<(), VerifyError> {
        Plonky3::verified(|| verify(&self.config, &OnlineAir, proof, &public_values(statement)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;
    use p3_air::{ConstraintReport, check_all_constraints};
    use pool_prf::modular::reduce_q;
    use pool_prf::params::{Q, Zdelta, ZqAccum};
    use pool_prf::prf::SecretKey;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// A random witness and the honest statement for it, from `seed`.
    fn random(seed: u64) -> (Online, OnlineWitness) {
        let mut rng = StdRng::seed_from_u64(seed);
        let witness = OnlineWitness {
            sk: SecretKey::random(&mut rng),
            r_sigma_sum: rng.random_range(0..Q),
            m_randomness: rng.random(),
            pads: rng.random(),
        };
        let e = array::from_fn(|_| rng.random_range(0..Q));
        let b_bar_prime = rng.random_range(0..DELTA as Zdelta);
        (
            OnlineStatement::for_witness(&witness, e, b_bar_prime),
            witness,
        )
    }

    /// Runs the rules over `trace` for `statement`.
    fn report(trace: &RowMajorMatrix<Val>, statement: &Online) -> ConstraintReport {
        check_all_constraints(&OnlineAir, trace, &public_values(statement), None)
    }

    fn each_holds_alone(
        key: &RowMajorMatrix<Val>,
        mask_sum: &RowMajorMatrix<Val>,
        sum: &RowMajorMatrix<Val>,
        response: &RowMajorMatrix<Val>,
        statement: &Online,
    ) -> bool {
        let e = sum::public_values(&statement.e);
        let y = response::public_values(&statement.y);
        check_all_constraints(&KeyAir, key, &statement.pk.0, None).is_ok()
            && check_all_constraints(&MaskSumAir, mask_sum, &statement.m.0, None).is_ok()
            && check_all_constraints(&SumAir, sum, &e, None).is_ok()
            && check_all_constraints(&ResponseAir, response, &y, None).is_ok()
    }

    #[test]
    fn the_rules_hold() {
        let (statement, witness) = random(1);
        let trace = OnlineAir::trace(&statement, &witness);
        assert!(report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties the key bits refuses it.
    #[test]
    fn a_sum_with_another_key_is_refused() {
        let (statement, witness) = random(2);
        let other = SecretKey::random(&mut StdRng::seed_from_u64(3));
        let a_sigma_sum = pool_eval::a_sigma_sum(&other, witness.r_sigma_sum, &statement.e);
        let y = pool_eval::respond(a_sigma_sum, &witness.pads, statement.b_bar_prime);
        let statement = OnlineStatement { y, ..statement };

        let key = KeyAir::trace(&witness.sk);
        let mask_sum = MaskSumAir::trace(witness.r_sigma_sum, witness.m_randomness);
        let sum = SumAir::trace(&other, witness.r_sigma_sum, &statement.e);
        let response = ResponseAir::trace(a_sigma_sum, &witness.pads, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &statement
        ));

        // Together they do not.
        let trace = side_by_side(&key, &mask_sum, &sum, &response);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties `r̃_Σ` refuses it.
    #[test]
    fn a_sum_with_another_r_sigma_sum_is_refused() {
        let (statement, witness) = random(4);
        let other = reduce_q(ZqAccum::from(witness.r_sigma_sum) + 1);
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, other, &statement.e);
        let y = pool_eval::respond(a_sigma_sum, &witness.pads, statement.b_bar_prime);
        let statement = OnlineStatement { y, ..statement };

        let key = KeyAir::trace(&witness.sk);
        let mask_sum = MaskSumAir::trace(witness.r_sigma_sum, witness.m_randomness);
        let sum = SumAir::trace(&witness.sk, other, &statement.e);
        let response = ResponseAir::trace(a_sigma_sum, &witness.pads, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &statement
        ));

        // Together they do not.
        let trace = side_by_side(&key, &mask_sum, &sum, &response);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties `ã_Σ` refuses it.
    #[test]
    fn a_response_from_another_a_sigma_sum_is_refused() {
        let (statement, witness) = random(5);
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &statement.e);
        let other = reduce_q(ZqAccum::from(a_sigma_sum) + 1);
        let y = pool_eval::respond(other, &witness.pads, statement.b_bar_prime);
        let statement = OnlineStatement { y, ..statement };

        let key = KeyAir::trace(&witness.sk);
        let mask_sum = MaskSumAir::trace(witness.r_sigma_sum, witness.m_randomness);
        let sum = SumAir::trace(&witness.sk, witness.r_sigma_sum, &statement.e);
        let response = ResponseAir::trace(other, &witness.pads, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &statement
        ));

        // Together they do not.
        let trace = side_by_side(&key, &mask_sum, &sum, &response);
        assert!(!report(&trace, &statement).is_ok());
    }
}
