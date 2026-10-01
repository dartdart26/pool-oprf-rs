//! The online statement on Plonky3. Its constraints are (K), (A), (R), (M)
//! and (P).
//!
//! # Layout
//!
//! The columns of each constraint side by side, `ROWS` rows of them:
//!
//! | row      |     | (K)     | (M)     | (A)     | (R)     | (P)         |     | `s_0` | `s_1` | … | `s_{Δ-1}` |
//! |----------|-----|---------|---------|---------|---------|-------------|-----|-------|-------|---|-----------|
//! | `0`      | c   | its row | its row | its row | its row | entry `0`   | p   | 1     | 0     | … | 0         |
//! | `1`      | o   | same    | same    | same    | same    | entry `1`   | e   | 0     | 1     | … | 0         |
//! | `2`      | m   | same    | same    | same    | same    | entry `2`   | r   | 0     | 0     | … | 0         |
//! | …        | m   | …       | …       | …       | …       | …           | i   | …     | …     | … | …         |
//! | `Δ-1`    | i → | same    | same    | same    | same    | entry `Δ-1` | o → | 0     | 0     | … | 1         |
//! | `Δ`      | t   | same    | same    | same    | same    | entry `0`   | d   | 1     | 0     | … | 0         |
//! | `Δ+1`    | t   | same    | same    | same    | same    | entry `1`   | i   | 0     | 1     | … | 0         |
//! | …        | e   | …       | …       | …       | …       | …           | c   | …     | …     | … | …         |
//! | `2Δ-1`   | d   | same    | same    | same    | same    | entry `Δ-1` |     | 0     | 0     | … | 1         |
//! | …        |     | …       | …       | …       | …       | …           |     | …     | …     | … | …         |
//! | `ROWS-1` |     | same    | same    | same    | same    | entry `Δ-1` |     | 0     | 0     | … | 1         |
//!
//! (K), (M), (A) and (R) hold everything in one row and repeat it. (P)
//! holds one entry per row: entry `j` on row `j`, and again every `Δ`
//! rows. `s_j` is 1 on the rows of entry `j` and 0 on the others. The
//! `s_j` are not columns of the table: they are periodic, both sides
//! compute them, see [`p_pads`]. They belong to the circuit, not to a block
//! of the row. (P) declares them and is the only one that reads them.
//!
//! The public values are in the same order as their respective constraints.
//!
//! # 1. The constraints
//!
//! Each constraint checks its own columns against its own public values,
//! with its own rules, on every row.
//!
//! # 2. The values they share
//!
//! Some constraints share a value. Each keeps it in its own columns, so a
//! rule makes the copies equal.

use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::key::KeyCommitment;
use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
use crate::plonky3::commitments::pad::PadCommitment;
use crate::plonky3::constraints::{a_sum, k_key, m_mask_sum, p_pads, r_response};
use crate::plonky3::statements::sub_air::eval_sub_air;
use crate::plonky3::{
    KeyAir, MaskSumAir, PadsAir, Plonky3, Proof, ProveError, ROWS, ResponseAir, SumAir, Val,
    VerifyError,
};
use crate::statements::online::{OnlineStatement, OnlineWitness};
use crate::traits::{ProofSystem, Statement};
use core::array;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use pool_prf::params::{DELTA, N};
use std::borrow::Cow;

type Online = OnlineStatement<KeyCommitment, MaskSumCommitment, PadCommitment>;

/// Where the columns of each constraint start.
const KEY: usize = 0;
const MASK_SUM: usize = KEY + k_key::NUM_COLS;
const SUM: usize = MASK_SUM + m_mask_sum::NUM_COLS;
const RESPONSE: usize = SUM + a_sum::NUM_COLS;
const PADS: usize = RESPONSE + r_response::NUM_COLS;
const NUM_COLS: usize = PADS + p_pads::NUM_COLS;

/// Where the public values of each constraint start.
const PK: usize = 0;
const M: usize = PK + DIGEST_ELEMENTS;
const E: usize = M + DIGEST_ELEMENTS;
const Y: usize = E + N;
const D: usize = Y + DELTA;
const NUM_PUBLIC_VALUES: usize = D + p_pads::NUM_PUBLIC_VALUES;

/// The tables side by side: row `i` is row `i` of each, one after the
/// other. Each table has `ROWS` rows.
fn side_by_side(tables: [&RowMajorMatrix<Val>; 5]) -> RowMajorMatrix<Val> {
    let mut values = Vec::with_capacity(ROWS * NUM_COLS);
    for i in 0..ROWS {
        for table in tables {
            let row = table.row_slice(i).expect("a row");
            values.extend_from_slice(&row);
        }
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

struct OnlineAir;

impl OnlineAir {
    fn trace(statement: &Online, witness: &OnlineWitness) -> RowMajorMatrix<Val> {
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &statement.e);
        side_by_side([
            &KeyAir::trace(&witness.sk),
            &MaskSumAir::trace(witness.r_sigma_sum, witness.m_randomness),
            &SumAir::trace(&witness.sk, witness.r_sigma_sum, &statement.e),
            &ResponseAir::trace(a_sigma_sum, &witness.pads, statement.b_bar_prime),
            &PadsAir::trace(&witness.pads, &witness.d_randomness, statement.b_bar_prime),
        ])
    }
}

impl BaseAir<Val> for OnlineAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// No constraint reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    /// Only (P) has periodic columns.
    fn num_periodic_columns(&self) -> usize {
        PadsAir.num_periodic_columns()
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        PadsAir.periodic_columns()
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for OnlineAir {
    fn eval(&self, builder: &mut AB) {
        // 1. The constraints
        eval_sub_air(builder, &KeyAir, KEY..MASK_SUM, PK..M);
        eval_sub_air(builder, &MaskSumAir, MASK_SUM..SUM, M..E);
        eval_sub_air(builder, &SumAir, SUM..RESPONSE, E..Y);
        eval_sub_air(builder, &ResponseAir, RESPONSE..PADS, Y..D);
        eval_sub_air(builder, &PadsAir, PADS..NUM_COLS, D..NUM_PUBLIC_VALUES);

        // 2. The values they share
        let main = builder.main();
        let row = main.current_slice();
        let key_columns = &row[KEY..MASK_SUM];
        let mask_sum_columns = &row[MASK_SUM..SUM];
        let sum_columns = &row[SUM..RESPONSE];
        let response_columns = &row[RESPONSE..PADS];
        let pads_columns = &row[PADS..NUM_COLS];

        // The key bits are the first columns of (K) and of (A).
        let key_sk = &key_columns[..N];
        let sum_sk = &sum_columns[a_sum::SK..a_sum::R_SIGMA];
        for (&key_bit, &sum_bit) in key_sk.iter().zip(sum_sk) {
            builder.assert_eq(sum_bit, key_bit);
        }

        // `r̃_Σ` is one column in (A) and bits in (M).
        let r_sigma_bits = &mask_sum_columns[m_mask_sum::R_SIGMA..m_mask_sum::RANDOMNESS];
        let r_sigma_sum = pack_bits_le::<AB::Expr, _, _>(r_sigma_bits.iter().copied());
        builder.assert_eq(sum_columns[a_sum::R_SIGMA], r_sigma_sum);

        // `ã_Σ` is bits in (A) and the first column of (R).
        let a_sigma_bits = &sum_columns[a_sum::A_SIGMA..a_sum::QUOTIENT];
        let a_sigma_sum = pack_bits_le::<AB::Expr, _, _>(a_sigma_bits.iter().copied());
        builder.assert_eq(response_columns[0], a_sigma_sum);

        // (P) has one pad column: on the rows of entry `j` it holds `pad_j`.
        // (R) has Δ pad columns, `pad_0 .. pad_{Δ-1}`, the same on every row.
        // `s` picks `pad_j` out of (R)'s Δ, and it must equal (P)'s.
        let s: [AB::PeriodicVar; DELTA] = builder.periodic_values().try_into().expect("s_j");
        let pad_of_p = pads_columns[p_pads::PAD];
        let pads_of_r = array::from_fn(|j| response_columns[r_response::pad_column(j)].into());
        let pad_of_r = p_pads::select::<AB>(&s, pads_of_r);
        builder.assert_eq(pad_of_p, pad_of_r);
    }
}

fn public_values(statement: &Online) -> Vec<Val> {
    let mut values = statement.pk.0.to_vec();
    values.extend(statement.m.0);
    values.extend(a_sum::public_values(&statement.e));
    values.extend(r_response::public_values(&statement.y));
    values.extend(p_pads::public_values(&statement.d, statement.b_bar_prime));
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
            d_randomness: rng.random(),
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
        pads: &RowMajorMatrix<Val>,
        statement: &Online,
    ) -> bool {
        let e = a_sum::public_values(&statement.e);
        let y = r_response::public_values(&statement.y);
        let d = p_pads::public_values(&statement.d, statement.b_bar_prime);
        check_all_constraints(&KeyAir, key, &statement.pk.0, None).is_ok()
            && check_all_constraints(&MaskSumAir, mask_sum, &statement.m.0, None).is_ok()
            && check_all_constraints(&SumAir, sum, &e, None).is_ok()
            && check_all_constraints(&ResponseAir, response, &y, None).is_ok()
            && check_all_constraints(&PadsAir, pads, &d, None).is_ok()
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
        let pads = PadsAir::trace(&witness.pads, &witness.d_randomness, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &pads, &statement
        ));

        // Together they do not.
        let trace = side_by_side([&key, &mask_sum, &sum, &response, &pads]);
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
        let pads = PadsAir::trace(&witness.pads, &witness.d_randomness, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &pads, &statement
        ));

        // Together they do not.
        let trace = side_by_side([&key, &mask_sum, &sum, &response, &pads]);
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
        let pads = PadsAir::trace(&witness.pads, &witness.d_randomness, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &pads, &statement
        ));

        // Together they do not.
        let trace = side_by_side([&key, &mask_sum, &sum, &response, &pads]);
        assert!(!report(&trace, &statement).is_ok());
    }

    /// Each constraint holds on its own columns, so only the rule that ties the pads refuses it.
    #[test]
    fn a_response_with_other_pads_is_refused() {
        let (statement, witness) = random(6);
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &statement.e);
        let mut other = witness.pads;
        other[0] ^= 1;
        let y = pool_eval::respond(a_sigma_sum, &other, statement.b_bar_prime);
        let statement = OnlineStatement { y, ..statement };

        let key = KeyAir::trace(&witness.sk);
        let mask_sum = MaskSumAir::trace(witness.r_sigma_sum, witness.m_randomness);
        let sum = SumAir::trace(&witness.sk, witness.r_sigma_sum, &statement.e);
        let response = ResponseAir::trace(a_sigma_sum, &other, statement.b_bar_prime);
        let pads = PadsAir::trace(&witness.pads, &witness.d_randomness, statement.b_bar_prime);

        // Each constraint holds on its own.
        assert!(each_holds_alone(
            &key, &mask_sum, &sum, &response, &pads, &statement
        ));

        // Together they do not.
        let trace = side_by_side([&key, &mask_sum, &sum, &response, &pads]);
        assert!(!report(&trace, &statement).is_ok());
    }
}
