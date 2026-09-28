//! Constraint (R) on Plonky3:
//!
//! ```text
//! y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}   mod p,   j = 0 .. Δ-1
//! ```
//!
//! Let's define:
//!
//! ```text
//! t_j   = (ã_Σ - j) mod q
//! pad_j = r′_{(j - b̄′) mod Δ}
//! ```
//!
//! (R) checks the arithmetic only. It takes `ã_Σ` and `r′` as given, without
//! checking that they are in `ℤ_q` and `ℤ_p` - (A) and (P) fix them.
//!
//! # Layout
//!
//! One row holds all of (R). Its columns, in order: `ã_Σ`, then the four
//! rows below it for `j = 0`, then the same four for `j = 1`, and so on
//! up to `j = Δ-1`.
//!
//! | columns | content                                    |
//! |---------|--------------------------------------------|
//! | 1       | `ã_Σ`                                      |
//! | `LOG_Q` | the bits of `t_j`, lowest first            |
//! | 1       | `wrapped`: 1 if `ã_Σ - j` was below zero   |
//! | 1       | `pad_j`                                    |
//! | 1       | `carry`: 1 if `⌈t_j⌋ + pad_j` reached `p`  |
//!
//! `ã_Σ` is the number itself, in one column.
//!
//! `j` has no column as the rules of entry `j` are written for that `j`, such
//! that it is a constant in them.
//!
//! # 1. `t_j` mod `q`
//!
//! `t_j` is laid out as `LOG_Q` bits, and no number above `q - 1` fits in
//! `LOG_Q` bits. So once the rule checks that each column is a bit, `t_j`
//! is in `ℤ_q`. The rule then computes `t_j` twice and compares:
//!
//! ```text
//! Σ_k 2^k · t_{j,k}  =  ã_Σ - j + q·wrapped
//! ```
//!
//! The left side computes `t_j` from its `LOG_Q` bits, `t_{j,k}` being bit
//! `k`. The right side computes it from the `ã_Σ` column, with `q` added
//! back when `ã_Σ - j` went below zero.
//!
//! # 2. rounding `t_j`, i.e. `⌈t_j⌋`
//!
//! `⌈t_j⌋` is the nearest integer to `t_j / Δ`, ties down. Since `Δ` is a
//! power of two, the division is a split of the bits of `t_j`: the quotient
//! is the high `LOG_P` bits and the remainder is the low `LOG_DELTA` bits.
//! The remainder decides the direction: above `Δ/2` rounds up, otherwise
//! down. So
//!
//! ```text
//! ⌈t_j⌋ = quotient + up
//! ```
//!
//! where `up` is 1 if the remainder is above `Δ/2`, else 0.
//!
//! To get `up` from the bits, call the remainder `m`, with bits `m_0` to
//! `m_{LOG_DELTA-1}`. In binary `Δ/2` is a one followed by `LOG_DELTA - 1`
//! zeros, i.e. `m_{LOG_DELTA-1} = 1` and every lower bit 0. So `m` is above
//! `Δ/2` exactly when `m_{LOG_DELTA-1}` is 1 and at least one lower bit is 1
//! as well.
//!
//! At least one lower bit being 1 is the opposite of all of them being 0,
//! and the product of the flipped lower bits is 1 exactly when all are 0:
//!
//! ```text
//! any_lower = 1 - (1 - m_0)·(1 - m_1)·…·(1 - m_{LOG_DELTA-2})
//! up        = m_{LOG_DELTA-1} · any_lower
//! ```
//!
//! # 3. `y_j` mod `p`
//!
//! `⌈t_j⌋` is at most `p` and `pad_j` is below `p`. So their sum is below
//! `2p` and taking it mod `p` subtracts `p` at most once. `carry` is a bit
//! that says whether:
//!
//! ```text
//! y_j = ⌈t_j⌋ + pad_j - p·carry
//! ```

use crate::plonky3::{Plonky3, Proof, ProveError, ROWS, Val, VerifyError};
use crate::proof::{ProofSystem, Statement};
use crate::response::{ResponseStatement, ResponseWitness};
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use pool_prf::modular::sub_q;
use pool_prf::params::{DELTA, DELTA_ZQ, LOG_DELTA, LOG_Q, P, Q, Zdelta, Zq};

const T_BITS: usize = LOG_Q as usize;
/// The bits of `t_j`, `wrapped`, `pad_j`, `carry`.
const ENTRY_COLS: usize = T_BITS + 3;
/// `ã_Σ` and then the `Δ` entries.
const NUM_COLS: usize = 1 + DELTA * ENTRY_COLS;

/// `up` of step 2, from the bits `m` of the remainder. Lowest bit first in `m`.
fn up<AB: AirBuilder>(m: &[AB::Var]) -> AB::Expr {
    let (&top, lower) = m.split_last().expect("a bit");
    let any_lower = AB::Expr::ONE
        - lower
            .iter()
            .map(|&bit| AB::Expr::ONE - bit)
            .product::<AB::Expr>();
    top * any_lower
}

pub struct ResponseAir;

impl ResponseAir {
    pub fn trace(witness: &ResponseWitness, b_bar_prime: Zdelta) -> RowMajorMatrix<Val> {
        let mut row = vec![Val::from_int(witness.a_sigma_sum)];
        for j in 0..DELTA {
            let t = sub_q(witness.a_sigma_sum, j as Zq);
            let wrapped = witness.a_sigma_sum < j as Zq;
            let up = (t % DELTA_ZQ) > DELTA_ZQ / 2;
            let rounded = t / DELTA_ZQ + Zq::from(up);
            let pad = pool_eval::pad(&witness.pads, j, b_bar_prime);
            let carry = (rounded + Zq::from(pad)) >= P;
            row.extend((0..T_BITS).map(|k| Val::from_int((t >> k) & 1)));
            row.push(Val::from_bool(wrapped));
            row.push(Val::from_int(pad));
            row.push(Val::from_bool(carry));
        }
        RowMajorMatrix::new(row.repeat(ROWS), NUM_COLS)
    }
}

impl BaseAir<Val> for ResponseAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds all of (R), so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        DELTA
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for ResponseAir {
    fn eval(&self, builder: &mut AB) {
        let y: [AB::PublicVar; DELTA] = builder.public_values().try_into().expect("y");
        let main = builder.main();
        let row = main.current_slice();
        let a_sigma_sum = row[0];
        for (j, y_j) in y.into_iter().enumerate() {
            let start = 1 + j * ENTRY_COLS; // after ã_Σ
            let (t_bits, rest) = row[start..start + ENTRY_COLS].split_at(T_BITS);
            let (wrapped, pad, carry) = (rest[0], rest[1], rest[2]);
            for &bit in t_bits {
                builder.assert_bool(bit);
            }
            builder.assert_bool(wrapped);
            builder.assert_bool(carry);

            // 1. t_j = ã_Σ - j + q·wrapped
            let t = pack_bits_le::<AB::Expr, _, _>(t_bits.iter().copied());
            builder.assert_eq(
                t,
                a_sigma_sum - Val::from_int(j) + wrapped * Val::from_int(Q),
            );

            // 2. ⌈t_j⌋ = quotient + up
            let (m, quotient) = t_bits.split_at(LOG_DELTA);
            let rounded = pack_bits_le::<AB::Expr, _, _>(quotient.iter().copied()) + up::<AB>(m);

            // 3. y_j = ⌈t_j⌋ + pad_j - carry·p
            builder.assert_eq(rounded + pad - carry * Val::from_int(P), y_j);
        }
    }
}

fn public_values(statement: &ResponseStatement) -> [Val; DELTA] {
    statement.y.map(Val::from_int)
}

impl ProofSystem<ResponseStatement> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(
        &self,
        statement: &ResponseStatement,
        witness: &ResponseWitness,
    ) -> Result<Proof, ProveError> {
        if !statement.holds_for(witness) {
            return Err(ProveError::WrongWitness);
        }
        let trace = ResponseAir::trace(witness, statement.b_bar_prime);
        prove(&self.config, &ResponseAir, trace, &public_values(statement))
            .map_err(ProveError::Prover)
    }

    fn verify(&self, statement: &ResponseStatement, proof: &Proof) -> Result<(), VerifyError> {
        Plonky3::verified(|| verify(&self.config, &ResponseAir, proof, &public_values(statement)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{ConstraintReport, check_all_constraints};
    use pool_prf::params::{DELTA_ZQ, ZP_MAX, Zq};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// A random statement and its witness, from `seed`.
    fn random(seed: u64) -> (ResponseStatement, ResponseWitness) {
        let mut rng = StdRng::seed_from_u64(seed);
        let witness = ResponseWitness {
            a_sigma_sum: rng.random_range(0..Q),
            pads: rng.random(),
        };
        let b_bar_prime = rng.random_range(0..DELTA as Zdelta);
        (
            ResponseStatement::for_witness(&witness, b_bar_prime),
            witness,
        )
    }

    /// Runs the rules over `trace` for `statement`.
    fn report(trace: &RowMajorMatrix<Val>, statement: &ResponseStatement) -> ConstraintReport {
        check_all_constraints(&ResponseAir, trace, &public_values(statement), None)
    }

    /// An honest trace passes the rules wherever a bit of it flips.
    ///
    /// `wrapped` flips when `ã_Σ < j` (`ã_Σ` below `Δ`).
    /// `carry` flips when `⌈t_j⌋ + pad_j` reaches `p`.
    /// `up` flips at every remainder and one row has them all.
    #[test]
    fn the_rules_hold_at_every_wrap() {
        let mut rng = StdRng::seed_from_u64(1);
        let below_delta = 0..=DELTA_ZQ;
        let near_q = Q - DELTA_ZQ..Q;
        let random: Vec<Zq> = (0..8).map(|_| rng.random_range(0..Q)).collect();
        for a_sigma_sum in below_delta.chain(near_q).chain(random) {
            for pads in [[0; DELTA], [ZP_MAX; DELTA], rng.random()] {
                let witness = ResponseWitness { a_sigma_sum, pads };
                let statement = ResponseStatement::for_witness(&witness, 0);
                let trace = ResponseAir::trace(&witness, 0);
                assert!(
                    report(&trace, &statement).is_ok(),
                    "ã_Σ = {a_sigma_sum}, pads = {pads:?}"
                );
            }
        }
    }

    #[test]
    fn every_entry_is_checked() {
        let (statement, witness) = random(2);
        let trace = ResponseAir::trace(&witness, statement.b_bar_prime);
        for j in 0..DELTA {
            let mut changed = statement;
            changed.y[j] ^= 1;
            assert!(
                !report(&trace, &changed).is_ok(),
                "entry {j} is not checked"
            );
        }
    }

    /// With `ã_Σ = 3`, entry 0 has `t_0 = 3`, whose lowest two bits are 1, 1.
    /// Writing them as 3, 0 violates the rule that columns of `t_0` are bits",
    /// namely constraint 0.
    #[test]
    fn a_bit_that_is_not_a_bit_is_refused() {
        let witness = ResponseWitness {
            a_sigma_sum: 3,
            pads: [0; DELTA],
        };
        let statement = ResponseStatement::for_witness(&witness, 0);
        let mut trace = ResponseAir::trace(&witness, 0);
        assert!(report(&trace, &statement).is_ok());
        for row in trace.values.chunks_mut(NUM_COLS) {
            assert_eq!(row[1..3], [Val::ONE, Val::ONE]);
            row[1] = Val::from_int(3);
            row[2] = Val::ZERO;
        }
        let failures = report(&trace, &statement).failures;
        assert!(!failures.is_empty());
        assert!(
            failures.iter().all(|failure| failure.constraint == 0),
            "{failures:?}"
        );
    }

    #[test]
    fn a_proof_verifies() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let (statement, witness) = random(3);
        let proof = system.prove(&statement, &witness).expect("proving");
        system.verify(&statement, &proof).expect("verifying");
    }

    #[test]
    fn a_wrong_response_does_not_verify() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let (statement, witness) = random(3);
        let proof = system.prove(&statement, &witness).expect("proving");
        let mut wrong = statement;
        wrong.y[DELTA - 1] ^= 1;
        assert!(system.verify(&wrong, &proof).is_err());
    }

    #[test]
    fn an_unreduced_a_sigma_sum_is_refused() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let (statement, witness) = random(4);
        let unreduced = ResponseWitness {
            a_sigma_sum: Q,
            pads: witness.pads,
        };
        let refused = system.prove(&statement, &unreduced);
        assert!(matches!(refused, Err(ProveError::WrongWitness)));
    }
}
