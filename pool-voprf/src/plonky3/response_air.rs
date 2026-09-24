//! Constraint (R) on Plonky3:
//!
//! ```text
//! y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}   mod p,   j = 0 .. Δ-1
//! ```
//!
//! A circuit has no `mod` and no rounding, only sums and products of
//! columns. But `q`, `p` and `Δ` are powers of two, so with the witness
//! given in bits every step becomes a rule on bits: each `mod` is adding or
//! taking away the modulus once, recorded in a bit, and the rounding reads
//! the bits of its input.
//!
//! Short names for two parts of the equation:
//!
//! ```text
//! t     = (ã_Σ - j) mod q
//! pad_j = r′_{(j - b̄′) mod Δ}
//! ```
//!
//! One row holds all of (R): `ã_Σ`, then `ENTRY_COLS` columns per entry `j`:
//!
//! | columns | content                                    |
//! |---------|--------------------------------------------|
//! | `LOG_Q` | the bits of `t`, lowest first              |
//! | 1       | `wrapped`: 1 if `ã_Σ - j` was below zero    |
//! | `LOG_P` | the bits of `pad_j`, lowest first          |
//! | 1       | `carry`: 1 if `⌈t⌋ + pad_j` reached `p`     |
//!
//! The rules, per entry, besides every bit being 0 or 1:
//!
//! 1. `t = ã_Σ - j + q·wrapped`. Having `LOG_Q` bits, `t` is below `q`.
//! 2. `⌈t⌋ = t / Δ + up`: `t / Δ` is the high `LOG_P` bits of `t`, and `up`
//!    is 1 if the low `LOG_DELTA` bits, the remainder, are above `Δ/2`.
//! 3. `y_j = ⌈t⌋ + pad_j - p·carry`, with `y_j` from the verifier.
//!
//! `b̄′` is not in the circuit. It only picks the pads.

use crate::plonky3::{Plonky3, Proof, ProveError, ROWS, Val, VerifyError};
use crate::proof::{ProofSystem, Statement};
use crate::response::{ResponseStatement, ResponseWitness};
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use pool_prf::modular::sub_q;
use pool_prf::params::{DELTA, DELTA_ZQ, LOG_DELTA, LOG_P, LOG_Q, P, Q, Zdelta, Zq};

const T_BITS: usize = LOG_Q as usize;
const PAD_BITS: usize = LOG_P as usize;
/// The bits of `t`, `wrapped`, the bits of the pad, `carry`.
const ENTRY_COLS: usize = T_BITS + 1 + PAD_BITS + 1;
const NUM_COLS: usize = 1 + DELTA * ENTRY_COLS;

/// The columns of one entry, as in the table above.
struct Entry<'a, T> {
    t: &'a [T],
    wrapped: T,
    pad: &'a [T],
    carry: T,
}

fn entry<T: Copy>(row: &[T], j: usize) -> Entry<'_, T> {
    let start = 1 + j * ENTRY_COLS;
    let (t, rest) = row[start..start + ENTRY_COLS].split_at(T_BITS);
    let (wrapped, rest) = rest.split_first().expect("wrapped");
    let (pad, carry) = rest.split_at(PAD_BITS);
    Entry {
        t,
        wrapped: *wrapped,
        pad,
        carry: carry[0],
    }
}

/// 1 if `remainder`, a number below `Δ` as bits, is above `Δ/2`: its top
/// bit is set and it is not exactly `Δ/2`, i.e. not all lower bits are 0.
fn above_half<AB: AirBuilder>(remainder: &[AB::Var]) -> AB::Expr {
    let (&top, lower) = remainder.split_last().expect("a bit");
    let lower_all_zero: AB::Expr = lower.iter().map(|&bit| AB::Expr::ONE - bit).product();
    top * (AB::Expr::ONE - lower_all_zero)
}

/// The low `count` bits of `value`, lowest first.
fn bits(value: u32, count: usize) -> impl Iterator<Item = Val> {
    debug_assert!(value >> count == 0, "{value} fits {count} bits");
    (0..count).map(move |position| Val::from_bool((value >> position) & 1 == 1))
}

/// The rules for (R). Its public values are `y_0 .. y_{Δ-1}`.
#[derive(Default)]
pub struct ResponseAir;

impl ResponseAir {
    /// The table for `witness` - `ROWS` copies of the row.
    pub fn trace(witness: &ResponseWitness, b_bar_prime: Zdelta) -> RowMajorMatrix<Val> {
        let mut row = vec![Val::from_u16(witness.a_sigma_sum)];
        for j in 0..DELTA {
            let t = sub_q(witness.a_sigma_sum, j as Zq);
            let wrapped = witness.a_sigma_sum < j as Zq;
            let up = t % DELTA_ZQ > DELTA_ZQ / 2;
            let pad = pool_eval::pad(&witness.pads, j, b_bar_prime);
            let sum = u32::from(t / DELTA_ZQ) + u32::from(up) + u32::from(pad);
            row.extend(bits(u32::from(t), T_BITS));
            row.push(Val::from_bool(wrapped));
            row.extend(bits(u32::from(pad), PAD_BITS));
            row.push(Val::from_bool(sum >= u32::from(P)));
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

    /// `above_half` multiplies the `LOG_DELTA` bits of the remainder.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(LOG_DELTA)
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
        for (j, expected) in y.into_iter().enumerate() {
            let entry = entry(row, j);
            for &bit in entry.t.iter().chain(entry.pad) {
                builder.assert_bool(bit);
            }
            builder.assert_bool(entry.wrapped);
            builder.assert_bool(entry.carry);

            // 1. t = (ã_Σ - j) mod q.
            let t = pack_bits_le::<AB::Expr, _, _>(entry.t.iter().copied());
            let added = entry.wrapped * AB::F::from_u16(Q);
            builder.assert_eq(t, a_sigma_sum - AB::F::from_usize(j) + added);

            // 2. ⌈t⌋ = t / Δ, plus 1 if the remainder is above Δ/2.
            let (remainder, quotient) = entry.t.split_at(LOG_DELTA);
            let rounded = pack_bits_le::<AB::Expr, _, _>(quotient.iter().copied())
                + above_half::<AB>(remainder);

            // 3. y_j = ⌈t⌋ + pad mod p.
            let pad = pack_bits_le::<AB::Expr, _, _>(entry.pad.iter().copied());
            let taken_away = entry.carry * AB::F::from_u16(P);
            builder.assert_eq(rounded + pad - taken_away, expected);
        }
    }
}

/// `y` as the public values.
fn public_values(statement: &ResponseStatement) -> [Val; DELTA] {
    statement.y.map(Val::from_u8)
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
    use p3_air::check_constraints;
    use pool_prf::params::{DELTA_ZQ, ZP_MAX, Zq};
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::panic::catch_unwind;

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

    /// Runs the rules over `trace` for `statement`. Returns the message of
    /// the failure, if any.
    fn refusal(trace: &RowMajorMatrix<Val>, statement: &ResponseStatement) -> Option<String> {
        catch_unwind(|| check_constraints(&ResponseAir, trace, &public_values(statement)))
            .err()
            .map(|panic| *panic.downcast::<String>().expect("a message"))
    }

    /// `ã_Σ` below `Δ` makes `ã_Σ - j` wrap around `q`, and `ã_Σ` within
    /// `Δ` of `q` makes the rounding wrap around `p`. Any one row has every
    /// remainder mod `Δ` across its entries, so any `ã_Σ` covers the rounding
    /// ties.
    #[test]
    fn the_rules_hold_at_every_wrap() {
        let mut rng = StdRng::seed_from_u64(1);
        let random: Vec<Zq> = (0..8).map(|_| rng.random_range(0..Q)).collect();
        let wraps = (0..=DELTA_ZQ).chain(Q - DELTA_ZQ..Q);
        for a_sigma_sum in wraps.chain(random) {
            for pads in [[0; DELTA], [ZP_MAX; DELTA], rng.random()] {
                let witness = ResponseWitness { a_sigma_sum, pads };
                let b_bar_prime = rng.random_range(0..DELTA as Zdelta);
                let statement = ResponseStatement::for_witness(&witness, b_bar_prime);
                let trace = ResponseAir::trace(&witness, b_bar_prime);
                assert_eq!(
                    refusal(&trace, &statement),
                    None,
                    "ã_Σ = {a_sigma_sum}, pads = {pads:?}, b̄′ = {b_bar_prime}"
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
                refusal(&trace, &changed).is_some(),
                "entry {j} is not checked"
            );
        }
    }

    /// With `ã_Σ = 3`, entry 0 has `t = 3`, whose lowest bits are 1, 1.
    /// Writing the same number as 3, 0 breaks only the bit rule of the first.
    #[test]
    fn a_bit_that_is_not_a_bit_is_refused() {
        let witness = ResponseWitness {
            a_sigma_sum: 3,
            pads: [0; DELTA],
        };
        let statement = ResponseStatement::for_witness(&witness, 0);
        let mut trace = ResponseAir::trace(&witness, 0);
        assert_eq!(refusal(&trace, &statement), None);
        for row in trace.values.chunks_mut(NUM_COLS) {
            assert_eq!(row[1..3], [Val::ONE, Val::ONE]);
            row[1] = Val::from_u8(3);
            row[2] = Val::ZERO;
        }
        let message = refusal(&trace, &statement).expect("refused");
        assert!(message.contains("failed constraints = [#0]"), "{message}");
    }

    #[test]
    fn a_proof_verifies_and_a_changed_response_does_not() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let (statement, witness) = random(3);
        let proof = system.prove(&statement, &witness).expect("proving");
        system.verify(&statement, &proof).expect("verifying");
        let mut changed = statement;
        changed.y[DELTA - 1] ^= 1;
        assert!(system.verify(&changed, &proof).is_err());
    }

    #[test]
    fn a_witness_that_does_not_give_the_response_is_refused() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let (statement, witness) = random(4);

        let mut other = statement;
        other.y[0] ^= 1;
        let refused = system.prove(&other, &witness);
        assert!(matches!(refused, Err(ProveError::WrongWitness)));

        let unreduced = ResponseWitness {
            a_sigma_sum: Q,
            pads: witness.pads,
        };
        let refused = system.prove(&statement, &unreduced);
        assert!(matches!(refused, Err(ProveError::WrongWitness)));
    }
}
