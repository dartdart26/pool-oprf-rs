//! Constraint (A) on Plonky3:
//!
//! ```text
//! ã_Σ = Σ_i sk_i·e_i + r̃_Σ   mod q
//! ```
//!
//! (A) takes `sk` and `r̃_Σ` as given - (K) and (M) fix them.
//!
//! `e` is public.
//!
//! # Layout
//!
//! One row holds all of (A). Its columns, in order:
//!
//! | columns         | content                              |
//! |-----------------|--------------------------------------|
//! | `N`             | `sk`                                 |
//! | 1               | `r̃_Σ`                                |
//! | `LOG_Q`         | the bits of `ã_Σ`, lowest first      |
//! | `QUOTIENT_BITS` | the bits of `quotient`, lowest first |
//!
//! # 1. `sk_i·e_i`
//!
//! Let's call `S = Σ_i sk_i·e_i + r̃_Σ`, without the modulo operation.
//!
//! # 2. the sum mod `q`
//!
//! The result we want is `ã_Σ = S mod q`. To show that `ã_Σ` is the result,
//! we use the definition of mod: `ã_Σ ≡ S mod q` when `S = ã_Σ + q·quotient`,
//! where `quotient` is a whole number. The rule checks this equation.
//! `ã_Σ` is `LOG_Q` bit columns, so it is below `q`.
//!
//! Let's call the field's prime `Pf`. `S` and `q·quotient + ã_Σ` must stay
//! below `Pf`, because the rule compares them `mod Pf`.

use crate::plonky3::{ROWS, Val};
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::modular::{quotient_q, reduce_q};
use pool_prf::params::{LOG_Q, N, Q, Zq, ZqAccum};
use pool_prf::prf::SecretKey;

const A_SIGMA_BITS: usize = LOG_Q as usize;
const QUOTIENT_BITS: usize = (N + 1).next_power_of_two().ilog2() as usize;

/// Where each part of the row starts.
const SK: usize = 0;
const R_SIGMA: usize = SK + N;
const A_SIGMA: usize = R_SIGMA + 1;
const QUOTIENT: usize = A_SIGMA + A_SIGMA_BITS;
const NUM_COLS: usize = QUOTIENT + QUOTIENT_BITS;

/// Both sides of the sum rule are below this.
const SUM_BOUND: usize = (Q as usize) << QUOTIENT_BITS;
const _: () = assert!(SUM_BOUND < Val::ORDER_U32 as usize);

/// The lowest `count` bits of `value`, as columns.
fn bits(value: ZqAccum, count: usize) -> impl Iterator<Item = Val> {
    (0..count).map(move |k| Val::from_int((value >> k) & 1))
}

pub struct SumAir;

impl SumAir {
    pub fn trace(sk: &SecretKey, r_sigma_sum: Zq, e: &[Zq; N]) -> RowMajorMatrix<Val> {
        let sk = sk.as_bits();
        let first_sum: ZqAccum = sk
            .iter()
            .zip(e)
            .map(|(&sk_i, &e_i)| if sk_i == 0 { 0 } else { ZqAccum::from(e_i) })
            .sum();
        // Σ_i sk_i·e_i + r̃_Σ
        let sum = first_sum + ZqAccum::from(r_sigma_sum);
        let mut row: Vec<Val> = sk.iter().map(|&bit| Val::from_int(bit)).collect();
        row.push(Val::from_int(r_sigma_sum));
        row.extend(bits(reduce_q(sum).into(), A_SIGMA_BITS));
        row.extend(bits(quotient_q(sum), QUOTIENT_BITS));
        RowMajorMatrix::new(row.repeat(ROWS), NUM_COLS)
    }
}

impl BaseAir<Val> for SumAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        N
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for SumAir {
    fn eval(&self, builder: &mut AB) {
        let e: [AB::PublicVar; N] = builder.public_values().try_into().expect("e");
        let main = builder.main();
        let row = main.current_slice();
        let sk = &row[SK..R_SIGMA];
        let r_sigma_sum: AB::Expr = row[R_SIGMA].into();
        let a_sigma_bits = &row[A_SIGMA..QUOTIENT];
        let quotient_bits = &row[QUOTIENT..NUM_COLS];
        for &bit in sk.iter().chain(a_sigma_bits).chain(quotient_bits) {
            builder.assert_bool(bit);
        }

        // sk_i·e_i
        let terms = sk.iter().zip(e).map(|(&sk_i, e_i)| {
            let e_i: AB::Expr = e_i.into();
            sk_i * e_i
        });
        // S = Σ_i sk_i·e_i + r̃_Σ
        let s = terms.sum::<AB::Expr>() + r_sigma_sum;

        // S = ã_Σ + q·quotient
        let a_sigma_sum = pack_bits_le::<AB::Expr, _, _>(a_sigma_bits.iter().copied());
        let quotient = pack_bits_le::<AB::Expr, _, _>(quotient_bits.iter().copied());
        builder.assert_eq(s, a_sigma_sum + quotient * Val::from_int(Q));
    }
}

pub fn public_values(e: &[Zq; N]) -> [Val; N] {
    e.map(Val::from_int)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    fn vector(rng: &mut StdRng) -> [Zq; N] {
        array::from_fn(|_| rng.random_range(0..Q))
    }

    /// A random key, `r̃_Σ` and `e`, from `seed`.
    fn random(seed: u64) -> (SecretKey, Zq, [Zq; N]) {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        let r_sigma_sum = rng.random_range(0..Q);
        (sk, r_sigma_sum, vector(&mut rng))
    }

    /// The key, `r̃_Σ` and `e` each zero, their largest and random, in
    /// every combination.
    fn corners() -> Vec<(SecretKey, Zq, [Zq; N])> {
        let mut rng = StdRng::seed_from_u64(1);
        let keys = [
            SecretKey::from_bits([0; N]).expect("bits"),
            SecretKey::from_bits([1; N]).expect("bits"),
            SecretKey::random(&mut rng),
        ];
        let r_sigma_sums = [0, Q - 1, rng.random_range(0..Q)];
        let vectors = [[0; N], [Q - 1; N], vector(&mut rng)];
        let mut corners = Vec::new();
        for sk in &keys {
            for r_sigma_sum in r_sigma_sums {
                for e in vectors {
                    corners.push((sk.clone(), r_sigma_sum, e));
                }
            }
        }
        corners
    }

    /// Runs the rules over `trace` for `e`.
    fn report(trace: &RowMajorMatrix<Val>, e: &[Zq; N]) -> ConstraintReport {
        check_all_constraints(&SumAir, trace, &public_values(e), None)
    }

    /// `ã_Σ` as the trace holds it, from its bits.
    fn a_sigma_sum_of(trace: &RowMajorMatrix<Val>) -> Zq {
        let row = trace.row_slice(0).expect("a row");
        row[A_SIGMA..QUOTIENT]
            .iter()
            .enumerate()
            .map(|(k, &bit)| Zq::from(bit == Val::ONE) << k)
            .sum()
    }

    #[test]
    fn the_rules_hold_at_every_corner() {
        for (sk, r_sigma_sum, e) in corners() {
            let trace = SumAir::trace(&sk, r_sigma_sum, &e);
            assert!(report(&trace, &e).is_ok());
        }
    }

    /// The trace holds the `ã_Σ` the server computes.
    #[test]
    fn a_sigma_sum_is_the_servers() {
        for (sk, r_sigma_sum, e) in corners() {
            let trace = SumAir::trace(&sk, r_sigma_sum, &e);
            assert_eq!(
                a_sigma_sum_of(&trace),
                pool_eval::a_sigma_sum(&sk, r_sigma_sum, &e)
            );
        }
    }

    /// `e_i` enters the sum only where `sk_i = 1`.
    #[test]
    fn e_i_counts_exactly_where_sk_i_is_set() {
        let (sk, r_sigma_sum, e) = random(2);
        let trace = SumAir::trace(&sk, r_sigma_sum, &e);
        for i in 0..N {
            let mut changed = e;
            changed[i] ^= 1;
            assert_eq!(
                report(&trace, &changed).is_ok(),
                sk.as_bits()[i] == 0,
                "coordinate {i}"
            );
        }
    }

    #[test]
    fn a_bit_that_is_not_a_bit_is_refused() {
        // With `sk = 0` and `r̃_Σ = 2`, `ã_Σ = 2`, whose lowest two bits are 0, 1.
        let sk = SecretKey::from_bits([0; N]).expect("bits");
        let e = [0; N];
        let mut trace = SumAir::trace(&sk, 2, &e);
        assert!(report(&trace, &e).is_ok());
        for row in trace.values.chunks_mut(NUM_COLS) {
            assert_eq!(row[A_SIGMA..A_SIGMA + 2], [Val::ZERO, Val::ONE]);
            row[A_SIGMA] = Val::TWO;
            row[A_SIGMA + 1] = Val::ZERO;
        }
        let failures = report(&trace, &e).failures;
        assert!(!failures.is_empty());
        assert!(
            failures.iter().all(|failure| failure.constraint == N),
            "{failures:?}"
        );
    }

    #[test]
    fn a_wrong_a_sigma_sum_is_refused() {
        let (sk, r_sigma_sum, e) = random(3);
        let mut trace = SumAir::trace(&sk, r_sigma_sum, &e);
        for row in trace.values.chunks_mut(NUM_COLS) {
            // flip a bit
            row[A_SIGMA] = Val::ONE - row[A_SIGMA];
        }
        assert!(!report(&trace, &e).is_ok());
    }
}
