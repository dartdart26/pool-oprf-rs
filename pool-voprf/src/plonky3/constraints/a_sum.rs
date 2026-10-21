//! Constraint (A) on Plonky3:
//!
//! ```text
//! ã^{v, k}_Σ = Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ   mod q
//! ```
//!
//! (A) takes `sk` and `r̃^{v, k}_Σ` as given - (K) and (M) pin them down.
//! `sk` is not in (A)'s columns: the caller passes it in as (K)'s key bits.
//!
//! `e^{v, k}` is public.
//!
//! # Layout
//!
//! One row holds all of (A) and every row is the same. The bits are lowest
//! first.
//!
//! | row      | mask sum (1) | `ã^{v, k}_Σ` (`LOG_Q`) | quotient (`QUOTIENT_BITS`) |
//! |----------|--------------|------------------------|----------------------------|
//! | `0`      | `r̃^{v, k}_Σ` | bits                   | bits                       |
//! | `1`      | `r̃^{v, k}_Σ` | bits                   | bits                       |
//! | …        | …            | …                      | …                          |
//! | `ROWS-1` | `r̃^{v, k}_Σ` | bits                   | bits                       |
//!
//! # 1. `sk_i·e^{v, k}_i`
//!
//! Let's call `S = Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ`, without the modulo
//! operation.
//!
//! # 2. The sum mod `q`
//!
//! The result we want is `ã^{v, k}_Σ = S mod q`. To show that `ã^{v, k}_Σ` is
//! the result, we use the definition of mod: `ã^{v, k}_Σ ≡ S mod q` when
//! `S = ã^{v, k}_Σ + q·quotient`, where `quotient` is a whole number. The rule
//! checks this equation.
//! `ã^{v, k}_Σ` is `LOG_Q` bit columns, so it is below `q`.
//!
//! Let's call the field's prime `Pf`. `S` and `q·quotient + ã^{v, k}_Σ` must
//! stay below `Pf`, because the rule compares them `mod Pf`.

use crate::plonky3::constraints::common::{KEY_BITS, bits};
use crate::plonky3::{N_BITS, ROWS, Val};
use core::array;
use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::modular::{quotient_q, reduce_q};
use pool_prf::params::{LOG_Q, N, Q, Zq, ZqAccum};
use pool_prf::prf::SecretKey;

const A_SIGMA_BITS: usize = LOG_Q as usize;
/// The quotient is at most `n`.
const QUOTIENT_BITS: usize = N_BITS;

/// Where each part of the row starts.
pub(crate) const R_SIGMA: usize = 0;
pub(crate) const A_SIGMA: usize = R_SIGMA + 1;
pub(crate) const QUOTIENT: usize = A_SIGMA + A_SIGMA_BITS;
pub(crate) const NUM_COLS: usize = QUOTIENT + QUOTIENT_BITS;

/// Both sides of the sum rule are below this.
const SUM_BOUND: usize = (Q as usize) << QUOTIENT_BITS;
const _: () = assert!(SUM_BOUND < Val::ORDER_U32 as usize);

pub struct SumAir;

impl SumAir {
    pub fn row(sk: &SecretKey, r_sigma_sum: Zq, e: &[Zq; N]) -> Vec<Val> {
        let first_sum: ZqAccum = sk
            .as_bits()
            .iter()
            .zip(e)
            .map(|(&sk_i, &e_i)| if sk_i == 0 { 0 } else { ZqAccum::from(e_i) })
            .sum();
        // Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ
        let sum = first_sum + ZqAccum::from(r_sigma_sum);
        let mut row = vec![Val::from_int(r_sigma_sum)];
        row.extend(bits(reduce_q(sum).into(), A_SIGMA_BITS));
        row.extend(bits(quotient_q(sum), QUOTIENT_BITS));
        row
    }

    /// The table - `ROWS` copies of the row.
    pub fn trace(sk: &SecretKey, r_sigma_sum: Zq, e: &[Zq; N]) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(Self::row(sk, r_sigma_sum, e).repeat(ROWS), NUM_COLS)
    }

    pub fn rules<AB: AirBuilder<F = Val>>(
        builder: &mut AB,
        sk: [AB::Expr; KEY_BITS],
        e: [AB::Expr; N],
    ) {
        let main = builder.main();
        let row = main.current_slice();
        let r_sigma_sum: AB::Expr = row[R_SIGMA].into();
        let a_sigma_bits = &row[A_SIGMA..QUOTIENT];
        let quotient_bits = &row[QUOTIENT..NUM_COLS];
        for &bit in a_sigma_bits.iter().chain(quotient_bits) {
            builder.assert_bool(bit);
        }

        // sk_i·e^{v, k}_i
        let terms = sk.into_iter().zip(e).map(|(sk_i, e_i)| sk_i * e_i);
        // S = Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ
        let s = terms.sum::<AB::Expr>() + r_sigma_sum;

        // S = ã^{v, k}_Σ + q·quotient
        let a_sigma_sum = pack_bits_le::<AB::Expr, _, _>(a_sigma_bits.iter().copied());
        let quotient = pack_bits_le::<AB::Expr, _, _>(quotient_bits.iter().copied());
        builder.assert_eq(s, a_sigma_sum + quotient * Val::from_int(Q));
    }
}

impl BaseAir<Val> for SumAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    /// On its own, (A) takes `e^{v, k}` and the key bits as public values.
    fn num_public_values(&self) -> usize {
        N + KEY_BITS
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for SumAir {
    fn eval(&self, builder: &mut AB) {
        let public = builder.public_values();
        let e = array::from_fn(|i| public[i].into());
        let sk = array::from_fn(|i| public[N + i].into());
        Self::rules(builder, sk, e);
    }
}

pub fn public_values(e: &[Zq; N]) -> [Val; N] {
    e.map(Val::from_int)
}

/// The public values of (A) on its own: `e^{v, k}`, then the key bits.
#[cfg(test)]
pub fn standalone_public_values(sk: &SecretKey, e: &[Zq; N]) -> Vec<Val> {
    let bits = sk.as_bits().iter().map(|&bit| Val::from_int(bit));
    public_values(e).into_iter().chain(bits).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    fn vector(rng: &mut StdRng) -> [Zq; N] {
        array::from_fn(|_| rng.random_range(0..Q))
    }

    /// A random key, `r̃^{v, k}_Σ` and `e^{v, k}`, from `seed`.
    fn random(seed: u64) -> (SecretKey, Zq, [Zq; N]) {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        let r_sigma_sum = rng.random_range(0..Q);
        (sk, r_sigma_sum, vector(&mut rng))
    }

    /// The key, `r̃^{v, k}_Σ` and `e^{v, k}` each zero, their largest and
    /// random, in every combination.
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

    fn report(trace: &RowMajorMatrix<Val>, sk: &SecretKey, e: &[Zq; N]) -> ConstraintReport {
        check_all_constraints(&SumAir, trace, &standalone_public_values(sk, e), None)
    }

    /// `ã^{v, k}_Σ` as the trace holds it, from its bits.
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
            assert!(report(&trace, &sk, &e).is_ok());
        }
    }

    /// The trace holds the `ã^{v, k}_Σ` the server computes.
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

    /// `e^{v, k}_i` enters the sum only where `sk_i = 1`.
    #[test]
    fn e_i_counts_exactly_where_sk_i_is_set() {
        let (sk, r_sigma_sum, e) = random(2);
        let trace = SumAir::trace(&sk, r_sigma_sum, &e);
        for i in 0..N {
            let mut changed = e;
            changed[i] ^= 1;
            assert_eq!(
                report(&trace, &sk, &changed).is_ok(),
                sk.as_bits()[i] == 0,
                "coordinate {i}"
            );
        }
    }

    #[test]
    fn a_bit_that_is_not_a_bit_is_refused() {
        // With `sk = 0` and `r̃^{v, k}_Σ = 2`, `ã^{v, k}_Σ = 2`, whose lowest
        // two bits are 0, 1.
        let sk = SecretKey::from_bits([0; N]).expect("bits");
        let e = [0; N];
        let mut trace = SumAir::trace(&sk, 2, &e);
        assert!(report(&trace, &sk, &e).is_ok());
        for row in trace.values.chunks_mut(NUM_COLS) {
            assert_eq!(row[A_SIGMA..A_SIGMA + 2], [Val::ZERO, Val::ONE]);
            row[A_SIGMA] = Val::TWO;
            row[A_SIGMA + 1] = Val::ZERO;
        }
        let failures = report(&trace, &sk, &e).failures;
        assert!(!failures.is_empty());
        assert!(
            failures.iter().all(|failure| failure.constraint == 0),
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
        assert!(!report(&trace, &sk, &e).is_ok());
    }
}
