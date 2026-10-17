//! Constraint (S) on Plonky3:
//!
//! ```text
//! c^v_{b̄_i ⊕ sk_i, i} = Commit(Domain::Masks, r^{v, 0}_{b_i, i} .. r^{v, RUNS_PER_EVALUATION-1}_{b_i, i}, ot_block_{b_i, i})      i = 0 .. n-1
//! ```
//!
//! (S) takes `sk` as given - (K) pins it down.
//!
//! # Layout
//!
//! One row holds one OT block `i` with its mask of every run `k`.
//! The rows after block `n-1`, up to `N_TABLE_ROWS`, repeat the row of
//! block `n-1`. Domain, masks, OT block and rest are Poseidon2's input.
//!
//! | row              | `sk_i` (1) | domain (1)      | masks (`RUNS_PER_EVALUATION`) | OT block (`RANDOMNESS_ELEMENTS`) | rest  | rounds                                 |
//! |------------------|------------|-----------------|-------------------------------|----------------------------------|-------|----------------------------------------|
//! | `0`              | `sk_0`     | `Domain::Masks` | `r^{v, k}_{b_0, 0}`           | `ot_block_{b_0, 0}`              | zeros | end in `c^v_{b̄_0 ⊕ sk_0, 0}`           |
//! | `1`              | `sk_1`     | `Domain::Masks` | `r^{v, k}_{b_1, 1}`           | `ot_block_{b_1, 1}`              | zeros | end in `c^v_{b̄_1 ⊕ sk_1, 1}`           |
//! | …                | …          | …               | …                             | …                                | …     | …                                      |
//! | `n-1`            | `sk_{n-1}` | `Domain::Masks` | `r^{v, k}_{b_{n-1}, n-1}`     | `ot_block_{b_{n-1}, n-1}`        | zeros | end in `c^v_{b̄_{n-1} ⊕ sk_{n-1}, n-1}` |
//! | `n`              | `sk_{n-1}` | `Domain::Masks` | `r^{v, k}_{b_{n-1}, n-1}`     | `ot_block_{b_{n-1}, n-1}`        | zeros | end in `c^v_{b̄_{n-1} ⊕ sk_{n-1}, n-1}` |
//! | …                | …          | …               | …                             | …                                | …     | …                                      |
//! | `N_TABLE_ROWS-1` | `sk_{n-1}` | `Domain::Masks` | `r^{v, k}_{b_{n-1}, n-1}`     | `ot_block_{b_{n-1}, n-1}`        | zeros | end in `c^v_{b̄_{n-1} ⊕ sk_{n-1}, n-1}` |
//!
//! `b̄_i`, `c^v_{0, i}` and `c^v_{1, i}` are public. Periodic columns hold
//! them, one block per row:
//!
//! | row              | `b̄_i` (1) | `c^v_{0, i}` (`DIGEST_ELEMENTS`) | `c^v_{1, i}` (`DIGEST_ELEMENTS`) |
//! |------------------|-----------|----------------------------------|----------------------------------|
//! | `0`              | `b̄_0`     | `c^v_{0, 0}`                     | `c^v_{1, 0}`                     |
//! | `1`              | `b̄_1`     | `c^v_{0, 1}`                     | `c^v_{1, 1}`                     |
//! | …                | …         | …                                | …                                |
//! | `n-1`            | `b̄_{n-1}` | `c^v_{0, n-1}`                   | `c^v_{1, n-1}`                   |
//! | `n`              | `b̄_{n-1}` | `c^v_{0, n-1}`                   | `c^v_{1, n-1}`                   |
//! | …                | …         | …                                | …                                |
//! | `N_TABLE_ROWS-1` | `b̄_{n-1}` | `c^v_{0, n-1}`                   | `c^v_{1, n-1}`                   |
//!
//! Plonky3 checks Poseidon2's rounds itself. We add these rules for (S):
//!
//! - `sk_i` is 0 or 1
//! - the input starts with `Domain::Masks` and ends in zeros
//! - the rounds end in `c^v_{b̄_i ⊕ sk_i, i}`
//!
//! With `b_i = b̄_i ⊕ sk_i = b̄_i + sk_i - 2·b̄_i·sk_i`, the commitment is
//! `c^v_{b_i, i} = c^v_{0, i} + b_i·(c^v_{1, i} - c^v_{0, i})`.

use crate::commitments::CommitmentRandomness;
use crate::plonky3::commitments::DIGEST_ELEMENTS;
use crate::plonky3::commitments::masks::{MasksCommitment, VALUE_ELEMENTS, elements};
use crate::plonky3::sponge::{PERMUTATION, PERMUTATION_COLS, eval_commitment, sponge_trace};
use crate::plonky3::{N_TABLE_ROWS, Val};
use core::array;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use pool_prf::params::{N, RUNS_PER_EVALUATION, Zq};
use pool_prf::prf::SecretKey;
use std::borrow::Cow;

/// Where each part of the row starts. Poseidon2's input is the domain, the
/// masks, the OT block, then zeros.
pub(crate) const SK_I: usize = 0;
const SPONGE: usize = SK_I + 1;
pub(crate) const MASKS: usize = SPONGE + 1;
pub(crate) const NUM_COLS: usize = SPONGE + PERMUTATION_COLS;

/// Where the periodic columns start: `b̄_i`, `c^v_{0, i}`, then `c^v_{1, i}`.
pub(crate) const B_BAR: usize = 0;
pub(crate) const C_0: usize = B_BAR + 1;
pub(crate) const C_1: usize = C_0 + DIGEST_ELEMENTS;
pub(crate) const NUM_PERIODIC_COLUMNS: usize = C_1 + DIGEST_ELEMENTS;

pub struct ServerMasksAir {
    periodic: [Vec<Val>; NUM_PERIODIC_COLUMNS],
}

impl ServerMasksAir {
    pub fn new(b_bar: &[u8; N], c: &[[MasksCommitment; 2]; N]) -> Self {
        let mut periodic: [Vec<Val>; NUM_PERIODIC_COLUMNS] =
            array::from_fn(|_| Vec::with_capacity(N_TABLE_ROWS));
        for row in 0..N_TABLE_ROWS {
            let i = row.min(N - 1);
            periodic[B_BAR].push(Val::from_u8(b_bar[i]));
            for e in 0..DIGEST_ELEMENTS {
                periodic[C_0 + e].push(c[i][0].0[e]);
                periodic[C_1 + e].push(c[i][1].0[e]);
            }
        }
        Self { periodic }
    }

    pub fn trace(
        sk: &SecretKey,
        masks: &[[Zq; RUNS_PER_EVALUATION]; N],
        ot_blocks: &[CommitmentRandomness; N],
    ) -> RowMajorMatrix<Val> {
        let sk = sk.as_bits();
        let mut rows = Vec::with_capacity(N_TABLE_ROWS * NUM_COLS);
        for row in 0..N_TABLE_ROWS {
            let i = row.min(N - 1);
            let values = elements(&masks[i], ot_blocks[i]);
            rows.push(Val::from_u8(sk[i]));
            rows.extend(sponge_trace(MasksCommitment::input(values)));
        }
        RowMajorMatrix::new(rows, NUM_COLS)
    }

    pub fn rules<AB: AirBuilder<F = Val>>(
        builder: &mut AB,
        b_bar_i: AB::Expr,
        [c_0, c_1]: [[AB::Expr; DIGEST_ELEMENTS]; 2],
    ) {
        let main = builder.main();
        let row = main.current_slice();
        let sk_i = row[SK_I];
        builder.assert_bool(sk_i);

        let b_i = b_bar_i.clone() + sk_i - b_bar_i * sk_i * Val::TWO;
        let c_b_i =
            array::from_fn(|e| c_0[e].clone() + b_i.clone() * (c_1[e].clone() - c_0[e].clone()));
        let domain = MasksCommitment::domain();
        eval_commitment(builder, SPONGE, domain, VALUE_ELEMENTS, c_b_i);
    }
}

impl BaseAir<Val> for ServerMasksAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds all of (S), so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        PERMUTATION.max_constraint_degree()
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_PERIODIC_COLUMNS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for ServerMasksAir {
    fn eval(&self, builder: &mut AB) {
        let periodic = builder.periodic_values();
        let b_bar_i = periodic[B_BAR].into();
        let c_0 = array::from_fn(|e| periodic[C_0 + e].into());
        let c_1 = array::from_fn(|e| periodic[C_1 + e].into());
        Self::rules(builder, b_bar_i, [c_0, c_1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments::key::KeyCommitment;
    use crate::plonky3::commitments::mask_sum::MaskSumCommitment;
    use crate::statements::preprocessing::{PreprocessingStatement, PreprocessingWitness};
    use crate::testing::random_preprocessing;
    use p3_air::check_all_constraints;

    type Preprocessing = PreprocessingStatement<KeyCommitment, MasksCommitment, MaskSumCommitment>;

    /// A random witness and the honest statement for one evaluation, from
    /// `seed`.
    fn random(seed: u64) -> (Preprocessing, PreprocessingWitness) {
        random_preprocessing(seed, 1)
    }

    fn holds(statement: &Preprocessing, witness: &PreprocessingWitness) -> bool {
        let air = ServerMasksAir::new(&statement.b_bar, &statement.evaluations[0].c);
        let masks = &witness.evaluations[0].masks;
        let trace = ServerMasksAir::trace(&witness.sk, masks, &witness.ot_blocks);
        check_all_constraints(&air, &trace, &[], None).is_ok()
    }

    #[test]
    fn the_rules_hold() {
        let (statement, witness) = random(1);
        assert!(holds(&statement, &witness));
    }

    #[test]
    fn another_b_bar_is_refused() {
        let (statement, witness) = random(2);
        for i in [0, 1, N - 1] {
            let mut statement = statement.clone();
            statement.b_bar[i] ^= 1;
            assert!(!holds(&statement, &witness), "block {i}");
        }
    }

    #[test]
    fn another_c_is_refused() {
        let (statement, witness) = random(3);
        let sk = witness.sk.as_bits();
        for i in [0, 1, N - 1] {
            let mut statement = statement.clone();
            let b_i = usize::from(statement.b_bar[i] ^ sk[i]);
            statement.evaluations[0].c[i][b_i].0[0] += Val::ONE;
            assert!(!holds(&statement, &witness), "block {i}");
        }
    }

    /// Another mask in any run does not open `c`.
    #[test]
    fn another_mask_is_refused() {
        let (statement, witness) = random(4);
        for k in 0..RUNS_PER_EVALUATION {
            let mut witness = witness.clone();
            witness.evaluations[0].masks[1][k] += 1;
            assert!(!holds(&statement, &witness), "run {k}");
        }
    }
}
