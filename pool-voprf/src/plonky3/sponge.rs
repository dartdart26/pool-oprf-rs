//! The sponge of [`commitments`](crate::plonky3::commitments) inside a
//! circuit.
//!
//! `commit` writes its input over a zero state of `WIDTH` elements, permutes
//! it with Poseidon2 and keeps the first `DIGEST_ELEMENTS` of the result.
//! The rest is dropped. Every input here fits in `RATE` elements, so one
//! permutation.
//!
//! In the circuit, the permutation is `PERMUTATION_COLS` columns: its input,
//! then its rounds, the helper values and the state after each round.

use crate::plonky3::Val;
use crate::plonky3::commitments::{DIGEST_ELEMENTS, RATE, WIDTH};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_32_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_32_INTERNAL, BABYBEAR_S_BOX_DEGREE, GenericPoseidon2LinearLayersBabyBear,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_air::{
    Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows, num_cols,
};
use p3_uni_stark::SubAirBuilder;

const SBOX_REGISTERS: usize = 1;
type LinearLayers = GenericPoseidon2LinearLayersBabyBear;
pub type PermutationAir = Poseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
>;
pub type PermutationCols<T> = Poseidon2Cols<
    T,
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
>;
const CONSTANTS: RoundConstants<
    Val,
    WIDTH,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
> = RoundConstants::new(
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_32_INTERNAL,
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_FINAL,
);

/// Plonky3's rules for one permutation.
pub static PERMUTATION: PermutationAir = PermutationAir::new(CONSTANTS);

/// The columns of one permutation.
pub const PERMUTATION_COLS: usize = num_cols::<
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
>();

/// Hashes `input`, which fits in one permutation, and returns the
/// permutation's `PERMUTATION_COLS` columns.
pub fn sponge_trace(input: impl Iterator<Item = Val>) -> Vec<Val> {
    let input: Vec<Val> = input.collect();
    assert!(input.len() <= RATE, "the input fits in one permutation");
    let mut state = [Val::ZERO; WIDTH];
    state[..input.len()].copy_from_slice(&input);
    generate_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        BABYBEAR_S_BOX_DEGREE,
        SBOX_REGISTERS,
        BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
        BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
    >(vec![state], &CONSTANTS, 0)
    .values
}

/// The state a permutation ends in.
pub fn output<T: Copy>(columns: &PermutationCols<T>) -> [T; WIDTH] {
    let [.., last] = &columns.ending_full_rounds;
    last.post
}

/// The rules of a commitment at column `first`:
///
/// - Plonky3's rules for the permutation
/// - its input is `domain`, then `len` values, then zeros
/// - it ends in `digest`
pub fn eval_commitment<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    first: usize,
    domain: Val,
    len: usize,
    digest: [impl Into<AB::Expr>; DIGEST_ELEMENTS],
) {
    assert!(
        len < RATE,
        "the domain and the values fit in one permutation"
    );
    let main = builder.main();
    let row = main.current_slice();
    let columns = first..first + PERMUTATION_COLS;

    // Plonky3's Poseidon2 rules: the permutation is computed correctly.
    PERMUTATION.eval(&mut SubAirBuilder::<AB, PermutationAir, AB::Var>::new(
        builder,
        columns.clone(),
    ));

    let permutation: &PermutationCols<AB::Var> = row[columns].borrow();
    let [domain_column, values @ ..] = &permutation.inputs;
    builder.assert_eq(*domain_column, domain);
    for &zero in &values[len..] {
        builder.assert_zero(zero);
    }
    // The commitment is the first `DIGEST_ELEMENTS` of the state.
    let state = output(permutation);
    for (&value, expected) in state[..DIGEST_ELEMENTS].iter().zip(digest) {
        builder.assert_eq(value, expected);
    }
}

/// The permutation whose columns start `columns`.
#[cfg(test)]
pub fn permutation(columns: &[Val]) -> &PermutationCols<Val> {
    columns[..PERMUTATION_COLS].borrow()
}
