//! The sponge of [`commitments`](crate::plonky3::commitments) inside a
//! circuit.
//!
//! `commit` writes its input over a zero state of `WIDTH` elements, permutes
//! it with Poseidon2 and keeps the first `DIGEST_ELEMENTS` of the result.
//! The rest is dropped. An input longer than `RATE` elements takes more than
//! one permutation, each writing the next `RATE` elements over the state the
//! one before ended in.
//!
//! In the circuit, a permutation is `PERMUTATION_COLS` columns: its input,
//! then its rounds, the helper values and the state after each round. The
//! permutations of a sponge are one after the other. [`sponge_trace`] fills
//! them and [`eval_sponge`] checks them.

use crate::plonky3::Val;
use crate::plonky3::commitments::{DIGEST_ELEMENTS, RATE, WIDTH};
use core::array;
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

/// How many permutations an input of `elements` takes.
pub const fn permutations(elements: usize) -> usize {
    elements.div_ceil(RATE)
}

/// Hashes `input` and returns the columns of every permutation,
/// `PERMUTATION_COLS` each, one after the other.
pub fn sponge_trace(input: impl Iterator<Item = Val>) -> Vec<Val> {
    let mut columns = Vec::new();
    let mut state = [Val::ZERO; WIDTH];
    let mut input = input.peekable();
    while input.peek().is_some() {
        absorb(&mut state, &mut input);
        let permutation = generate_trace_rows::<
            Val,
            LinearLayers,
            WIDTH,
            BABYBEAR_S_BOX_DEGREE,
            SBOX_REGISTERS,
            BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
            BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
        >(vec![state], &CONSTANTS, 0);
        state = output(permutation.values[..].borrow());
        columns.extend(permutation.values);
    }
    columns
}

/// One step of the sponge.
fn absorb<T>(state: &mut [T; WIDTH], input: &mut impl Iterator<Item = T>) {
    for slot in state.iter_mut().take(RATE) {
        if let Some(element) = input.next() {
            *slot = element;
        }
    }
}

/// The state a permutation ends in.
pub fn output<T: Copy>(columns: &PermutationCols<T>) -> [T; WIDTH] {
    let [.., last] = &columns.ending_full_rounds;
    last.post
}

/// The rules of the sponge over `input`, whose permutations start at
/// column `first`:
///
/// - Plonky3's rules for each permutation
/// - each permutation takes its input from `input`, over the state the one
///   before ended in
/// - the state the last one ends in starts with `digest`
pub fn eval_sponge<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    first: usize,
    input: impl Iterator<Item = AB::Expr>,
    digest: [impl Into<AB::Expr>; DIGEST_ELEMENTS],
) {
    let main = builder.main();
    let row = main.current_slice();
    let mut input = input.peekable();
    let mut state: [AB::Expr; WIDTH] = array::from_fn(|_| AB::Expr::ZERO);
    let mut start = first;
    while input.peek().is_some() {
        let columns = start..start + PERMUTATION_COLS;

        // Plonky3's Poseidon2 rules: the permutation is computed correctly.
        PERMUTATION.eval(&mut SubAirBuilder::<AB, PermutationAir, AB::Var>::new(
            builder,
            columns.clone(),
        ));

        // The input it was given is the right one.
        absorb(&mut state, &mut input);
        let permutation: &PermutationCols<AB::Var> = row[columns].borrow();
        for (column, value) in permutation.inputs.iter().zip(&state) {
            builder.assert_eq(*column, value.clone());
        }

        // Its output is where the next permutation starts, or the digest after the last.
        state = output(permutation).map(Into::into);
        start += PERMUTATION_COLS;
    }

    // The digest.
    for (value, expected) in state.into_iter().zip(digest) {
        builder.assert_eq(value, expected);
    }
}

/// The columns of the last permutation in `columns`.
#[cfg(test)]
pub fn last_run(columns: &[Val]) -> &PermutationCols<Val> {
    columns
        .chunks(PERMUTATION_COLS)
        .last()
        .expect("a run")
        .borrow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::commitments;
    use p3_symmetric::CryptographicHasher;

    #[test]
    fn the_sponge_carries_state_between_permutations() {
        let input = vec![Val::ONE; 2 * RATE + 3];
        let columns = sponge_trace(input.iter().copied());
        let expected: [Val; DIGEST_ELEMENTS] = commitments::sponge().hash_slice(&input);
        assert_eq!(output(last_run(&columns))[..DIGEST_ELEMENTS], expected);
    }
}
