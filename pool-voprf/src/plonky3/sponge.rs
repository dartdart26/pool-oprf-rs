//! The sponge of [`commitments`](crate::plonky3::commitments) inside a
//! circuit.
//!
//! `commit` writes its input over a zero state of `WIDTH` elements, permutes
//! it with Poseidon2 and keeps the first `DIGEST_ELEMENTS` of the result.
//! The rest is dropped. Every input here fits in `WIDTH - CAPACITY` elements,
//! so one permutation.
//!
//! In the circuit, the permutation is [`CircuitSponge::COLS`] columns: its
//! input, then its rounds, the helper values and the state after each round.
//! [`WIDE`] permutes `WIDTH` elements and [`NARROW`] `NARROW_WIDTH`.

use crate::plonky3::Val;
use crate::plonky3::commitments::{CAPACITY, DIGEST_ELEMENTS, NARROW_WIDTH, WIDTH};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL,
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_32_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_32_INTERNAL, BABYBEAR_S_BOX_DEGREE, GenericPoseidon2LinearLayersBabyBear,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{
    Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows, num_cols,
};
use p3_uni_stark::SubAirBuilder;

const SBOX_REGISTERS: usize = 1;
type LinearLayers = GenericPoseidon2LinearLayersBabyBear;
pub type PermutationAir<const WIDTH: usize, const PARTIAL_ROUNDS: usize> = Poseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;
pub type PermutationCols<T, const WIDTH: usize, const PARTIAL_ROUNDS: usize> = Poseidon2Cols<
    T,
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// A Poseidon2 permutation of `WIDTH` elements, with `PARTIAL_ROUNDS`
/// partial rounds, in a circuit.
pub struct CircuitSponge<const WIDTH: usize, const PARTIAL_ROUNDS: usize> {
    constants: RoundConstants<Val, WIDTH, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// Plonky3's rules for the permutation.
    air: PermutationAir<WIDTH, PARTIAL_ROUNDS>,
}

pub type Wide = CircuitSponge<WIDTH, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32>;
pub type Narrow = CircuitSponge<NARROW_WIDTH, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16>;

/// The sponge of the key, masks and mask-sum commitments.
pub static WIDE: Wide = CircuitSponge::new(
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_32_INTERNAL,
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_FINAL,
);

/// The sponge of the pad commitments.
pub static NARROW: Narrow = CircuitSponge::new(
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
);

impl<const WIDTH: usize, const PARTIAL_ROUNDS: usize> CircuitSponge<WIDTH, PARTIAL_ROUNDS>
where
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
{
    /// The columns of one permutation.
    pub const COLS: usize = num_cols::<
        WIDTH,
        BABYBEAR_S_BOX_DEGREE,
        SBOX_REGISTERS,
        BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >();

    const fn new(
        initial: [[Val; WIDTH]; BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS],
        partial: [Val; PARTIAL_ROUNDS],
        last: [[Val; WIDTH]; BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS],
    ) -> Self {
        Self {
            constants: RoundConstants::new(initial, partial, last),
            air: PermutationAir::new(RoundConstants::new(initial, partial, last)),
        }
    }

    /// Hashes `input`, which fits in one permutation, and returns the
    /// permutation's [`Self::COLS`] columns.
    pub fn trace(&self, input: impl Iterator<Item = Val>) -> Vec<Val> {
        let input: Vec<Val> = input.collect();
        assert!(
            input.len() <= WIDTH - CAPACITY,
            "the input fits in one permutation"
        );
        let mut state = [Val::ZERO; WIDTH];
        state[..input.len()].copy_from_slice(&input);
        generate_trace_rows::<
            Val,
            LinearLayers,
            WIDTH,
            BABYBEAR_S_BOX_DEGREE,
            SBOX_REGISTERS,
            BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(vec![state], &self.constants, 0)
        .values
    }

    pub fn max_constraint_degree(&self) -> Option<usize> {
        self.air.max_constraint_degree()
    }

    /// The rules of a commitment at column `first`:
    ///
    /// - Plonky3's rules for the permutation
    /// - its input is `domain`, then `len` values, then zeros
    /// - it ends in `digest`
    pub fn eval_commitment<AB: AirBuilder<F = Val>>(
        &self,
        builder: &mut AB,
        first: usize,
        domain: Val,
        len: usize,
        digest: [impl Into<AB::Expr>; DIGEST_ELEMENTS],
    ) {
        assert!(
            len < WIDTH - CAPACITY,
            "the domain and the values fit in one permutation"
        );
        let main = builder.main();
        let row = main.current_slice();
        let columns = first..first + Self::COLS;

        // Plonky3's Poseidon2 rules: the permutation is computed correctly.
        self.air.eval(&mut SubAirBuilder::<
            AB,
            PermutationAir<WIDTH, PARTIAL_ROUNDS>,
            AB::Var,
        >::new(builder, columns.clone()));

        let permutation: &PermutationCols<AB::Var, WIDTH, PARTIAL_ROUNDS> = row[columns].borrow();
        let (domain_column, values) = permutation.inputs.split_first().expect("a domain");
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
    pub fn permutation<'a>(
        &self,
        columns: &'a [Val],
    ) -> &'a PermutationCols<Val, WIDTH, PARTIAL_ROUNDS> {
        columns[..Self::COLS].borrow()
    }
}

/// The state a permutation ends in.
pub fn output<T: Copy, const WIDTH: usize, const PARTIAL_ROUNDS: usize>(
    columns: &PermutationCols<T, WIDTH, PARTIAL_ROUNDS>,
) -> [T; WIDTH] {
    let [.., last] = &columns.ending_full_rounds;
    last.post
}
