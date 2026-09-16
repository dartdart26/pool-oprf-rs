//! Constraint (K) on Plonky3.
//!
//! `commit` writes its input over a zero state of `WIDTH` elements,
//! permutes it with Poseidon2 and keeps the first `DIGEST_ELEMENTS` of the
//! result. The rest is dropped.
//!
//! In order, Poseidon2 takes `WIDTH` slots:
//!
//! | slots                 | content                                   |
//! |-----------------------|-------------------------------------------|
//! | 1                     | the domain                                |
//! | `PACKED_KEY_ELEMENTS` | the key, `BITS_PER_ELEMENT` bits per slot |
//! | the rest              | zero                                      |
//!
//! The rest is the `CAPACITY` slots, which never take input, plus the
//! input slots the key does not fill.
//!
//! Plonky3 checks Poseidon2 itself. We add these rules for (K):
//!
//! - every key bit is 0 or 1
//! - Poseidon2's input is what `commit` gives it: the domain, the key bits
//!   read as numbers, and zeros in the other slots
//! - the first `DIGEST_ELEMENTS` of Poseidon2's output are `pk`, which the
//!   verifier supplies

use crate::commitment::{DIGEST_ELEMENTS, RATE, WIDTH};
use crate::key::{
    BITS_PER_ELEMENT, INPUT_ELEMENTS, KeyCommitment, KeyStatement, PACKED_KEY_ELEMENTS, commit,
    elements, pack_key,
};
use crate::plonky3::{Plonky3, Proof, ProveError, Val, VerifyError};
use crate::proof::ProofSystem;
use core::array;
use core::borrow::Borrow;
use core::ops::Range;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
    BABYBEAR_POSEIDON2_RC_32_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_32_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_32_INTERNAL, BABYBEAR_S_BOX_DEGREE, GenericPoseidon2LinearLayersBabyBear,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{
    Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows, num_cols,
};
use p3_uni_stark::{SubAirBuilder, prove, verify};
use pool_prf::params::N;
use pool_prf::prf::SecretKey;

const SBOX_REGISTERS: usize = 1;
type LinearLayers = GenericPoseidon2LinearLayersBabyBear;
type PermutationAir = Poseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
>;
type PermutationCols<T> = Poseidon2Cols<
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
static PERMUTATION: PermutationAir = PermutationAir::new(CONSTANTS);
const PERMUTATION_COLS: usize = num_cols::<
    WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_32,
>();

// The row, `NUM_COLS` wide. `ROWS` of them, all containing the same values:
//
// | columns             | content                                             |
// |---------------------|-----------------------------------------------------|
// | `N`                 | the key bits, one per column                        |
// | `WIDTH`             | Poseidon2's input: the domain, the key bits, then   |
// |                     | zeros                                               |
// | the rest of the run | Poseidon2's rounds: the helper values and the state |
// |                     | after each round. The last state starts with `pk`   |
//
// The input and the rounds are one run, `PERMUTATION_COLS` together, and
// there are `PERMUTATIONS` runs.
const PERMUTATIONS: usize = INPUT_ELEMENTS.div_ceil(RATE);
const NUM_COLS: usize = N + PERMUTATIONS * PERMUTATION_COLS;

const fn permutation_columns(index: usize) -> Range<usize> {
    let start = N + index * PERMUTATION_COLS;
    start..start + PERMUTATION_COLS
}

/// How many times the row is repeated. Must be a power of 2.
/// Needed for hiding.
const ROWS: usize = 256;

/// The rules for (K). Its public value is `pk`.
#[derive(Default)]
pub struct KeyAir;

impl KeyAir {
    /// The table for `sk` - [`ROWS`] copies of the row.
    pub fn trace(sk: &SecretKey) -> RowMajorMatrix<Val> {
        let packed = pack_key(sk);
        let bits = sk.as_bits().iter().map(|&bit| Val::from_bool(bit == 1));
        let hash = sponge_trace(KeyCommitment::input(elements(&packed)));
        let row: Vec<Val> = bits.chain(hash).collect();
        RowMajorMatrix::new(row.repeat(ROWS), NUM_COLS)
    }
}

/// Hashes `input` and returns the columns of every Poseidon2 run, `PERMUTATION_COLS` each,
/// one after the other.
fn sponge_trace(input: impl Iterator<Item = Val>) -> Vec<Val> {
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
fn output<T: Copy>(columns: &PermutationCols<T>) -> [T; WIDTH] {
    let [.., last] = &columns.ending_full_rounds;
    last.post
}

impl BaseAir<Val> for KeyAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// A row holds all of (K), so no rule reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        PERMUTATION.max_constraint_degree()
    }

    fn num_public_values(&self) -> usize {
        DIGEST_ELEMENTS
    }
}

/// Takes the key's bit columns and returns element `index` of the packed
/// key. Works in the same way as `pack_key`.
fn packed<AB: AirBuilder>(bits: &[AB::Var], index: usize) -> AB::Expr {
    let element = bits
        .chunks(BITS_PER_ELEMENT)
        .nth(index)
        .expect("an element's bits");
    element
        .iter()
        .enumerate()
        .map(|(position, &bit)| bit * AB::F::from_u32(1 << position))
        .sum()
}

impl<AB: AirBuilder<F = Val>> Air<AB> for KeyAir {
    fn eval(&self, builder: &mut AB) {
        let pk: [AB::PublicVar; DIGEST_ELEMENTS] = builder.public_values().try_into().expect("pk");
        let main = builder.main();
        let row = main.current_slice();
        let bits = &row[..N];

        // Every key bit is 0 or 1.
        for &bit in bits {
            builder.assert_bool(bit);
        }

        let elements: [AB::Expr; PACKED_KEY_ELEMENTS] =
            array::from_fn(|index| packed::<AB>(bits, index));
        let mut input = KeyCommitment::input(elements);
        let mut state: [AB::Expr; WIDTH] = array::from_fn(|_| AB::Expr::ZERO);
        for index in 0..PERMUTATIONS {
            let columns = permutation_columns(index);

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

            // Its output is where the next permutation starts, or pk after the last.
            state = output(permutation).map(Into::into);
        }
        assert!(input.next().is_none(), "the sponge absorbed everything");

        // The digest is pk.
        for (value, expected) in state.into_iter().zip(pk) {
            builder.assert_eq(value, expected);
        }
    }
}

impl ProofSystem<KeyStatement> for Plonky3 {
    type Proof = Proof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(&self, statement: &KeyStatement, sk: &SecretKey) -> Result<Proof, ProveError> {
        if commit(sk) != statement.pk {
            return Err(ProveError::WrongWitness);
        }
        let trace = KeyAir::trace(sk);
        prove(&self.config, &KeyAir, trace, &statement.pk.0).map_err(ProveError::Prover)
    }

    fn verify(&self, statement: &KeyStatement, proof: &Proof) -> Result<(), VerifyError> {
        Plonky3::verified(|| verify(&self.config, &KeyAir, proof, &statement.pk.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::sponge;
    use p3_air::check_constraints;
    use p3_matrix::Matrix;
    use p3_symmetric::CryptographicHasher;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn last_run(columns: &[Val]) -> &PermutationCols<Val> {
        columns
            .chunks(PERMUTATION_COLS)
            .last()
            .expect("a run")
            .borrow()
    }

    #[test]
    fn the_trace_ends_in_the_commitment() {
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(1));
        let trace = KeyAir::trace(&sk);
        let row = trace.row_slice(0).expect("a row");
        assert_eq!(
            output(last_run(&row[N..]))[..DIGEST_ELEMENTS],
            commit(&sk).0
        );
    }

    #[test]
    fn the_sponge_carries_state_between_permutations() {
        let input = vec![Val::ONE; 2 * RATE + 3];
        let columns = sponge_trace(input.iter().copied());
        let expected: [Val; DIGEST_ELEMENTS] = sponge().hash_slice(&input);
        assert_eq!(output(last_run(&columns))[..DIGEST_ELEMENTS], expected);
    }

    #[test]
    fn a_key_bit_that_is_not_a_bit_is_refused() {
        let mut bits = [0; N];
        bits[1] = 1;
        let sk = SecretKey::from_bits(bits).expect("a key");
        let statement = KeyStatement::for_key(&sk);

        let mut trace = KeyAir::trace(&sk);
        check_constraints(&KeyAir, &trace, &statement.pk.0);
        for row in trace.values.chunks_mut(NUM_COLS) {
            row[0] = Val::TWO;
            row[1] = Val::ZERO;
        }
        let refused =
            std::panic::catch_unwind(|| check_constraints(&KeyAir, &trace, &statement.pk.0));
        let message = refused
            .expect_err("refused")
            .downcast::<String>()
            .expect("a message");
        assert!(message.contains("failed constraints = [#0]"), "{message}");
    }

    #[test]
    fn every_element_of_pk_is_checked() {
        let system = Plonky3::from_rng(&mut StdRng::seed_from_u64(1));
        let sk = SecretKey::random(&mut StdRng::seed_from_u64(2));
        let statement = KeyStatement::for_key(&sk);
        let proof = system.prove(&statement, &sk).expect("proving");
        system.verify(&statement, &proof).expect("verifying");
        for i in 0..statement.pk.0.len() {
            let mut pk = statement.pk;
            pk.0[i] += Val::ONE;
            assert!(
                system.verify(&KeyStatement { pk }, &proof).is_err(),
                "element {i} of pk is not checked"
            );
        }
    }
}
