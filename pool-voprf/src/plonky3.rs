//! The Plonky3 backend over BabyBear.
//!
//! Zero knowledge is not Plonky3's default. It comes from the hiding
//! commitment scheme.

mod key_air;

pub use key_air::KeyAir;

use crate::commitment;
use p3_baby_bear::{Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeField32};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::TruncatedPermutation;
use p3_uni_stark::{PcsError, PcsProverError, ProvingError, StarkConfig, VerificationError};
use rand::rngs::StdRng;
use rand::{CryptoRng, SeedableRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

type Val = commitment::Element;

// TODO: is this the right setting?
type Challenge = BinomialExtensionField<Val, 4>;
const CHALLENGE_DIMENSION: usize = <Challenge as BasedVectorSpace<Val>>::DIMENSION;

type LeafHash = commitment::Sponge;

/// A Merkle node has two children. Hashing an inner node feeds both child
/// digests.
const CHILDREN: usize = 2;
const NODE_ELEMENTS: usize = CHILDREN * commitment::DIGEST_ELEMENTS;
type Compress = TruncatedPermutation<
    Poseidon2BabyBear<NODE_ELEMENTS>,
    CHILDREN,
    { commitment::DIGEST_ELEMENTS },
    NODE_ELEMENTS,
>;

const SECURITY_BITS: usize = 128;
const SALT_ELEMS: usize = SECURITY_BITS.div_ceil(Val::ORDER_U32.ilog2() as usize);

/// The Merkle trees.
type Packed = <Val as Field>::Packing;
type ValMmcs = MerkleTreeHidingMmcs<
    Packed,
    Packed,
    LeafHash,
    Compress,
    StdRng,
    CHILDREN,
    { commitment::DIGEST_ELEMENTS },
    SALT_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

type Challenger =
    DuplexChallenger<Val, commitment::Permutation, { commitment::WIDTH }, { commitment::RATE }>;

type Dft = Radix2DitParallel<Val>;

type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;

/// The STARK configuration of this backend.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// A proof of any statement, under this configuration.
pub type Proof = p3_uni_stark::Proof<Config>;

/// Random columns masking the trace; at least the challenge dimension.
const NUM_RANDOM_CODEWORDS: usize = CHALLENGE_DIMENSION;

#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("the witness does not satisfy the statement")]
    WrongWitness,
    #[error("proving failed")]
    Prover(#[source] ProvingError<PcsProverError<Config>>),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("the proof does not verify")]
    Invalid(#[source] VerificationError<PcsError<Config>>),
    /// The verifier panicked, which Plonky3 documents can happen on a
    /// malformed proof.
    #[error("the proof is malformed")]
    Malformed,
}

pub struct Plonky3 {
    pub(super) config: Config,
}

impl Default for Plonky3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Plonky3 {
    pub fn new() -> Self {
        Self::from_rng(&mut rand::rng())
    }

    pub fn from_rng(rng: &mut impl CryptoRng) -> Self {
        let val_mmcs = ValMmcs::new(
            commitment::sponge(),
            Compress::new(default_babybear_poseidon2_16()),
            0,
            StdRng::from_rng(rng),
        );
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters::new_benchmark_zk(challenge_mmcs);
        let pcs = Pcs::new(
            Dft::default(),
            val_mmcs,
            fri,
            NUM_RANDOM_CODEWORDS,
            StdRng::from_rng(rng),
        );
        let challenger = Challenger::new(commitment::permutation());
        Self {
            config: Config::new(pcs, challenger),
        }
    }

    /// Run Plonky3's verifier, which it says may panic on a malformed proof
    /// and asks callers to catch.
    pub(super) fn verified(
        check: impl FnOnce() -> Result<(), VerificationError<PcsError<Config>>>,
    ) -> Result<(), VerifyError> {
        catch_unwind(AssertUnwindSafe(check))
            .map_err(|_| VerifyError::Malformed)?
            .map_err(VerifyError::Invalid)
    }
}
