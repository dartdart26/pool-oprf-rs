//! The Plonky3 backend: a univariate STARK over BabyBear with hiding FRI,
//! and BLAKE3 everywhere. Inside the circuit for the commitment, in the
//! Merkle trees of the commitment scheme, and in Fiat-Shamir. No other hash
//! assumption enters.
//!
//! Zero knowledge is not Plonky3's default. It comes from the hiding
//! commitment scheme, which salts Merkle leaves and masks the trace and
//! quotient with random polynomials, following Haböck and Kindi
//! (<https://eprint.iacr.org/2024/1037>). Both draw from a CSPRNG that
//! [`Plonky3::new`] seeds from the operating system.
//!
//! [`Plonky3::security`] grades a proof's parameters with Plonky3's own
//! soundness analysis.

mod compress;
mod key_air;

pub use key_air::{KeyAir, NUM_PUBLIC_VALUES};

use crate::key::{KeyStatement, commit};
use crate::proof::ProofSystem;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{
    AirLayout, ConjecturedSecurity, OpeningShape, PcsError, PcsProverError, Proof, ProvenSecurity,
    ProvingError, StarkConfig, StarkSecurityParams, VerificationError, prove, verify,
};
use pool_prf::prf::SecretKey;
use rand::rngs::StdRng;
use rand::{CryptoRng, SeedableRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

type Val = BabyBear;
/// The challenge field, BabyBear^4: about 124 bits.
type Challenge = BinomialExtensionField<Val, 4>;
const CHALLENGE_DIMENSION: usize = 4;
const CHALLENGE_BITS: usize = 124;

type ByteHash = p3_blake3::Blake3;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
/// BLAKE3's 256-bit digest.
const COLLISION_RESISTANCE_BITS: usize = 128;
/// Salt on every Merkle leaf: 5 field elements is 155 bits.
const SALT_ELEMS: usize = 5;
type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, StdRng, 2, 32, SALT_ELEMS>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;

/// The STARK configuration of this backend.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// A proof of a [`KeyStatement`].
pub type KeyProof = Proof<Config>;

// FRI parameters. Conjectured soundness is about `log_blowup` bits per query
// plus the proof of work, capped by the challenge field, see
// `Plonky3::security`.
const LOG_BLOWUP: usize = 3;
const NUM_QUERIES: usize = 40;
const QUERY_PROOF_OF_WORK_BITS: usize = 16;
/// Random columns masking the trace; at least the challenge dimension.
const NUM_RANDOM_CODEWORDS: usize = CHALLENGE_DIMENSION;

/// Trace rows. The hiding commitment masks every column with one value per
/// row and needs `rows >= 2 * (queries + dimension * opening points)` of
/// them, with one opening point here.
const LOG_ROWS: usize = 7;
const ROWS: usize = 1 << LOG_ROWS;
const _: () = assert!(
    ROWS >= 2 * (NUM_QUERIES + CHALLENGE_DIMENSION),
    "too few rows to hide"
);

fn fri_parameters(mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_PROOF_OF_WORK_BITS,
        mmcs,
    }
}

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

/// The backend: a configured prover and verifier.
pub struct Plonky3 {
    config: Config,
    fri: FriParameters<ChallengeMmcs>,
    air: KeyAir,
}

impl Default for Plonky3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Plonky3 {
    /// Seeded from the operating system. A verifier needs no randomness, but
    /// the configuration carries the prover's generators.
    pub fn new() -> Self {
        Self::from_rng(&mut rand::rng())
    }

    /// Seeded from `rng`. The hiding depends on this seed being
    /// unpredictable, so outside tests use [`Self::new`].
    pub fn from_rng(rng: &mut impl CryptoRng) -> Self {
        let byte_hash = p3_blake3::Blake3;
        let val_mmcs = ValMmcs::new(
            FieldHash::new(byte_hash),
            Compress::new(byte_hash),
            0,
            StdRng::from_rng(rng),
        );
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = fri_parameters(challenge_mmcs);
        let pcs = Pcs::new(
            Dft::default(),
            val_mmcs,
            fri.clone(),
            NUM_RANDOM_CODEWORDS,
            StdRng::from_rng(rng),
        );
        let challenger = Challenger::from_hasher(vec![], byte_hash);
        Self {
            config: Config::new(pcs, challenger),
            fri,
            air: KeyAir::new(),
        }
    }

    /// Plonky3's soundness grades for a proof under this configuration.
    pub fn security(&self, proof: &KeyProof) -> (ConjecturedSecurity, ProvenSecurity) {
        let params = StarkSecurityParams::from_air::<Val, Challenge, _>(
            self.fri.security_regime(),
            &self.air,
            AirLayout::from_air::<Val>(&self.air),
            TwoAdicMultiplicativeCoset::new(Val::ONE, LOG_ROWS).expect("a small power of two"),
            CHALLENGE_BITS,
            COLLISION_RESISTANCE_BITS,
            1,
            OpeningShape::hiding(NUM_RANDOM_CODEWORDS),
            self.fri.grinding_sites(),
        );
        (
            proof.conjectured_security(&params),
            proof.proven_security(&params),
        )
    }
}

impl ProofSystem<KeyStatement> for Plonky3 {
    type Proof = KeyProof;
    type ProveError = ProveError;
    type VerifyError = VerifyError;

    fn prove(&self, statement: &KeyStatement, sk: &SecretKey) -> Result<KeyProof, ProveError> {
        if commit(sk) != statement.pk {
            return Err(ProveError::WrongWitness);
        }
        let trace = self.air.trace(sk, ROWS);
        let public = KeyAir::public_values(&statement.pk);
        prove(&self.config, &self.air, trace, &public).map_err(ProveError::Prover)
    }

    fn verify(&self, statement: &KeyStatement, proof: &KeyProof) -> Result<(), VerifyError> {
        let public = KeyAir::public_values(&statement.pk);
        // Plonky3 says its verifier may panic on a malformed proof and asks
        // callers to catch that.
        catch_unwind(AssertUnwindSafe(|| {
            verify(&self.config, &self.air, proof, &public)
        }))
        .map_err(|_| VerifyError::Malformed)?
        .map_err(VerifyError::Invalid)
    }
}
