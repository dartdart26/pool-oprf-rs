#![cfg(feature = "plonky3")]

use pool_prf::params::{N, Q, RUNS_PER_EVALUATION};
use pool_voprf::plonky3::commitments::key::KeyCommitment;
use pool_voprf::plonky3::commitments::mask_sum::{self, MaskSumCommitment};
use pool_voprf::plonky3::commitments::masks::{self, MasksCommitment};
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::statements::preprocessing::{PreprocessingStatement, PreprocessingWitness};
use pool_voprf::testing;
use pool_voprf::traits::ProofSystem;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

type Statement = PreprocessingStatement<KeyCommitment, MasksCommitment, MaskSumCommitment>;

const EVALUATIONS: usize = 2;
const LAST: usize = EVALUATIONS - 1;

fn prover() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

fn verifier() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(2))
}

/// A random witness and the honest statement for it, from `seed`.
fn random(seed: u64) -> (Statement, PreprocessingWitness) {
    testing::random_preprocessing(seed, EVALUATIONS)
}

#[test]
fn proves_and_verifies_the_preprocessing() {
    let (statement, witness) = random(2);

    let started = Instant::now();
    let proof = prover().prove(&statement, &witness).expect("proving");
    let proving = started.elapsed();
    let bytes = bincode::serialize(&proof).expect("serializing");

    let started = Instant::now();
    verifier().verify(&statement, &proof).expect("verifying");
    let verifying = started.elapsed();

    eprintln!(
        "prove {proving:?}, verify {verifying:?}, proof {} bytes",
        bytes.len()
    );
}

#[test]
fn refuses_to_prove_with_the_witness_of_another_preprocessing() {
    let (_, witness) = random(3);
    let (other_statement, _) = random(4);
    assert!(matches!(
        prover().prove(&other_statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

/// (S) opens `c_{b̄_i ⊕ sk_i, i}` and, therefore, changing a b̄_i fails.
#[test]
fn refuses_to_prove_another_b_bar() {
    let (mut statement, witness) = random(5);
    statement.b_bar[N - 1] ^= 1;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

/// (T): an `r̃^k_Σ` that is not the sum of the masks.
#[test]
fn refuses_to_prove_another_r_sigma_sum() {
    let (mut statement, mut witness) = random(6);
    let evaluation = &mut witness.evaluations[LAST];
    evaluation.r_sigma_sums[RUNS_PER_EVALUATION - 1] ^= 1;
    statement.evaluations[LAST].m =
        mask_sum::commit(&evaluation.r_sigma_sums, evaluation.m_randomness);
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

/// (T): a mask outside ℤ_q.
#[test]
fn refuses_to_prove_with_a_mask_outside_zq() {
    let (mut statement, mut witness) = random(11);
    let i = N - 1;
    let b_i = usize::from(statement.b_bar[i] ^ witness.sk.as_bits()[i]);
    let server_masks = &mut witness.evaluations[LAST].masks[i];
    server_masks[0] = Q;
    statement.evaluations[LAST].c[i][b_i] = masks::commit(server_masks, witness.ot_blocks[i]);
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

/// (S): `c_{b_i, i}` does not open with another OT block.
#[test]
fn refuses_to_prove_with_another_ot_block() {
    let (statement, mut witness) = random(12);
    witness.ot_blocks[N - 1] ^= 1;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

/// (M): `m^v` does not open with another random value.
#[test]
fn refuses_to_prove_with_another_random_value_in_m() {
    let (statement, mut witness) = random(13);
    witness.evaluations[LAST].m_randomness ^= 1;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_the_statement_of_another_preprocessing() {
    let (statement, witness) = random(7);
    let (other, _) = random(8);
    let proof = prover().prove(&statement, &witness).expect("proving");
    assert!(matches!(
        verifier().verify(&other, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn rejects_the_commitment_of_another_key() {
    let (statement, witness) = random(14);
    let (other_statement, _) = random(15);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let wrong = Statement {
        pk: other_statement.pk,
        ..statement
    };
    assert!(matches!(
        verifier().verify(&wrong, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

/// Another `m^v` in the last evaluation.
#[test]
fn rejects_the_commitment_of_another_r_sigma_sum() {
    let (statement, witness) = random(16);
    let (other_statement, _) = random(17);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let mut wrong = statement;
    wrong.evaluations[LAST].m = other_statement.evaluations[LAST].m;
    assert!(matches!(
        verifier().verify(&wrong, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn rejects_a_statement_with_no_evaluation() {
    let (statement, witness) = random(18);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let mut wrong = statement;
    wrong.evaluations.clear();
    assert!(matches!(
        verifier().verify(&wrong, &proof),
        Err(VerifyError::NoEvaluation)
    ));
}

#[test]
fn proof_ser_deser() {
    let (statement, witness) = random(9);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    verifier().verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let (statement, witness) = random(10);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let mut bytes = bincode::serialize(&proof).expect("serializing");
    let at = bytes.len() / 3;
    bytes[at] ^= 0x42;
    let rejected = match bincode::deserialize(&bytes) {
        Ok(proof) => verifier().verify(&statement, &proof).is_err(),
        Err(_) => true,
    };
    assert!(rejected);
}
