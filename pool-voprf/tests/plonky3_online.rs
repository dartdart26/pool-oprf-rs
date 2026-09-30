#![cfg(feature = "plonky3")]

use core::array;
use pool_prf::params::{DELTA, N, Q, Zdelta};
use pool_prf::prf::SecretKey;
use pool_voprf::plonky3::commitments::key::KeyCommitment;
use pool_voprf::plonky3::commitments::mask_sum::MaskSumCommitment;
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::statements::online::{OnlineStatement, OnlineWitness};
use pool_voprf::traits::ProofSystem;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::time::Instant;

fn prover() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

fn verifier() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(2))
}

/// A random witness and the honest statement for it, from `seed`.
fn random(
    seed: u64,
) -> (
    OnlineStatement<KeyCommitment, MaskSumCommitment>,
    OnlineWitness,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let witness = OnlineWitness {
        sk: SecretKey::random(&mut rng),
        r_sigma_sum: rng.random_range(0..Q),
        m_randomness: rng.random(),
        pads: rng.random(),
    };
    let e = array::from_fn(|_| rng.random_range(0..Q));
    let b_bar_prime = rng.random_range(0..DELTA as Zdelta);
    (
        OnlineStatement::for_witness(&witness, e, b_bar_prime),
        witness,
    )
}

#[test]
fn proves_and_verifies_the_response() {
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
fn refuses_to_prove_with_a_witness_of_another_response() {
    let (_, witness) = random(3);
    let (other_statement, _) = random(4);
    assert!(matches!(
        prover().prove(&other_statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn refuses_to_prove_a_request_outside_zq() {
    let (mut statement, witness) = random(5);
    statement.e[0] = Q;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn refuses_to_prove_with_an_r_sigma_sum_outside_zq() {
    let (statement, mut witness) = random(6);
    witness.r_sigma_sum = Q;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn refuses_to_prove_with_another_random_value_in_m() {
    let (statement, mut witness) = random(15);
    witness.m_randomness ^= 1;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_another_statement() {
    let (statement, witness) = random(7);
    let (other_statement, _) = random(8);
    let proof = prover().prove(&statement, &witness).expect("proving");
    assert!(matches!(
        verifier().verify(&other_statement, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn rejects_the_commitment_of_another_key() {
    let (statement, witness) = random(9);
    let (other_statement, _) = random(10);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let wrong = OnlineStatement {
        pk: other_statement.pk,
        ..statement
    };
    assert!(verifier().verify(&wrong, &proof).is_err());
}

#[test]
fn rejects_the_commitment_of_another_r_sigma_sum() {
    let (statement, witness) = random(16);
    let (other_statement, _) = random(17);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let wrong = OnlineStatement {
        m: other_statement.m,
        ..statement
    };
    assert!(verifier().verify(&wrong, &proof).is_err());
}

#[test]
fn rejects_another_request() {
    let (statement, witness) = random(11);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let mut wrong = statement;
    wrong.e[N - 1] ^= 1;
    assert!(verifier().verify(&wrong, &proof).is_err());
}

#[test]
fn rejects_another_response() {
    let (statement, witness) = random(12);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let mut wrong = statement;
    wrong.y[DELTA - 1] ^= 1;
    assert!(verifier().verify(&wrong, &proof).is_err());
}

#[test]
fn proof_ser_deser() {
    let (statement, witness) = random(13);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    verifier().verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let (statement, witness) = random(14);
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
