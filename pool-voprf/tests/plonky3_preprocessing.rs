#![cfg(feature = "plonky3")]

use pool_prf::prf::SecretKey;
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::statements::preprocessing::{PreprocessingStatement, PreprocessingWitness};
use pool_voprf::traits::ProofSystem;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

fn prover() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

fn verifier() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(2))
}

/// A random witness, from `seed`.
fn random(seed: u64) -> PreprocessingWitness {
    PreprocessingWitness {
        sk: SecretKey::random(&mut StdRng::seed_from_u64(seed)),
    }
}

#[test]
fn proves_and_verifies_the_preprocessing() {
    let witness = random(2);
    let statement = PreprocessingStatement::for_witness(&witness);

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
    let witness = random(3);
    let other = random(4);
    assert!(matches!(
        prover().prove(&PreprocessingStatement::for_witness(&other), &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_the_statement_of_another_preprocessing() {
    let witness = random(5);
    let other = random(6);
    let proof = prover()
        .prove(&PreprocessingStatement::for_witness(&witness), &witness)
        .expect("proving");
    assert!(matches!(
        verifier().verify(&PreprocessingStatement::for_witness(&other), &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn proof_ser_deser() {
    let witness = random(7);
    let statement = PreprocessingStatement::for_witness(&witness);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    verifier().verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let witness = random(8);
    let statement = PreprocessingStatement::for_witness(&witness);
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
