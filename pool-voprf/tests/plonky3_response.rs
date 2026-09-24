#![cfg(feature = "plonky3")]

use pool_prf::params::{DELTA, Q, Zdelta};
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::proof::ProofSystem;
use pool_voprf::response::{ResponseStatement, ResponseWitness};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::time::Instant;

fn prover() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

fn verifier() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(2))
}

/// A random statement and its witness, from `seed`.
fn statement(seed: u64) -> (ResponseStatement, ResponseWitness) {
    let mut rng = StdRng::seed_from_u64(seed);
    let witness = ResponseWitness {
        a_sigma_sum: rng.random_range(0..Q),
        pads: rng.random(),
    };
    let b_bar_prime = rng.random_range(0..DELTA as Zdelta);
    (
        ResponseStatement::for_witness(&witness, b_bar_prime),
        witness,
    )
}

#[test]
fn proves_and_verifies_the_response() {
    let (statement, witness) = statement(2);

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
    let (_, witness) = statement(3);
    let (other, _) = statement(4);
    assert!(matches!(
        prover().prove(&other, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_another_response() {
    let (statement, witness) = statement(5);
    let (other, _) = self::statement(6);
    let proof = prover().prove(&statement, &witness).expect("proving");
    assert!(matches!(
        verifier().verify(&other, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn proof_ser_deser() {
    let (statement, witness) = statement(7);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    verifier().verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let (statement, witness) = statement(8);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let mut bytes = bincode::serialize(&proof).expect("serializing");
    let at = bytes.len() / 3;
    bytes[at] ^= 0x42;
    if let Ok(proof) = bincode::deserialize(&bytes) {
        assert!(verifier().verify(&statement, &proof).is_err());
    }
}
