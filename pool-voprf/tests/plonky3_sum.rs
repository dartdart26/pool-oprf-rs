#![cfg(feature = "plonky3")]

use core::array;
use pool_prf::params::{N, Q, Zq};
use pool_prf::prf::SecretKey;
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::proof::ProofSystem;
use pool_voprf::sum::{SumStatement, SumWitness};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::time::Instant;

fn prover() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

fn verifier() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(2))
}

fn vector(rng: &mut StdRng) -> [Zq; N] {
    array::from_fn(|_| rng.random_range(0..Q))
}

/// A random statement and its witness, from `seed`.
fn random(seed: u64) -> (SumStatement, SumWitness) {
    let mut rng = StdRng::seed_from_u64(seed);
    let witness = SumWitness {
        sk: SecretKey::random(&mut rng),
        r_sigma_sum: rng.random_range(0..Q),
    };
    (
        SumStatement {
            e: vector(&mut rng),
        },
        witness,
    )
}

#[test]
fn proves_and_verifies_the_sum() {
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
fn refuses_to_prove_a_request_outside_zq() {
    let (mut statement, witness) = random(3);
    statement.e[0] = Q;
    assert!(matches!(
        prover().prove(&statement, &witness),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_another_request() {
    let (statement, witness) = random(4);
    let (other_statement, _) = random(5);
    let proof = prover().prove(&statement, &witness).expect("proving");
    assert!(matches!(
        verifier().verify(&other_statement, &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn proof_ser_deser() {
    let (statement, witness) = random(6);
    let proof = prover().prove(&statement, &witness).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    verifier().verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let (statement, witness) = random(7);
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
