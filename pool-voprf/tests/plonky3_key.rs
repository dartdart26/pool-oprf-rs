#![cfg(feature = "plonky3")]

use pool_prf::prf::SecretKey;
use pool_voprf::key::KeyStatement;
use pool_voprf::plonky3::{Plonky3, ProveError, VerifyError};
use pool_voprf::proof::ProofSystem;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

fn prover() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(1))
}

fn verifier() -> Plonky3 {
    Plonky3::from_rng(&mut StdRng::seed_from_u64(2))
}

#[test]
fn proves_and_verifies_the_committed_key() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(2));
    let statement = KeyStatement::for_key(&sk);

    let started = Instant::now();
    let proof = prover().prove(&statement, &sk).expect("proving");
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
fn refuses_to_prove_with_a_key_that_does_not_open_pk() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(3));
    let other = SecretKey::random(&mut StdRng::seed_from_u64(4));
    assert!(matches!(
        prover().prove(&KeyStatement::for_key(&other), &sk),
        Err(ProveError::WrongWitness)
    ));
}

#[test]
fn rejects_the_commitment_of_another_key() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(5));
    let other = SecretKey::random(&mut StdRng::seed_from_u64(6));
    let proof = prover()
        .prove(&KeyStatement::for_key(&sk), &sk)
        .expect("proving");
    assert!(matches!(
        verifier().verify(&KeyStatement::for_key(&other), &proof),
        Err(VerifyError::Invalid(_))
    ));
}

#[test]
fn proof_ser_deser() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(7));
    let statement = KeyStatement::for_key(&sk);
    let proof = prover().prove(&statement, &sk).expect("proving");
    let bytes = bincode::serialize(&proof).expect("serializing");
    let proof = bincode::deserialize(&bytes).expect("deserializing");
    verifier().verify(&statement, &proof).expect("verifying");
}

#[test]
fn rejects_a_tampered_proof() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(8));
    let statement = KeyStatement::for_key(&sk);
    let proof = prover().prove(&statement, &sk).expect("proving");
    let mut bytes = bincode::serialize(&proof).expect("serializing");
    let at = bytes.len() / 3;
    bytes[at] ^= 0x42;
    if let Ok(proof) = bincode::deserialize(&bytes) {
        assert!(verifier().verify(&statement, &proof).is_err());
    }
}
