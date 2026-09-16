//! Verifiable Pool OPRF: server proofs as described in `docs/voprf.md`.
//!
//! [`proof`] is the interface: a [`proof::Statement`] per proof and a
//! [`proof::ProofSystem`] is the backend implementation.
//!
//! [`key`] is constraint (K).

pub mod key;
pub mod proof;

#[cfg(feature = "plonky3")]
pub mod plonky3;
