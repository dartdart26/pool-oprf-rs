//! Verifiable Pool OPRF: server proofs as described in `docs/voprf.md`.

/// Commitments used by proofs.
pub mod commitment;

/// The interface: a [`proof::Statement`] per proof type and a
/// [`proof::ProofSystem`] per backend that proves and verifies them.
pub mod proof;

/// Constraint (K) - the commitment to the key, and the statement that `sk`
/// opens it.
pub mod key;

/// Plonky3 STARK as a backend.
#[cfg(feature = "plonky3")]
pub mod plonky3;
