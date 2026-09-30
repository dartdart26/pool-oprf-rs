//! The interface between the protocol and a proof system.
//!
//! A [`Constraint`] is one relation between values.
//!
//! A proof is about a [`Statement`]: public values both parties hold plus a
//! witness only the prover holds, and the constraints that tie them.
//!
//! A [`ProofSystem`] is one circuit per statement.

mod commitment;
mod constraint;
mod proof_system;
mod statement;

pub use commitment::Commitment;
pub use constraint::Constraint;
pub use proof_system::ProofSystem;
pub use statement::Statement;
