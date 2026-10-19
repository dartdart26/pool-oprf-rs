//! Helpers for tests.

use crate::voprf::{VerifiedKey, setup};
use pool_prf::prf::SecretKey;

pub fn verified_key(sk: &SecretKey) -> VerifiedKey {
    let (pk, proof) = setup(sk).expect("proving");
    VerifiedKey::verify(pk, &proof).expect("verifying")
}
