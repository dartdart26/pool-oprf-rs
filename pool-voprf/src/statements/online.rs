//! The online statement: what the server proves with every response.
//!
//! Its constraints are (K), (A), (R), (M) and (P).

use crate::constraints::key::Key;
use crate::constraints::response::Response;
use crate::constraints::sum::Sum;
use crate::traits::{Commitment, Constraint, Statement};
use pool_prf::params::{DELTA, N, Zdelta, Zp, Zq};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OnlineStatement<PK> {
    pub pk: PK,
    pub e: [Zq; N],
    /// `b̄′`, in `0 .. Δ-1`.
    pub b_bar_prime: Zdelta,
    /// `y_0 .. y_{Δ-1}`.
    pub y: [Zp; DELTA],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OnlineWitness {
    pub sk: SecretKey,
    /// `r̃_Σ`.
    pub r_sigma_sum: Zq,
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: [Zp; DELTA],
}

impl<PK: Commitment<Value = SecretKey>> OnlineStatement<PK> {
    /// The statement an honest server makes.
    pub fn for_witness(witness: &OnlineWitness, e: [Zq; N], b_bar_prime: Zdelta) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &e);
        Self {
            pk: PK::commit(&witness.sk),
            y: pool_eval::respond(a_sigma_sum, &witness.pads, b_bar_prime),
            e,
            b_bar_prime,
        }
    }
}

impl<PK: Commitment<Value = SecretKey>> Statement for OnlineStatement<PK> {
    type Witness = OnlineWitness;

    fn holds_for(&self, witness: &OnlineWitness) -> bool {
        let key = Key {
            pk: &self.pk,
            sk: &witness.sk,
        };
        let sum = Sum {
            e: &self.e,
            sk: &witness.sk,
            r_sigma_sum: witness.r_sigma_sum,
        };
        let response = Response {
            y: &self.y,
            b_bar_prime: self.b_bar_prime,
            a_sigma_sum: sum.a_sigma_sum(),
            pads: &witness.pads,
        };
        key.holds() && sum.holds() && response.holds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;
    use pool_prf::params::Q;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// A stand-in for a backend's `pk`: the key itself.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Plain([u8; N]);

    impl Commitment for Plain {
        type Value = SecretKey;

        fn commit(sk: &SecretKey) -> Self {
            Self(*sk.as_bits())
        }
    }

    /// A random witness and the honest statement for it, from `seed`.
    fn random(seed: u64) -> (OnlineStatement<Plain>, OnlineWitness) {
        let mut rng = StdRng::seed_from_u64(seed);
        let witness = OnlineWitness {
            sk: SecretKey::random(&mut rng),
            r_sigma_sum: rng.random_range(0..Q),
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
    fn the_honest_statement_holds() {
        let (statement, witness) = random(1);
        assert!(statement.holds_for(&witness));
    }

    /// Only (K) refuses this.
    #[test]
    fn the_commitment_of_another_key_does_not_hold() {
        let (mut statement, witness) = random(2);
        statement.pk = Plain::commit(&SecretKey::random(&mut StdRng::seed_from_u64(3)));
        assert!(!statement.holds_for(&witness));
    }

    /// `r̃_Σ = q` gives the same `ã_Σ` as `r̃_Σ = 0`, so only (A) refuses
    /// this.
    #[test]
    fn an_r_sigma_sum_outside_zq_does_not_hold() {
        let (_, mut witness) = random(4);
        witness.r_sigma_sum = 0;
        let statement = OnlineStatement::<Plain>::for_witness(&witness, [0; N], 0);
        assert!(statement.holds_for(&witness));
        witness.r_sigma_sum = Q;
        assert!(!statement.holds_for(&witness));
    }

    /// Only (R) refuses this.
    #[test]
    fn a_wrong_response_does_not_hold() {
        let (mut statement, witness) = random(5);
        statement.y[DELTA - 1] ^= 1;
        assert!(!statement.holds_for(&witness));
    }
}
