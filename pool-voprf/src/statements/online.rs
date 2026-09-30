//! The online statement: what the server proves with every response.
//!
//! Its constraints are (K), (A), (R), (M) and (P).

use crate::CommitmentRandomness;
use crate::constraints::key::Key;
use crate::constraints::mask_sum::MaskSum;
use crate::constraints::response::Response;
use crate::constraints::sum::Sum;
use crate::traits::{Commitment, Constraint, Statement};
use pool_prf::params::{DELTA, N, Zdelta, Zp, Zq};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OnlineStatement<PK, M> {
    pub pk: PK,
    /// `m`.
    pub m: M,
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
    /// Hashed into `m` with `r̃_Σ`.
    pub m_randomness: CommitmentRandomness,
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: [Zp; DELTA],
}

impl<PK, M> OnlineStatement<PK, M>
where
    PK: Commitment<Value = SecretKey>,
    M: Commitment<Value = (Zq, CommitmentRandomness)>,
{
    /// The statement an honest server makes.
    pub fn for_witness(witness: &OnlineWitness, e: [Zq; N], b_bar_prime: Zdelta) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &e);
        Self {
            pk: PK::commit(&witness.sk),
            m: M::commit(&(witness.r_sigma_sum, witness.m_randomness)),
            y: pool_eval::respond(a_sigma_sum, &witness.pads, b_bar_prime),
            e,
            b_bar_prime,
        }
    }
}

impl<PK, M> Statement for OnlineStatement<PK, M>
where
    PK: Commitment<Value = SecretKey>,
    M: Commitment<Value = (Zq, CommitmentRandomness)>,
{
    type Witness = OnlineWitness;

    fn holds_for(&self, witness: &OnlineWitness) -> bool {
        let key = Key {
            pk: &self.pk,
            sk: &witness.sk,
        };
        let mask_sum = MaskSum {
            m: &self.m,
            r_sigma_sum: witness.r_sigma_sum,
            randomness: witness.m_randomness,
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
        key.holds() && mask_sum.holds() && sum.holds() && response.holds()
    }
}
