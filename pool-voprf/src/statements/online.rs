//! The online statement: what the server proves with every response.
//!
//! Its constraints are (K), (A), (R), (M) and (P).

use crate::CommitmentRandomness;
use crate::constraints::a_sum::Sum;
use crate::constraints::k_key::Key;
use crate::constraints::m_mask_sum::MaskSum;
use crate::constraints::p_pads::Pads;
use crate::constraints::r_response::Response;
use crate::traits::{Commitment, Constraint, Statement};
use core::array;
use pool_prf::params::{DELTA, N, Zdelta, Zp, Zq};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OnlineStatement<PK, M, D> {
    pub pk: PK,
    /// `m`.
    pub m: M,
    /// `d_0 .. d_{Δ-1}`.
    pub d: [D; DELTA],
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
    /// Hashed into `d_j` with `r′_j`.
    pub d_randomness: [CommitmentRandomness; DELTA],
}

impl<PK, M, D> OnlineStatement<PK, M, D>
where
    PK: Commitment<Value = SecretKey>,
    M: Commitment<Value = (Zq, CommitmentRandomness)>,
    D: Commitment<Value = (Zp, CommitmentRandomness)>,
{
    /// The statement an honest server makes.
    pub fn for_witness(witness: &OnlineWitness, e: [Zq; N], b_bar_prime: Zdelta) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(&witness.sk, witness.r_sigma_sum, &e);
        Self {
            pk: PK::commit(&witness.sk),
            m: M::commit(&(witness.r_sigma_sum, witness.m_randomness)),
            d: array::from_fn(|j| D::commit(&(witness.pads[j], witness.d_randomness[j]))),
            y: pool_eval::respond(a_sigma_sum, &witness.pads, b_bar_prime),
            e,
            b_bar_prime,
        }
    }
}

impl<PK, M, D> Statement for OnlineStatement<PK, M, D>
where
    PK: Commitment<Value = SecretKey>,
    M: Commitment<Value = (Zq, CommitmentRandomness)>,
    D: Commitment<Value = (Zp, CommitmentRandomness)>,
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
        let pads = Pads {
            d: &self.d,
            pads: &witness.pads,
            randomness: &witness.d_randomness,
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
        key.holds() && mask_sum.holds() && pads.holds() && sum.holds() && response.holds()
    }
}
