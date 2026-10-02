//! The online statement: what the server proves with every response.
//!
//! Its constraints are (K), (A), (R), (M) and (P).
//!
//! A response is one evaluation: `RUNS_PER_EVALUATION` runs of the
//! protocol, one per output element. The key is the same in every run, so
//! (K) is in the statement once. `m` commits to the `r̃_Σ` of every run at
//! once, so (M) is in the statement once too. (P), (A) and (R) are per
//! run.

use crate::CommitmentRandomness;
use crate::constraints::a_sum::Sum;
use crate::constraints::k_key::Key;
use crate::constraints::m_mask_sum::MaskSum;
use crate::constraints::p_pads::Pads;
use crate::constraints::r_response::Response;
use crate::traits::{Commitment, Constraint, Statement};
use core::array;
use pool_prf::params::{DELTA, N, RUNS_PER_EVALUATION, Zdelta, Zp, Zq};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OnlineStatement<PK, M, D> {
    pub pk: PK,
    /// `m`.
    pub m: M,
    pub runs: [Run<D>; RUNS_PER_EVALUATION],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OnlineWitness {
    pub sk: SecretKey,
    /// Hashed into `m` with the `r̃_Σ` of every run.
    pub m_randomness: CommitmentRandomness,
    pub runs: [RunWitness; RUNS_PER_EVALUATION],
}

/// One run: what the server committed to, the request and the response.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Run<D> {
    /// `d_0 .. d_{Δ-1}`.
    pub d: [D; DELTA],
    pub e: [Zq; N],
    /// `b̄′`, in `0 .. Δ-1`.
    pub b_bar_prime: Zdelta,
    /// `y_0 .. y_{Δ-1}`.
    pub y: [Zp; DELTA],
}

/// What only the server holds for one run.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RunWitness {
    /// `r̃_Σ`.
    pub r_sigma_sum: Zq,
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: [Zp; DELTA],
    /// Hashed into `d_j` with `r′_j`.
    pub d_randomness: [CommitmentRandomness; DELTA],
}

impl OnlineWitness {
    /// `r̃_Σ` of each run.
    pub fn r_sigma_sum(&self) -> [Zq; RUNS_PER_EVALUATION] {
        array::from_fn(|k| self.runs[k].r_sigma_sum)
    }
}

impl<PK, M, D> OnlineStatement<PK, M, D>
where
    PK: Commitment<Value = SecretKey>,
    M: Commitment<Value = ([Zq; RUNS_PER_EVALUATION], CommitmentRandomness)>,
    D: Commitment<Value = (Zp, CommitmentRandomness)>,
{
    /// The statement an honest server makes, for the `e` and `b̄′` of each
    /// run.
    pub fn for_witness(
        witness: &OnlineWitness,
        e: &[[Zq; N]; RUNS_PER_EVALUATION],
        b_bar_prime: &[Zdelta; RUNS_PER_EVALUATION],
    ) -> Self {
        Self {
            pk: PK::commit(&witness.sk),
            m: M::commit(&(witness.r_sigma_sum(), witness.m_randomness)),
            runs: array::from_fn(|k| {
                Run::for_witness(&witness.sk, &witness.runs[k], e[k], b_bar_prime[k])
            }),
        }
    }
}

impl<D: Commitment<Value = (Zp, CommitmentRandomness)>> Run<D> {
    /// The run an honest server makes.
    pub fn for_witness(
        sk: &SecretKey,
        witness: &RunWitness,
        e: [Zq; N],
        b_bar_prime: Zdelta,
    ) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(sk, witness.r_sigma_sum, &e);
        Self {
            d: array::from_fn(|j| D::commit(&(witness.pads[j], witness.d_randomness[j]))),
            y: pool_eval::respond(a_sigma_sum, &witness.pads, b_bar_prime),
            e,
            b_bar_prime,
        }
    }

    /// Whether (P), (A) and (R) hold.
    fn holds_for(&self, sk: &SecretKey, witness: &RunWitness) -> bool {
        let pads = Pads {
            d: &self.d,
            pads: &witness.pads,
            randomness: &witness.d_randomness,
        };
        let sum = Sum {
            e: &self.e,
            sk,
            r_sigma_sum: witness.r_sigma_sum,
        };
        let response = Response {
            y: &self.y,
            b_bar_prime: self.b_bar_prime,
            a_sigma_sum: sum.a_sigma_sum(),
            pads: &witness.pads,
        };
        pads.holds() && sum.holds() && response.holds()
    }
}

impl<PK, M, D> Statement for OnlineStatement<PK, M, D>
where
    PK: Commitment<Value = SecretKey>,
    M: Commitment<Value = ([Zq; RUNS_PER_EVALUATION], CommitmentRandomness)>,
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
            r_sigma_sum: &witness.r_sigma_sum(),
            randomness: witness.m_randomness,
        };
        let runs = self.runs.iter().zip(&witness.runs);
        key.holds()
            && mask_sum.holds()
            && runs
                .into_iter()
                .all(|(run, w)| run.holds_for(&witness.sk, w))
    }
}
