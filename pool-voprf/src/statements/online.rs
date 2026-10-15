//! The online statement: what the server proves with every response.
//!
//! Its constraints are (K), (A), (R), (M) and (P).
//!
//! An online response is one evaluation, i.e. `RUNS_PER_EVALUATION` runs of
//! the protocol, one per output element. The secret key is the same in every
//! run, so (K) is in the statement once. `m` commits to the `r̃_Σ` of every
//! run at once, so (M) is in the statement once too. (P), (A) and (R) are per
//! run.

use crate::commitments::{CommitmentRandomness, MaskSumsInput, PadInput};
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
    pub m: M,
    pub runs: [RunStatement<D>; RUNS_PER_EVALUATION],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RunStatement<D> {
    /// `d_0 .. d_{Δ-1}`, the server's commitments to its pads
    pub d: [D; DELTA],
    /// `e_1 .. e_n`, from the client's request
    pub e: [Zq; N],
    /// `b̄′`, from the client's request
    pub b_bar_prime: Zdelta,
    /// `y_0 .. y_{Δ-1}`
    pub y: [Zp; DELTA],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OnlineWitness {
    pub sk: SecretKey,
    pub m_randomness: CommitmentRandomness,
    pub runs: [RunWitness; RUNS_PER_EVALUATION],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RunWitness {
    /// `r̃_Σ`.
    pub r_sigma_sum: Zq,
    /// `r′_0 .. r′_{Δ-1}`.
    pub pads: [Zp; DELTA],
    pub d_randomness: [CommitmentRandomness; DELTA],
}

impl OnlineWitness {
    pub fn r_sigma_sums(&self) -> [Zq; RUNS_PER_EVALUATION] {
        array::from_fn(|k| self.runs[k].r_sigma_sum)
    }
}

impl<PK, M, D> OnlineStatement<PK, M, D>
where
    PK: Commitment<Input = SecretKey>,
    M: Commitment<Input = MaskSumsInput>,
    D: Commitment<Input = PadInput>,
{
    pub fn honest(
        witness: &OnlineWitness,
        e: &[[Zq; N]; RUNS_PER_EVALUATION],
        b_bar_prime: &[Zdelta; RUNS_PER_EVALUATION],
    ) -> Self {
        Self {
            pk: PK::commit(&witness.sk),
            m: M::commit(&MaskSumsInput {
                r_sigma_sums: witness.r_sigma_sums(),
                randomness: witness.m_randomness,
            }),
            runs: array::from_fn(|k| {
                RunStatement::honest(&witness.sk, &witness.runs[k], e[k], b_bar_prime[k])
            }),
        }
    }
}

impl<D: Commitment<Input = PadInput>> RunStatement<D> {
    pub fn honest(sk: &SecretKey, witness: &RunWitness, e: [Zq; N], b_bar_prime: Zdelta) -> Self {
        let a_sigma_sum = pool_eval::a_sigma_sum(sk, witness.r_sigma_sum, &e);
        Self {
            d: array::from_fn(|j| {
                D::commit(&PadInput {
                    pad: witness.pads[j],
                    randomness: witness.d_randomness[j],
                })
            }),
            y: pool_eval::respond(a_sigma_sum, &witness.pads, b_bar_prime),
            e,
            b_bar_prime,
        }
    }

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
    PK: Commitment<Input = SecretKey>,
    M: Commitment<Input = MaskSumsInput>,
    D: Commitment<Input = PadInput>,
{
    type Witness = OnlineWitness;

    fn holds_for(&self, witness: &OnlineWitness) -> bool {
        let key = Key {
            pk: &self.pk,
            sk: &witness.sk,
        };
        let mask_sum = MaskSum {
            m: &self.m,
            r_sigma_sum: &witness.r_sigma_sums(),
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
