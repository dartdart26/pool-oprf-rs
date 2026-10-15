//! The preprocessing statement.
//!
//! Its constraints are (K), (S), (T) and (M).
//!
//! One preprocessing serves one or more evaluations. The secret key is the
//! same in every evaluation and, therefore, (K) is in the statement once.
//! (S), (T) and (M) are per evaluation.

use crate::commitments::{CommitmentRandomness, MaskSumsInput, MasksInput};
use crate::constraints::k_key::Key;
use crate::constraints::m_mask_sum::MaskSum;
use crate::constraints::s_masks::ServerMasks;
use crate::constraints::t_sum_of_masks::SumOfMasks;
use crate::traits::{Commitment, Constraint, Statement};
use pool_prf::params::{N, RUNS_PER_EVALUATION, Zq};
use pool_prf::prf::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreprocessingStatement<PK, C, M> {
    pub pk: PK,
    /// `b̄_0 .. b̄_{n-1}`, from the server.
    pub b_bar: [u8; N],
    pub evaluations: Vec<EvaluationStatement<C, M>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvaluationStatement<C, M> {
    /// `c_{0, i}` and `c_{1, i}` of each `i`, from the client.
    pub c: [[C; 2]; N],
    pub m: M,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PreprocessingWitness {
    pub sk: SecretKey,
    /// `ot_block_{b_i, i}` of each `i`: the server's binary OT blocks.
    pub ot_blocks: [CommitmentRandomness; N],
    pub evaluations: Vec<EvaluationWitness>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EvaluationWitness {
    /// `r^k_{b_i, i}` of each `i` and run `k`.
    pub masks: [[Zq; RUNS_PER_EVALUATION]; N],
    /// `r̃^k_Σ` of each run `k`.
    pub r_sigma_sums: [Zq; RUNS_PER_EVALUATION],
    pub m_randomness: CommitmentRandomness,
}

impl<PK, C, M> PreprocessingStatement<PK, C, M>
where
    PK: Commitment<Input = SecretKey>,
    C: Commitment<Input = MasksInput>,
    M: Commitment<Input = MaskSumsInput>,
{
    pub fn honest(witness: &PreprocessingWitness, b_bar: [u8; N], c: Vec<[[C; 2]; N]>) -> Self {
        let evaluations = c.into_iter().zip(&witness.evaluations);
        Self {
            pk: PK::commit(&witness.sk),
            b_bar,
            evaluations: evaluations
                .map(|(c, evaluation)| EvaluationStatement {
                    c,
                    m: M::commit(&MaskSumsInput {
                        r_sigma_sums: evaluation.r_sigma_sums,
                        randomness: evaluation.m_randomness,
                    }),
                })
                .collect(),
        }
    }
}

impl<C, M> EvaluationStatement<C, M>
where
    C: Commitment<Input = MasksInput>,
    M: Commitment<Input = MaskSumsInput>,
{
    fn holds_for(
        &self,
        b_bar: &[u8; N],
        sk: &SecretKey,
        ot_blocks: &[CommitmentRandomness; N],
        witness: &EvaluationWitness,
    ) -> bool {
        let masks = ServerMasks {
            c: &self.c,
            b_bar,
            sk,
            masks: &witness.masks,
            ot_blocks,
        };
        let sum_of_masks = SumOfMasks {
            sk,
            masks: &witness.masks,
            r_sigma_sums: &witness.r_sigma_sums,
        };
        let mask_sum = MaskSum {
            m: &self.m,
            r_sigma_sum: &witness.r_sigma_sums,
            randomness: witness.m_randomness,
        };
        masks.holds() && sum_of_masks.holds() && mask_sum.holds()
    }
}

impl<PK, C, M> Statement for PreprocessingStatement<PK, C, M>
where
    PK: Commitment<Input = SecretKey>,
    C: Commitment<Input = MasksInput>,
    M: Commitment<Input = MaskSumsInput>,
{
    type Witness = PreprocessingWitness;

    fn holds_for(&self, witness: &PreprocessingWitness) -> bool {
        let key = Key {
            pk: &self.pk,
            sk: &witness.sk,
        };
        let evaluations = self.evaluations.iter().zip(&witness.evaluations);
        key.holds()
            && !self.evaluations.is_empty()
            && self.evaluations.len() == witness.evaluations.len()
            && evaluations.into_iter().all(|(evaluation, w)| {
                evaluation.holds_for(&self.b_bar, &witness.sk, &witness.ot_blocks, w)
            })
    }
}
