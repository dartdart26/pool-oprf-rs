use crate::commitments::{CommitmentRandomness, MaskSumsInput, MasksInput, PadInput};
use crate::statements::online::{OnlineStatement, OnlineWitness, RunWitness};
use crate::statements::preprocessing::{
    EvaluationWitness, PreprocessingStatement, PreprocessingWitness,
};
use crate::traits::Commitment;
use core::array;
use pool_prf::params::{DELTA, N, Q, RUNS_PER_EVALUATION, Zdelta, Zq};
use pool_prf::prf::SecretKey;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

/// A random online witness and the honest statement for it, from `seed`.
pub fn random_online<PK, M, D>(seed: u64) -> (OnlineStatement<PK, M, D>, OnlineWitness)
where
    PK: Commitment<Input = SecretKey>,
    M: Commitment<Input = MaskSumsInput>,
    D: Commitment<Input = PadInput>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let witness = OnlineWitness {
        sk: SecretKey::random(&mut rng),
        m_randomness: rng.random(),
        runs: array::from_fn(|_| RunWitness {
            r_sigma_sum: rng.random_range(0..Q),
            pads: rng.random(),
            d_randomness: rng.random(),
        }),
    };
    let e = array::from_fn(|_| array::from_fn(|_| rng.random_range(0..Q)));
    let b_bar_prime = array::from_fn(|_| rng.random_range(0..DELTA as Zdelta));
    (OnlineStatement::honest(&witness, &e, &b_bar_prime), witness)
}

/// The mask of each run of an evaluation, random in ℤ_q.
fn random_masks(rng: &mut StdRng) -> [Zq; RUNS_PER_EVALUATION] {
    array::from_fn(|_| rng.random_range(0..Q))
}

/// `r̃^k_Σ` of each run `k`.
pub fn r_sigma_sums(
    sk: &SecretKey,
    masks: &[[Zq; RUNS_PER_EVALUATION]; N],
) -> [Zq; RUNS_PER_EVALUATION] {
    array::from_fn(|k| {
        let masks_of_run = array::from_fn(|i| masks[i][k]);
        pool_eval::r_sigma_sum(sk, &masks_of_run)
    })
}

/// A random preprocessing witness for `evaluations` evaluations and the
/// honest statement for it, from `seed`.
pub fn random_preprocessing<PK, C, M>(
    seed: u64,
    evaluations: usize,
) -> (PreprocessingStatement<PK, C, M>, PreprocessingWitness)
where
    PK: Commitment<Input = SecretKey>,
    C: Commitment<Input = MasksInput>,
    M: Commitment<Input = MaskSumsInput>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let sk = SecretKey::random(&mut rng);
    // The server's OT choice `b_i` of each `i`.
    let b: [u8; N] = array::from_fn(|_| rng.random_range(0..=1));
    let b_bar = array::from_fn(|i| b[i] ^ sk.as_bits()[i]);
    // The client's two OT blocks of each `i`.
    let client_ot_blocks: [[CommitmentRandomness; 2]; N] = array::from_fn(|_| rng.random());

    // `c` of each evaluation: the client's commitments to the masks of both
    // OT blocks of each `i`.
    let mut c = Vec::new();
    let mut evaluation_witnesses = Vec::new();
    for _ in 0..evaluations {
        // The client's masks of both OT blocks of each `i`.
        let client_masks: [[[Zq; RUNS_PER_EVALUATION]; 2]; N] =
            array::from_fn(|_| [random_masks(&mut rng), random_masks(&mut rng)]);
        c.push(array::from_fn(|i| {
            let [masks_0, masks_1] = client_masks[i];
            let [ot_block_0, ot_block_1] = client_ot_blocks[i];
            [
                C::commit(&MasksInput {
                    masks: masks_0,
                    randomness: ot_block_0,
                }),
                C::commit(&MasksInput {
                    masks: masks_1,
                    randomness: ot_block_1,
                }),
            ]
        }));

        // The server's masks are the ones of OT block `b_i`.
        let masks = array::from_fn(|i| client_masks[i][usize::from(b[i])]);
        evaluation_witnesses.push(EvaluationWitness {
            masks,
            r_sigma_sums: r_sigma_sums(&sk, &masks),
            // The protocol derives `randomness^v` from the 1-out-of-Δ OT blocks.
            // The proof does not check the derivation, therefore a random value is ok here.
            m_randomness: rng.random(),
        });
    }
    let witness = PreprocessingWitness {
        sk,
        ot_blocks: array::from_fn(|i| client_ot_blocks[i][usize::from(b[i])]),
        evaluations: evaluation_witnesses,
    };
    (PreprocessingStatement::honest(&witness, b_bar, c), witness)
}
