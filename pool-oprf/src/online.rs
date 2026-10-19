//! Online phase of the Pool OPRF (Figure 4 of the paper).
//!
//! Request, BlindEval and Finalize each follow Figure 4, with two deviations
//! that apply to all three:
//!
//!  - **One evaluation is `H_ROWS` base runs.** A base run of the paper's
//!    protocol produces a single ℤ_p element, while the PRF output is a whole
//!    row vector, so every algorithm here does the single-row version once
//!    on each of `H_ROWS` consecutive runs. A [`ClientState`] with
//!    τ runs therefore supports τ / `H_ROWS` evaluations.
//!  - **One message may carry several evaluations.** Batching is not in the
//!    paper, but a caller with a set to evaluate (a PSI, say) would otherwise
//!    pay one round trip per element and lose the round-optimality the design
//!    is built for.

use crate::preprocessing::{ClientState, ServerState, Uid, tau_for};
use crate::voprf::{
    MAX_VOPRF_BATCH_EVALUATIONS, OnlineStatement, Proof, ProveError, VerifyError, verify_online,
};
use pool_prf::hash::{ZqMatrix, hash_to_zq_matrix};
use pool_prf::modular::{reduce_delta, reduce_q, sub_delta, sub_p};
use pool_prf::params::{DELTA, DELTA_ZQ, H_ROWS, N, OUTPUT_ELEMENTS, Q, Zdelta, Zp, Zq, ZqAccum};
use pool_prf::prf::{PrfOutput, SecretKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_TAG_LEN: usize = 1024;

/// Most evaluations one request may carry.
///
/// Batching is not part of the paper, but is something useful we do here.
pub const MAX_BATCH_EVALUATIONS: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("preprocessing exhausted: a request needs {needed} runs, only {have} left")]
    Exhausted { needed: usize, have: usize },
    #[error("tag is {len} bytes, the maximum is {MAX_TAG_LEN}")]
    TagTooLong { len: usize },
    #[error("a request must carry at least one evaluation")]
    EmptyBatch,
    #[error("batch of {len} evaluations, the maximum is {MAX_BATCH_EVALUATIONS}")]
    BatchTooLarge { len: usize },
    #[error("VOPRF batch of {len} evaluations, the maximum is {MAX_VOPRF_BATCH_EVALUATIONS}")]
    VoprfBatchTooLarge { len: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum BlindEvalError {
    #[error("no preprocessing state for session {uid:?}")]
    UnknownSession { uid: Uid },
    #[error("preprocessing exhausted: a request needs {needed} runs, only {have} left")]
    Exhausted { needed: usize, have: usize },
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("proving the response failed")]
    Prove(#[from] ProveError),
}

#[derive(Debug, thiserror::Error)]
pub enum FinalizeError {
    #[error("response is for session {got:?}, this request was session {want:?}")]
    SessionMismatch { want: Uid, got: Uid },
    #[error("malformed response: {0}")]
    Malformed(&'static str),
    #[error("response row {row} is for run {got}, this request used run {want}")]
    CounterMismatch { row: usize, want: u64, got: u64 },
    #[error("this request was a batch of {len} evaluations; use finalize_batch")]
    NotSingle { len: usize },
    #[error("the response proof does not verify")]
    Verify(#[from] VerifyError),
}

/// One row of a request. Figure 4's `Request` is the single-row protocol and
/// returns a whole message, `(t, (e_1, ..., e_n), b̄′, uid)`. An evaluation
/// runs `H_ROWS` of those, so a row is that tuple without `t` and `uid`, which
/// [`RequestMessage`] carries once for all the rows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowRequest {
    /// `e_i = a_i + r_i + r^ctr_{1-b̄_i,i} mod q`, for `i` in `[N]`,
    /// where `r_i = r^ctr_{b̄_i,i}`.
    #[serde(with = "crate::packing")]
    pub e: [Zq; N],
    /// `b̄′ = (r_Σ mod Δ - b′_ctr) mod Δ`.
    pub(crate) b_bar_prime: Zdelta,
}

/// The request message the client sends to the server (`req` in Figure 4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestMessage {
    pub(crate) uid: Uid,
    /// The public tag `t`, in the clear. At most [`MAX_TAG_LEN`] bytes.
    pub tag: Vec<u8>,
    /// One or more evaluations end to end, so a multiple of `H_ROWS`.
    pub rows: Vec<RowRequest>,
}

impl RequestMessage {
    pub(crate) fn evaluations(&self) -> usize {
        self.rows.len() / H_ROWS
    }
}

/// One row of a response. Figure 4's `BlindEval` is the single-row protocol
/// and returns a whole message, `((y_0, ..., y_{Δ-1}), uid, ctr)`. An
/// evaluation runs `H_ROWS` of those, so a row is that tuple without `uid`,
/// which [`ResponseMessage`] carries once for all the rows.
///
/// `ctr` stays per row, unlike the request's, because each row spent its own
/// run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowResponse {
    /// `y_i = ⌈(ã_Σ - i) mod q⌋_{q,p} + r′_{(i - b̄′) mod Δ, ctr} mod p`,
    /// for `i` in `[0, Δ)`.
    pub(crate) y: [Zp; DELTA],
    /// The preprocessing run this row consumed.
    pub(crate) ctr: u64,
}

/// The response message the server sends back (`rep` in Figure 4).
#[derive(Serialize, Deserialize)]
pub struct ResponseMessage {
    pub(crate) uid: Uid,
    pub(crate) rows: Vec<RowResponse>,
    /// `π_online` of each evaluation, if a VOPRF.
    pub(crate) proofs: Vec<Proof>,
}

/// A proof is not printed, only how many there are.
impl std::fmt::Debug for ResponseMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseMessage")
            .field("uid", &self.uid)
            .field("rows", &self.rows)
            .field("proofs", &self.proofs.len())
            .finish()
    }
}

impl ResponseMessage {
    /// Evaluations this response carries.
    pub fn evaluations(&self) -> usize {
        self.rows.len() / H_ROWS
    }
}

/// One row's `st_fin`, stored by Request() in Figure 4 as
/// `((uid, ctr), r_Σ, r′_{b′_ctr})` and read back by Finalize(). The `uid`
/// is on [`FinalizeState`], which carries it once for all the rows.
#[derive(Clone)]
pub(crate) struct RowFinalizeState {
    pub(crate) ctr: u64,
    /// `r_Σ = r_1 + ... + r_n mod q`, where `r_i = r^ctr_{b̄_i,i}` - see Request() in Figure 4.
    pub(crate) r_sigma: Zq,
    /// `r′_{b′_ctr}`.
    pub(crate) r_prime: Zp,
}

impl std::fmt::Debug for RowFinalizeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RowFinalizeState")
            .field("ctr", &self.ctr)
            .finish_non_exhaustive()
    }
}

impl Zeroize for RowFinalizeState {
    fn zeroize(&mut self) {
        self.ctr.zeroize();
        self.r_sigma.zeroize();
        self.r_prime.zeroize();
    }
}

/// State the client keeps between Request and Finalize (`st_fin` in Figure 4),
/// batched over the `H_ROWS` rows.
#[derive(Clone, Debug)]
pub struct FinalizeState {
    pub(crate) uid: Uid,
    pub(crate) rows: Vec<RowFinalizeState>,
    /// If a VOPRF, the online statement of each evaluation.
    pub(crate) voprf: Option<Vec<OnlineStatement>>,
}

impl Zeroize for FinalizeState {
    fn zeroize(&mut self) {
        self.rows.zeroize();
    }
}

impl Drop for FinalizeState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FinalizeState {}

impl FinalizeState {
    pub(crate) fn evaluations(&self) -> usize {
        self.rows.len() / H_ROWS
    }
}

/// Figure 4's Request.
pub fn request_batch<T: AsRef<[u8]>>(
    state: &mut ClientState,
    tag: &[u8],
    inputs: &[T],
) -> Result<(RequestMessage, FinalizeState), RequestError> {
    if tag.len() > MAX_TAG_LEN {
        return Err(RequestError::TagTooLong { len: tag.len() });
    }
    if inputs.is_empty() {
        return Err(RequestError::EmptyBatch);
    }
    if inputs.len() > MAX_BATCH_EVALUATIONS {
        return Err(RequestError::BatchTooLarge { len: inputs.len() });
    }
    if state.voprf().is_some() && inputs.len() > MAX_VOPRF_BATCH_EVALUATIONS {
        return Err(RequestError::VoprfBatchTooLarge { len: inputs.len() });
    }
    let needed_runs = tau_for(inputs.len());
    let have_runs = state.remaining_runs();
    if have_runs < needed_runs {
        return Err(RequestError::Exhausted {
            needed: needed_runs,
            have: have_runs,
        });
    }

    let uid = *state.uid();
    let mut rows = Vec::with_capacity(needed_runs);
    let mut fin_rows = Vec::with_capacity(needed_runs);
    let mut statements = Vec::new();
    for input in inputs {
        let m = hash_to_zq_matrix(tag, input.as_ref());
        let first_run = state
            .next_runs(H_ROWS)
            .expect("have_runs >= needed_runs checked above");
        request_evaluation(state, first_run, &m, &mut rows, &mut fin_rows);
        if let Some(voprf) = state.voprf() {
            statements.push(voprf.online_statement(first_run, &rows[rows.len() - H_ROWS..]));
        }
    }

    Ok((
        RequestMessage {
            uid,
            tag: tag.to_vec(),
            rows,
        },
        FinalizeState {
            uid,
            rows: fin_rows,
            voprf: state.voprf().map(|_| statements),
        },
    ))
}

/// Build a request for public tag `tag` and private input `x` - the
/// one-input case of [`request_batch`].
pub fn request(
    state: &mut ClientState,
    tag: &[u8],
    x: &[u8],
) -> Result<(RequestMessage, FinalizeState), RequestError> {
    request_batch(state, tag, &[x])
}

/// The `H_ROWS` base runs of Figure 4's Request for one evaluation, runs
/// `first_run .. first_run + H_ROWS`.
fn request_evaluation(
    state: &ClientState,
    first_run: u64,
    m: &ZqMatrix,
    rows: &mut Vec<RowRequest>,
    fin_rows: &mut Vec<RowFinalizeState>,
) {
    let a: [&[Zq]; H_ROWS] = std::array::from_fn(|k| m.row(k).as_slice());
    let mut e = [[0 as Zq; N]; H_ROWS];
    let mut r_sigma_acc = [0 as ZqAccum; H_ROWS];

    for i in 0..N {
        // H_ROWS masks each.
        let r_bhats = state.r_bhat(i, first_run);
        let r_not_bhats = state.r_not_bhat(i, first_run);

        for k in 0..H_ROWS {
            let r_bhat = ZqAccum::from(r_bhats[k]);
            let r_not_bhat = ZqAccum::from(r_not_bhats[k]);
            e[k][i] = reduce_q(ZqAccum::from(a[k][i]) + r_bhat + r_not_bhat);
            r_sigma_acc[k] += r_bhat;
        }
    }

    for (k, e_k) in e.into_iter().enumerate() {
        let ctr = first_run + k as u64;
        let r_sigma = reduce_q(r_sigma_acc[k]);

        let rc = state.r_c(ctr); // (b′_ctr, r′_{b′_ctr})
        let b_bar_prime = sub_delta(reduce_delta(r_sigma), rc.b_prime);

        rows.push(RowRequest {
            e: e_k,
            b_bar_prime,
        });
        fin_rows.push(RowFinalizeState {
            ctr,
            r_sigma,
            r_prime: rc.r_prime,
        });
    }
}

/// Figure 4's BlindEval.
pub fn blind_eval(
    state: &mut ServerState,
    sk: &SecretKey,
    req: &RequestMessage,
) -> Result<ResponseMessage, BlindEvalError> {
    if req.uid != *state.uid() {
        return Err(BlindEvalError::UnknownSession { uid: req.uid });
    }
    if req.tag.len() > MAX_TAG_LEN {
        return Err(BlindEvalError::Malformed("tag is longer than MAX_TAG_LEN"));
    }
    if req.rows.is_empty() || !req.rows.len().is_multiple_of(H_ROWS) {
        return Err(BlindEvalError::Malformed(
            "row count is not a whole number of evaluations",
        ));
    }
    if req.evaluations() > MAX_BATCH_EVALUATIONS {
        return Err(BlindEvalError::Malformed(
            "batch is larger than MAX_BATCH_EVALUATIONS",
        ));
    }
    if state.voprf().is_some() && req.evaluations() > MAX_VOPRF_BATCH_EVALUATIONS {
        return Err(BlindEvalError::Malformed(
            "batch is larger than MAX_VOPRF_BATCH_EVALUATIONS",
        ));
    }

    for row in &req.rows {
        if row.e.iter().any(|&e| e >= Q) {
            return Err(BlindEvalError::Malformed("e has an element outside Zq"));
        }
        if (row.b_bar_prime as usize) >= DELTA {
            return Err(BlindEvalError::Malformed("b_bar' is outside [0, DELTA)"));
        }
    }

    let needed_runs = req.rows.len();
    let have_runs = state.remaining_runs();
    if have_runs < needed_runs {
        return Err(BlindEvalError::Exhausted {
            needed: needed_runs,
            have: have_runs,
        });
    }

    let mut rows = Vec::with_capacity(needed_runs);
    let mut proofs = Vec::new();
    for eval in req.rows.chunks_exact(H_ROWS) {
        let first_run = state
            .next_runs(H_ROWS)
            .expect("have_runs >= needed_runs checked above");
        let r_sigma_sums = blind_eval_one(state, sk, eval, first_run, &mut rows);
        if let Some(voprf) = state.voprf() {
            proofs.push(voprf.prove_online(sk, first_run, eval, &r_sigma_sums)?);
        }
    }

    Ok(ResponseMessage {
        uid: *state.uid(),
        rows,
        proofs,
    })
}

/// The `H_ROWS` base runs of Figure 4's BlindEval for one evaluation, runs
/// `first_run .. first_run + H_ROWS`, appended to `out`. Returns `r̃_Σ` of
/// each run.
fn blind_eval_one(
    state: &ServerState,
    sk: &SecretKey,
    reqs: &[RowRequest],
    first_run: u64,
    out: &mut Vec<RowResponse>,
) -> [Zq; H_ROWS] {
    assert_eq!(reqs.len(), H_ROWS, "an evaluation is H_ROWS rows");

    // r^ctr_{b_i,i}: the H_ROWS masks of coordinate i, one per row.
    let r: Vec<[Zq; H_ROWS]> = (0..N).map(|i| state.r(i, first_run)).collect();

    let mut r_sigma_sums = [0 as Zq; H_ROWS];
    for (k, req) in reqs.iter().enumerate() {
        let ctr = first_run + k as u64;
        let masks: [Zq; N] = std::array::from_fn(|i| r[i][k]);
        let r_sigma_sum = pool_eval::r_sigma_sum(sk, &masks);
        let a_sigma_sum = pool_eval::a_sigma_sum(sk, r_sigma_sum, &req.e);
        let y = pool_eval::respond(a_sigma_sum, state.s_s(ctr), req.b_bar_prime);
        out.push(RowResponse { y, ctr });
        r_sigma_sums[k] = r_sigma_sum;
    }
    r_sigma_sums
}

/// Figure 4's Finalize.
pub fn finalize_batch(
    state: &FinalizeState,
    resp: &ResponseMessage,
) -> Result<Vec<PrfOutput>, FinalizeError> {
    if resp.uid != state.uid {
        return Err(FinalizeError::SessionMismatch {
            want: state.uid,
            got: resp.uid,
        });
    }
    if resp.rows.len() != state.rows.len() {
        return Err(FinalizeError::Malformed("wrong number of rows"));
    }
    assert_eq!(
        state.rows.len() % H_ROWS,
        0,
        "expected multiple of H_ROWS rows per evaluation"
    );
    if let Some(statements) = &state.voprf {
        if resp.proofs.len() != statements.len() {
            return Err(FinalizeError::Malformed("not one proof per evaluation"));
        }
        let evaluations = statements
            .iter()
            .zip(resp.rows.chunks_exact(H_ROWS))
            .zip(&resp.proofs);
        for ((statement, rows), proof) in evaluations {
            verify_online(statement, rows, proof)?;
        }
    }

    let mut outputs = Vec::with_capacity(state.evaluations());
    for (eval, (fin_rows, resp_rows)) in state
        .rows
        .chunks_exact(H_ROWS)
        .zip(resp.rows.chunks_exact(H_ROWS))
        .enumerate()
    {
        let mut out = [0 as Zp; OUTPUT_ELEMENTS];
        for (k, (fin, row)) in fin_rows.iter().zip(resp_rows).enumerate() {
            if row.ctr != fin.ctr {
                return Err(FinalizeError::CounterMismatch {
                    row: eval * H_ROWS + k,
                    want: fin.ctr,
                    got: row.ctr,
                });
            }
            out[k] = finalize_row(fin, row);
        }
        outputs.push(PrfOutput::from(out));
    }
    Ok(outputs)
}

/// Unblind a response into the PRF output - the one-input case of
/// [`finalize_batch`].
pub fn finalize(state: &FinalizeState, resp: &ResponseMessage) -> Result<PrfOutput, FinalizeError> {
    let evaluations = state.evaluations();
    if evaluations != 1 {
        return Err(FinalizeError::NotSingle { len: evaluations });
    }
    let mut outputs = finalize_batch(state, resp)?;
    Ok(outputs.pop().expect("one evaluation checked above"))
}

/// One base run of Figure 4's Finalize, for a single response row.
fn finalize_row(fin: &RowFinalizeState, resp: &RowResponse) -> Zp {
    let r_sigma_mod_delta = reduce_delta(fin.r_sigma) as usize;
    let r = fin.r_prime;
    let y = sub_p(resp.y[r_sigma_mod_delta], r);
    let r_sigma_div_delta = (fin.r_sigma - r_sigma_mod_delta as Zq) / DELTA_ZQ;
    sub_p(y, r_sigma_div_delta as Zp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocessing::{RcEntry, RsEntry, preproc_client_voprf, preproc_server};
    use crate::testing::verified_key;
    use cryprot_core::Block;
    use pool_prf::modular::reduce_p;
    use pool_prf::params::{LAMBDA_BYTES, ZpAccum};
    use pool_prf::prf::evaluate;

    const TAG: &[u8] = b"tag-1";

    fn ot_block(label: u64) -> Block {
        let mut bytes = [0u8; Block::BYTES];
        bytes[..8].copy_from_slice(&label.to_le_bytes());
        Block::new(bytes)
    }

    fn test_client_state(tau: usize) -> ClientState {
        let ot_blocks: Vec<[Block; 2]> = (0..N as u64)
            .map(|i| [ot_block(2 * i), ot_block(2 * i + 1)])
            .collect();
        let bhat: Vec<u8> = (0..N).map(|i| (i % 2) as u8).collect();
        let r_c: Vec<RcEntry> = (0..tau)
            .map(|j| RcEntry {
                b_prime: (j % DELTA) as Zdelta,
                r_prime: reduce_p(j as ZpAccum),
            })
            .collect();
        ClientState::new(ot_blocks, bhat, r_c, [7u8; LAMBDA_BYTES], None)
    }

    #[test]
    fn request_spends_one_evaluation_and_is_well_formed() {
        let mut state = test_client_state(tau_for(3));
        let before = state.remaining_runs();
        let (msg, fin) = request(&mut state, TAG, b"input").unwrap();

        assert_eq!(state.remaining_runs(), before - tau_for(1));
        assert_eq!(msg.rows.len(), H_ROWS);
        assert_eq!(fin.rows.len(), H_ROWS);
        assert_eq!(msg.uid, fin.uid);
        assert_eq!(msg.tag, TAG);
        for row in &msg.rows {
            assert!(row.e.iter().all(|&e| e < Q));
            assert!((row.b_bar_prime as usize) < DELTA);
        }
    }

    #[test]
    fn request_errs_when_exhausted_without_consuming() {
        let needed_runs = tau_for(1);
        let have_runs = needed_runs - 1;
        let mut state = test_client_state(have_runs);

        let err = request(&mut state, TAG, b"input").unwrap_err();
        let RequestError::Exhausted { needed, have } = err else {
            panic!("expected Exhausted, got {err}");
        };
        assert_eq!(needed, needed_runs);
        assert_eq!(have, have_runs);

        // No runs consumed on failure.
        assert_eq!(state.remaining_runs(), have_runs);
    }

    #[test]
    fn request_rejects_oversized_tag_without_consuming() {
        let mut state = test_client_state(tau_for(1));
        let tag = vec![0u8; MAX_TAG_LEN + 1];
        let err = request(&mut state, &tag, b"input").unwrap_err();
        assert!(matches!(err, RequestError::TagTooLong { len } if len == MAX_TAG_LEN + 1));
        assert_eq!(state.remaining_runs(), tau_for(1));
    }

    #[test]
    fn request_is_deterministic() {
        let mut s1 = test_client_state(tau_for(1));
        let mut s2 = test_client_state(tau_for(1));
        let (m1, _) = request(&mut s1, TAG, b"same").unwrap();
        let (m2, _) = request(&mut s2, TAG, b"same").unwrap();
        for (r1, r2) in m1.rows.iter().zip(&m2.rows) {
            assert_eq!(r1.e, r2.e);
            assert_eq!(r1.b_bar_prime, r2.b_bar_prime);
        }
    }

    /// A client/server state pair as PreProc (Figure 3) would leave it.
    fn matched_states(sk: &SecretKey, tau: usize) -> (ClientState, ServerState) {
        let uid = [9u8; LAMBDA_BYTES];
        let mut ot_blocks = Vec::with_capacity(N);
        let mut r_s = Vec::with_capacity(N);
        let mut bhat = Vec::with_capacity(N);
        for i in 0..N {
            let pair = [ot_block(2 * i as u64), ot_block(2 * i as u64 + 1)];
            let b = u8::from(i % 3 == 0); // server's OT choice bits
            ot_blocks.push(pair);
            r_s.push(RsEntry {
                b,
                ot_block: pair[b as usize],
            });
            bhat.push(b ^ sk.as_bits()[i]);
        }
        let mut r_c = Vec::with_capacity(tau);
        let mut s_s = Vec::with_capacity(tau);
        for j in 0..tau {
            let mut pads = [0 as Zp; DELTA];
            for (d, pad) in pads.iter_mut().enumerate() {
                *pad = reduce_p((17 * j + 5 * d + 1) as ZpAccum);
            }
            let b_prime = (7 * j + 3) % DELTA;
            r_c.push(RcEntry {
                b_prime: b_prime as Zdelta,
                r_prime: pads[b_prime],
            });
            s_s.push(pads);
        }
        (
            ClientState::new(ot_blocks, bhat, r_c, uid, None),
            ServerState::new(r_s, s_s, uid, None),
        )
    }

    #[test]
    fn request_blind_eval_finalize_matches_prf() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let x = b"correctness";

        let (msg, fin) = request(&mut client_state, TAG, x).unwrap();
        let resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
        let z = finalize(&fin, &resp).unwrap();

        assert_eq!(z, evaluate(&sk, TAG, x));
    }

    #[test]
    fn consecutive_evaluations_match_prf() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(2));

        for x in [b"first".as_slice(), b"second".as_slice()] {
            let (msg, fin) = request(&mut client_state, TAG, x).unwrap();
            let resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
            assert_eq!(
                finalize(&fin, &resp).unwrap(),
                evaluate(&sk, TAG, x),
                "{x:?}"
            );
        }
        assert_eq!(client_state.remaining_runs(), 0);
        assert_eq!(server_state.remaining_runs(), 0);
    }

    #[test]
    fn batch_matches_the_same_inputs_one_at_a_time() {
        let sk = SecretKey::random(&mut rand::rng());
        let inputs: [&[u8]; 3] = [b"alice", b"bob", b"alice"];

        let (mut batch_client, mut batch_server) = matched_states(&sk, tau_for(3));
        let (msg, fin) = request_batch(&mut batch_client, TAG, &inputs).unwrap();
        assert_eq!(msg.evaluations(), 3);
        let resp = blind_eval(&mut batch_server, &sk, &msg).unwrap();
        assert_eq!(resp.evaluations(), 3);
        let batched = finalize_batch(&fin, &resp).unwrap();

        let (mut one_client, mut one_server) = matched_states(&sk, tau_for(3));
        let singly: Vec<_> = inputs
            .iter()
            .map(|x| {
                let (msg, fin) = request(&mut one_client, TAG, x).unwrap();
                let resp = blind_eval(&mut one_server, &sk, &msg).unwrap();
                finalize(&fin, &resp).unwrap()
            })
            .collect();

        assert_eq!(batched, singly);
        for (x, out) in inputs.iter().zip(&batched) {
            assert_eq!(*out, evaluate(&sk, TAG, x), "input {x:?}");
        }
        assert_eq!(batched[0], batched[2]);
        assert_eq!(batch_client.remaining_runs(), 0);
        assert_eq!(batch_server.remaining_runs(), 0);
    }

    #[test]
    fn request_batch_consumes_runs_per_input() {
        let mut state = test_client_state(tau_for(4));
        let (msg, fin) = request_batch(&mut state, TAG, &[b"a", b"b", b"c"]).unwrap();

        assert_eq!(msg.rows.len(), 3 * H_ROWS);
        assert_eq!(fin.rows.len(), 3 * H_ROWS);
        assert_eq!(state.remaining_runs(), tau_for(1));
    }

    #[test]
    fn request_batch_rejects_bad_batch_sizes_without_consuming() {
        let mut state = test_client_state(tau_for(2));

        let empty: [&[u8]; 0] = [];
        assert!(matches!(
            request_batch(&mut state, TAG, &empty).unwrap_err(),
            RequestError::EmptyBatch
        ));

        let huge = vec![b"x".as_slice(); MAX_BATCH_EVALUATIONS + 1];
        assert!(matches!(
            request_batch(&mut state, TAG, &huge).unwrap_err(),
            RequestError::BatchTooLarge { len } if len == MAX_BATCH_EVALUATIONS + 1
        ));

        // Fits the bound but not the remaining material.
        assert!(matches!(
            request_batch(&mut state, TAG, &[b"a", b"b", b"c"]).unwrap_err(),
            RequestError::Exhausted { needed, have }
                if needed == tau_for(3) && have == tau_for(2)
        ));

        assert_eq!(state.remaining_runs(), tau_for(2));
    }

    #[test]
    fn blind_eval_rejects_a_partial_evaluation() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(2));
        let (good, _) = request_batch(&mut client_state, TAG, &[b"a", b"b"]).unwrap();

        let mut partial = good.clone();
        partial.rows.truncate(H_ROWS + 1);

        let err = blind_eval(&mut server_state, &sk, &partial).unwrap_err();
        assert!(matches!(err, BlindEvalError::Malformed(_)), "{err}");
        assert_eq!(server_state.remaining_runs(), tau_for(2));
    }

    #[test]
    fn finalize_rejects_a_batch_state() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(2));
        let (msg, fin) = request_batch(&mut client_state, TAG, &[b"a", b"b"]).unwrap();
        let resp = blind_eval(&mut server_state, &sk, &msg).unwrap();

        let err = finalize(&fin, &resp).unwrap_err();
        assert!(matches!(err, FinalizeError::NotSingle { len: 2 }), "{err}");
        // The batch helper handles it.
        assert_eq!(finalize_batch(&fin, &resp).unwrap().len(), 2);
    }

    #[test]
    fn each_tag_gives_its_own_prf() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(3));
        let x = b"same input";

        let mut outputs = Vec::new();
        for tag in [b"".as_slice(), b"tag-1".as_slice(), b"tag-2".as_slice()] {
            let (msg, fin) = request(&mut client_state, tag, x).unwrap();
            assert_eq!(msg.tag, tag);
            let resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
            let z = finalize(&fin, &resp).unwrap();

            assert_eq!(z, evaluate(&sk, tag, x), "tag {tag:?}");
            outputs.push(z);
        }
        assert_ne!(outputs[0], outputs[1]);
        assert_ne!(outputs[1], outputs[2]);
        assert_ne!(outputs[0], outputs[2]);
    }

    #[test]
    fn finalize_needs_the_pad_rotation() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));

        let (mut msg, fin) = request(&mut client_state, TAG, b"rotation").unwrap();
        for row in &mut msg.rows {
            row.b_bar_prime = sub_delta(row.b_bar_prime, 1);
        }
        let resp = blind_eval(&mut server_state, &sk, &msg).unwrap();

        assert_ne!(
            finalize(&fin, &resp).unwrap(),
            evaluate(&sk, TAG, b"rotation")
        );
    }

    #[test]
    fn finalize_needs_the_delta_ot_pad() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));

        let (msg, mut fin) = request(&mut client_state, TAG, b"pads").unwrap();
        let resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
        for row in &mut fin.rows {
            row.r_prime = 0;
        }

        assert_ne!(finalize(&fin, &resp).unwrap(), evaluate(&sk, TAG, b"pads"));
    }

    #[test]
    fn finalize_rejects_other_session() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (msg, fin) = request(&mut client_state, TAG, b"input").unwrap();
        let mut resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
        resp.uid = [0xffu8; LAMBDA_BYTES];

        let err = finalize(&fin, &resp).unwrap_err();
        assert!(
            matches!(err, FinalizeError::SessionMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn finalize_rejects_counter_drift() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (msg, fin) = request(&mut client_state, TAG, b"input").unwrap();
        let mut resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
        resp.rows[0].ctr += 1;

        let err = finalize(&fin, &resp).unwrap_err();
        assert!(
            matches!(err, FinalizeError::CounterMismatch { row, want, got }
                if row == 0 && want == 0 && got == 1),
            "{err}"
        );
    }

    #[test]
    fn finalize_rejects_truncated_response() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (msg, fin) = request(&mut client_state, TAG, b"input").unwrap();
        let mut resp = blind_eval(&mut server_state, &sk, &msg).unwrap();
        resp.rows.pop();

        let err = finalize(&fin, &resp).unwrap_err();
        assert!(matches!(err, FinalizeError::Malformed(_)), "{err}");
    }

    #[test]
    fn blind_eval_consumes_h_rows() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(3));
        let before = server_state.remaining_runs();
        let (msg, _) = request(&mut client_state, TAG, b"input").unwrap();

        blind_eval(&mut server_state, &sk, &msg).unwrap();
        assert_eq!(server_state.remaining_runs(), before - tau_for(1));
    }

    #[test]
    fn blind_eval_rejects_other_session_without_consuming() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (mut msg, _) = request(&mut client_state, TAG, b"input").unwrap();
        msg.uid = [0xffu8; LAMBDA_BYTES];

        let err = blind_eval(&mut server_state, &sk, &msg).unwrap_err();
        assert!(matches!(err, BlindEvalError::UnknownSession { .. }));
        assert_eq!(server_state.remaining_runs(), tau_for(1));
    }

    #[test]
    fn blind_eval_rejects_malformed_request_without_consuming() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (good, _) = request(&mut client_state, TAG, b"input").unwrap();

        let mut short_row_count = good.clone();
        short_row_count.rows.pop();
        let mut bad_e = good.clone();
        bad_e.rows[0].e[0] = Q;
        let mut bad_correction = good.clone();
        bad_correction.rows[0].b_bar_prime = DELTA as Zdelta;
        let mut huge_tag = good.clone();
        huge_tag.tag = vec![0u8; MAX_TAG_LEN + 1];

        for bad in [short_row_count, bad_e, bad_correction, huge_tag] {
            let err = blind_eval(&mut server_state, &sk, &bad).unwrap_err();
            assert!(matches!(err, BlindEvalError::Malformed(_)), "{err}");
        }
        assert_eq!(server_state.remaining_runs(), tau_for(1));
    }

    #[test]
    fn blind_eval_errs_when_exhausted() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (msg, _) = request(&mut client_state, TAG, b"first").unwrap();
        blind_eval(&mut server_state, &sk, &msg).unwrap();

        let err = blind_eval(&mut server_state, &sk, &msg).unwrap_err();
        assert!(matches!(
            err,
            BlindEvalError::Exhausted { needed, have }
                if needed == tau_for(1) && have == 0
        ));
        assert_eq!(server_state.remaining_runs(), 0);
    }

    #[tokio::test]
    async fn a_maximum_batch_fits() {
        use crate::channel::{ClientChannel, ServerChannel};

        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let uid = [7u8; LAMBDA_BYTES];
        let rows = MAX_BATCH_EVALUATIONS * H_ROWS;

        let req = RequestMessage {
            uid,
            tag: TAG.to_vec(),
            rows: vec![
                RowRequest {
                    e: [Q - 1; N],
                    b_bar_prime: 0,
                };
                rows
            ],
        };
        let resp = ResponseMessage {
            uid,
            rows: vec![
                RowResponse {
                    y: [0 as Zp; DELTA],
                    ctr: 0,
                };
                rows
            ],
            proofs: Vec::new(),
        };

        let (client, server) = tokio::join!(
            ClientChannel::new(&mut client_conn),
            ServerChannel::new(&mut server_conn),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        let (got_resp, ()) = tokio::join!(
            async { client.exchange(req).await.expect("request did not fit") },
            async {
                let got = server
                    .next_request()
                    .await
                    .expect("request did not fit")
                    .expect("stream closed");
                assert_eq!(got.evaluations(), MAX_BATCH_EVALUATIONS);
                server.respond(resp).await.expect("response did not fit");
            },
        );
        assert_eq!(got_resp.evaluations(), MAX_BATCH_EVALUATIONS);
    }

    async fn voprf_states(sk: &SecretKey, evaluations: usize) -> (ClientState, ServerState) {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let pk = verified_key(sk);
        let mut rng = rand::rng();
        tokio::try_join!(
            preproc_client_voprf(&mut client_conn, &pk, tau_for(evaluations), &mut rng),
            preproc_server(&mut server_conn, sk, tau_for(evaluations)),
        )
        .expect("preprocessing")
    }

    #[tokio::test]
    async fn a_voprf_client_refuses_a_response_under_another_key() {
        let sk = SecretKey::random(&mut rand::rng());
        let other = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = voprf_states(&sk, 1).await;
        let (msg, fin) = request(&mut client_state, TAG, b"input").unwrap();

        let resp = blind_eval(&mut server_state, &other, &msg).unwrap();

        let err = finalize(&fin, &resp).unwrap_err();
        assert!(matches!(err, FinalizeError::Verify(_)), "{err}");
    }

    #[tokio::test]
    async fn a_voprf_client_refuses_a_changed_response() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = voprf_states(&sk, 1).await;
        let (msg, fin) = request(&mut client_state, TAG, b"input").unwrap();
        let mut resp = blind_eval(&mut server_state, &sk, &msg).unwrap();

        resp.rows[H_ROWS - 1].y[DELTA - 1] ^= 1;

        let err = finalize(&fin, &resp).unwrap_err();
        assert!(matches!(err, FinalizeError::Verify(_)), "{err}");
    }

    #[tokio::test]
    async fn a_voprf_client_refuses_the_proofs_of_a_batch_swapped() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = voprf_states(&sk, 2).await;
        let (msg, fin) = request_batch(&mut client_state, TAG, &[b"a", b"b"]).unwrap();
        let mut resp = blind_eval(&mut server_state, &sk, &msg).unwrap();

        resp.proofs.swap(0, 1);

        let err = finalize_batch(&fin, &resp).unwrap_err();
        assert!(matches!(err, FinalizeError::Verify(_)), "{err}");
    }

    #[tokio::test]
    async fn a_voprf_batch_over_its_maximum_is_refused() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = voprf_states(&sk, 1).await;
        let evaluations = MAX_VOPRF_BATCH_EVALUATIONS + 1;

        let inputs = vec![b"x".as_slice(); evaluations];
        let err = request_batch(&mut client_state, TAG, &inputs).unwrap_err();
        assert!(
            matches!(err, RequestError::VoprfBatchTooLarge { len } if len == evaluations),
            "{err}"
        );
        assert_eq!(client_state.remaining_runs(), tau_for(1));

        // The server refuses it too, from a client that skips the check.
        let (mut over, _) = request(&mut client_state, TAG, b"x").unwrap();
        over.rows = over
            .rows
            .iter()
            .cycle()
            .take(evaluations * H_ROWS)
            .cloned()
            .collect();
        let err = blind_eval(&mut server_state, &sk, &over).unwrap_err();
        assert!(matches!(err, BlindEvalError::Malformed(_)), "{err}");
        assert_eq!(server_state.remaining_runs(), tau_for(1));
    }
}
