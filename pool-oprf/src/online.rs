//! Online phase of the Pool OPRF (Figure 4 of the paper).
//!
//! Request, BlindEval and Finalize each follow Figure 4, with two deviations
//! that apply to all three:
//!
//!  - **One evaluation is `H_ROWS` base runs.** A base run of the paper's
//!    protocol produces a single Zp element, while the PRF output is a whole
//!    row vector, so every algorithm here runs the single-row version
//!    `H_ROWS` times over `H_ROWS` consecutive slots. A [`ClientState`] with
//!    `tau` slots therefore supports `tau / H_ROWS` evaluations.
//!  - **One message may carry several evaluations.** Batching is not in the
//!    paper, but a caller with a set to evaluate (a PSI, say) would otherwise
//!    pay one round trip per element and lose the round-optimality the design
//!    is built for.

use crate::preprocessing::{ClientState, ServerState, Uid, tau_for};
use pool_prf::hash::{ZqMatrix, hash_to_zq_matrix};
use pool_prf::modular::{add_p, reduce_delta, reduce_q, sub_delta, sub_p, sub_q};
use pool_prf::params::{DELTA, DELTA_ZQ, H_ROWS, N, OUTPUT_ELEMENTS, Q, Zdelta, Zp, Zq, ZqAccum};
use pool_prf::prf::{PrfOutput, SecretKey};
use pool_prf::round::round_zq_to_zp;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_TAG_LEN: usize = 1024;

/// Most evaluations one request may carry.
///
/// Batching is not part of the paper, but is something useful we do here.
pub const MAX_BATCH_EVALUATIONS: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("preprocessing exhausted: a request needs {needed} slots, only {have} left")]
    Exhausted { needed: usize, have: usize },
    #[error("tag is {len} bytes, the maximum is {MAX_TAG_LEN}")]
    TagTooLong { len: usize },
    #[error("a request must carry at least one evaluation")]
    EmptyBatch,
    #[error("batch of {len} evaluations, the maximum is {MAX_BATCH_EVALUATIONS}")]
    BatchTooLarge { len: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum BlindEvalError {
    #[error("no preprocessing state for session {uid:?}")]
    UnknownSession { uid: Uid },
    #[error("preprocessing exhausted: a request needs {needed} slots, only {have} left")]
    Exhausted { needed: usize, have: usize },
    #[error("malformed request: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub enum FinalizeError {
    #[error("response is for session {got:?}, this request was session {want:?}")]
    SessionMismatch { want: Uid, got: Uid },
    #[error("malformed response: {0}")]
    Malformed(&'static str),
    #[error("response row {row} is for slot {got}, this request used slot {want}")]
    CounterMismatch { row: usize, want: u64, got: u64 },
    #[error("this request was a batch of {len} evaluations; use finalize_batch")]
    NotSingle { len: usize },
}

/// One row of a request. Figure 4's `Request` is the single-row protocol and
/// returns a whole message, `(t, (e_1, ..., e_n), b_bar', uid)`. An evaluation
/// runs `H_ROWS` of those, so a row is that tuple without `t` and `uid`, which
/// [`RequestMessage`] carries once for all the rows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowRequest {
    /// `e_i = a_i + r_i + r^ctr_{1-b_bar_i,i} mod q`, for `i` in `[N]`,
    /// where `r_i = r^ctr_{b_bar_i,i}`.
    #[serde(with = "crate::packing")]
    pub e: [Zq; N],
    /// `b_bar' = (r_sigma mod DELTA - b'_ctr) mod DELTA`.
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
/// and returns a whole message, `((y_0, ..., y_{DELTA-1}), uid, ctr)`. An
/// evaluation runs `H_ROWS` of those, so a row is that tuple without `uid`,
/// which [`ResponseMessage`] carries once for all the rows.
///
/// `ctr` stays per row, unlike the request's, because each row spent its own
/// slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowResponse {
    /// `y_i = round_{q,p}((a_tilde_sigma - i) mod Q) + r'_{i - b_bar' mod DELTA, ctr} mod P`,
    /// for `i` in `[0, DELTA)`.
    pub(crate) y: [Zp; DELTA],
    /// The preprocessing slot this row consumed.
    pub(crate) ctr: u64,
}

/// The response message the server sends back (`rep` in Figure 4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseMessage {
    pub(crate) uid: Uid,
    pub(crate) rows: Vec<RowResponse>,
}

impl ResponseMessage {
    /// Evaluations this response carries.
    pub fn evaluations(&self) -> usize {
        self.rows.len() / H_ROWS
    }
}

/// One row's `st_fin`, stored by Request() in Figure 4 as
/// `((uid, ctr), r_sigma, r'_{b'_ctr})` and read back by Finalize(). The `uid`
/// is on [`FinalizeState`], which carries it once for all the rows.
#[derive(Clone)]
pub(crate) struct RowFinalizeState {
    pub(crate) ctr: u64,
    /// `r_sigma = r_1 + ... + r_n mod Q`, where `r_i = r^ctr_{b_bar_i,i}` - see Request() in Figure 4.
    pub(crate) r_sigma: Zq,
    /// `r'_{b'_ctr}`.
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
    let needed_slots = tau_for(inputs.len());
    let have_slots = state.remaining_slots();
    if have_slots < needed_slots {
        return Err(RequestError::Exhausted {
            needed: needed_slots,
            have: have_slots,
        });
    }

    let uid = *state.uid();
    let mut rows = Vec::with_capacity(needed_slots);
    let mut fin_rows = Vec::with_capacity(needed_slots);
    for input in inputs {
        let m = hash_to_zq_matrix(tag, input.as_ref());
        let first_slot = state
            .next_slots(H_ROWS)
            .expect("have_slots >= needed_slots checked above");
        request_evaluation(state, first_slot, &m, &mut rows, &mut fin_rows);
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

/// The `H_ROWS` base runs of Figure 4's Request for one evaluation,
/// on slots `first_slot .. first_slot + H_ROWS`.
fn request_evaluation(
    state: &ClientState,
    first_slot: u64,
    m: &ZqMatrix,
    rows: &mut Vec<RowRequest>,
    fin_rows: &mut Vec<RowFinalizeState>,
) {
    let a: [&[Zq]; H_ROWS] = std::array::from_fn(|k| m.row(k).as_slice());
    let mut e = [[0 as Zq; N]; H_ROWS];
    let mut r_sigma_acc = [0 as ZqAccum; H_ROWS];

    for i in 0..N {
        // H_ROWS masks each.
        let r_bhats = state.r_bhat(i, first_slot);
        let r_not_bhats = state.r_not_bhat(i, first_slot);

        for k in 0..H_ROWS {
            let r_bhat = ZqAccum::from(r_bhats[k]);
            let r_not_bhat = ZqAccum::from(r_not_bhats[k]);
            e[k][i] = reduce_q(ZqAccum::from(a[k][i]) + r_bhat + r_not_bhat);
            r_sigma_acc[k] += r_bhat;
        }
    }

    for (k, e_k) in e.into_iter().enumerate() {
        let ctr = first_slot + k as u64;
        let r_sigma = reduce_q(r_sigma_acc[k]);

        let rc = state.r_c(ctr); // (b'_ctr, r'_{b'_ctr})
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

    for row in &req.rows {
        if row.e.iter().any(|&e| e >= Q) {
            return Err(BlindEvalError::Malformed("e has an element outside Zq"));
        }
        if (row.b_bar_prime as usize) >= DELTA {
            return Err(BlindEvalError::Malformed("b_bar' is outside [0, DELTA)"));
        }
    }

    let needed_slots = req.rows.len();
    let have_slots = state.remaining_slots();
    if have_slots < needed_slots {
        return Err(BlindEvalError::Exhausted {
            needed: needed_slots,
            have: have_slots,
        });
    }

    let sk_bits = sk.as_bits();
    let mut rows = Vec::with_capacity(needed_slots);
    for eval in req.rows.chunks_exact(H_ROWS) {
        let first_slot = state
            .next_slots(H_ROWS)
            .expect("have_slots >= needed_slots checked above");
        blind_eval_evaluation(state, sk_bits, eval, first_slot, &mut rows);
    }

    Ok(ResponseMessage {
        uid: *state.uid(),
        rows,
    })
}

/// The `H_ROWS` base runs of Figure 4's BlindEval for one evaluation, on slots
/// `first_slot .. first_slot + H_ROWS`, appended to `out`.
fn blind_eval_evaluation(
    state: &ServerState,
    sk_bits: &[u8; N],
    reqs: &[RowRequest],
    first_slot: u64,
    out: &mut Vec<RowResponse>,
) {
    assert_eq!(reqs.len(), H_ROWS, "an evaluation is H_ROWS rows");

    let mut a_tilde_acc = [0 as ZqAccum; H_ROWS];

    for (i, &sk_i) in sk_bits.iter().enumerate() {
        // r^ctr_{b_i, i} for each row
        let r = state.r(i, first_slot);

        let s = ZqAccum::from(sk_i);

        for k in 0..H_ROWS {
            let r_k = ZqAccum::from(r[k]);
            let a_tilde_0 = r_k;
            let a_tilde_1 = ZqAccum::from(sub_q(reqs[k].e[i], r[k]));
            a_tilde_acc[k] += a_tilde_0 * (1 - s) + a_tilde_1 * s;
        }
    }

    for k in 0..H_ROWS {
        let ctr = first_slot + k as u64;
        let a_sigma = reduce_q(a_tilde_acc[k]);

        let pads = state.s_s(ctr);
        let mut y = [0 as Zp; DELTA];
        for (i, y_i) in y.iter_mut().enumerate() {
            let rounded = round_zq_to_zp(sub_q(a_sigma, i as Zq));
            let pad = pads[sub_delta(i as Zdelta, reqs[k].b_bar_prime) as usize];
            *y_i = add_p(rounded, pad);
        }

        out.push(RowResponse { y, ctr });
    }
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
    use crate::preprocessing::{RcEntry, RsEntry};
    use cryprot_core::Block;
    use pool_prf::modular::reduce_p;
    use pool_prf::params::{LAMBDA_BYTES, ZpAccum};
    use pool_prf::prf::evaluate;

    const TAG: &[u8] = b"tag-1";

    fn seed(label: u64) -> Block {
        let mut bytes = [0u8; Block::BYTES];
        bytes[..8].copy_from_slice(&label.to_le_bytes());
        Block::new(bytes)
    }

    fn test_client_state(tau: usize) -> ClientState {
        let r_seeds: Vec<[Block; 2]> = (0..N as u64)
            .map(|i| [seed(2 * i), seed(2 * i + 1)])
            .collect();
        let bhat: Vec<u8> = (0..N).map(|i| (i % 2) as u8).collect();
        let r_c: Vec<RcEntry> = (0..tau)
            .map(|j| RcEntry {
                b_prime: (j % DELTA) as Zdelta,
                r_prime: reduce_p(j as ZpAccum),
            })
            .collect();
        ClientState::new(r_seeds, bhat, r_c, [7u8; LAMBDA_BYTES])
    }

    #[test]
    fn request_spends_one_evaluation_and_is_well_formed() {
        let mut state = test_client_state(tau_for(3));
        let before = state.remaining_slots();
        let (msg, fin) = request(&mut state, TAG, b"input").unwrap();

        assert_eq!(state.remaining_slots(), before - tau_for(1));
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
        let needed_slots = tau_for(1);
        let have_slots = needed_slots - 1;
        let mut state = test_client_state(have_slots);

        let err = request(&mut state, TAG, b"input").unwrap_err();
        let RequestError::Exhausted { needed, have } = err else {
            panic!("expected Exhausted, got {err}");
        };
        assert_eq!(needed, needed_slots);
        assert_eq!(have, have_slots);

        // No slots consumed on failure.
        assert_eq!(state.remaining_slots(), have_slots);
    }

    #[test]
    fn request_rejects_oversized_tag_without_consuming() {
        let mut state = test_client_state(tau_for(1));
        let tag = vec![0u8; MAX_TAG_LEN + 1];
        let err = request(&mut state, &tag, b"input").unwrap_err();
        assert!(matches!(err, RequestError::TagTooLong { len } if len == MAX_TAG_LEN + 1));
        assert_eq!(state.remaining_slots(), tau_for(1));
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
        let mut r_seeds = Vec::with_capacity(N);
        let mut r_s = Vec::with_capacity(N);
        let mut bhat = Vec::with_capacity(N);
        for i in 0..N {
            let pair = [seed(2 * i as u64), seed(2 * i as u64 + 1)];
            let b = u8::from(i % 3 == 0); // server's OT choice bits
            r_seeds.push(pair);
            r_s.push(RsEntry {
                b,
                r_seed: pair[b as usize],
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
            ClientState::new(r_seeds, bhat, r_c, uid),
            ServerState::new(r_s, s_s, uid),
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
        assert_eq!(client_state.remaining_slots(), 0);
        assert_eq!(server_state.remaining_slots(), 0);
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
        assert_eq!(batch_client.remaining_slots(), 0);
        assert_eq!(batch_server.remaining_slots(), 0);
    }

    #[test]
    fn request_batch_consumes_slots_per_input() {
        let mut state = test_client_state(tau_for(4));
        let (msg, fin) = request_batch(&mut state, TAG, &[b"a", b"b", b"c"]).unwrap();

        assert_eq!(msg.rows.len(), 3 * H_ROWS);
        assert_eq!(fin.rows.len(), 3 * H_ROWS);
        assert_eq!(state.remaining_slots(), tau_for(1));
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

        assert_eq!(state.remaining_slots(), tau_for(2));
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
        assert_eq!(server_state.remaining_slots(), tau_for(2));
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
        let before = server_state.remaining_slots();
        let (msg, _) = request(&mut client_state, TAG, b"input").unwrap();

        blind_eval(&mut server_state, &sk, &msg).unwrap();
        assert_eq!(server_state.remaining_slots(), before - tau_for(1));
    }

    #[test]
    fn blind_eval_rejects_other_session_without_consuming() {
        let sk = SecretKey::random(&mut rand::rng());
        let (mut client_state, mut server_state) = matched_states(&sk, tau_for(1));
        let (mut msg, _) = request(&mut client_state, TAG, b"input").unwrap();
        msg.uid = [0xffu8; LAMBDA_BYTES];

        let err = blind_eval(&mut server_state, &sk, &msg).unwrap_err();
        assert!(matches!(err, BlindEvalError::UnknownSession { .. }));
        assert_eq!(server_state.remaining_slots(), tau_for(1));
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
        assert_eq!(server_state.remaining_slots(), tau_for(1));
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
        assert_eq!(server_state.remaining_slots(), 0);
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
}
