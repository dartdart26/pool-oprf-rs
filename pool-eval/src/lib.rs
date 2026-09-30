//! The equations of the paper's BlindEval.

use core::array;
use pool_prf::modular::{add_p, reduce_q, sub_delta, sub_q};
use pool_prf::params::{DELTA, N, Zdelta, Zp, Zq, ZqAccum};
use pool_prf::prf::SecretKey;
use pool_prf::round::round_zq_to_zp;

/// `r̃_Σ` is the sum with the server's masks added where `sk_i = 0` and
/// subtracted where `sk_i = 1`:
///
/// ```text
/// r̃_Σ = Σ_i (1 - 2·sk_i)·r_{b_i, i}   mod q
/// ```
pub fn r_sigma_sum(sk: &SecretKey, masks: &[Zq; N]) -> Zq {
    let terms = sk
        .as_bits()
        .iter()
        .zip(masks)
        .map(|(&sk_i, &r_i)| if sk_i == 0 { r_i } else { sub_q(0, r_i) });
    reduce_q(terms.map(ZqAccum::from).sum::<ZqAccum>())
}

/// `ã_Σ`, the server's sum over all coordinates:
///
/// ```text
/// ã_Σ = Σ_i sk_i·e_i + r̃_Σ   mod q
/// ```
pub fn a_sigma_sum(sk: &SecretKey, r_sigma_sum: Zq, e: &[Zq; N]) -> Zq {
    let terms = sk
        .as_bits()
        .iter()
        .zip(e)
        .map(|(&sk_i, &e_i)| if sk_i == 0 { 0 } else { e_i });
    reduce_q(terms.map(ZqAccum::from).sum::<ZqAccum>() + ZqAccum::from(r_sigma_sum))
}

/// `⌈(ã_Σ - j) mod q⌋`, the rounded part of entry `j`.
pub fn rounded(a_sigma_sum: Zq, j: usize) -> Zp {
    round_zq_to_zp(sub_q(a_sigma_sum, j as Zq))
}

/// `r′_{(j - b̄′) mod Δ}`.
pub fn pad(pads: &[Zp; DELTA], j: usize, b_bar_prime: Zdelta) -> Zp {
    pads[usize::from(sub_delta(j as Zdelta, b_bar_prime))]
}

/// The server's response `y_0 .. y_{Δ-1}`:
///
/// ```text
/// y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}   mod p
/// ```
///
/// `a_sigma_sum` is `ã_Σ`, reduced mod `q`. `pads` are `r′_0 .. r′_{Δ-1}`.
/// `b_bar_prime` is `b̄′`, in `0 .. Δ-1`.
pub fn respond(a_sigma_sum: Zq, pads: &[Zp; DELTA], b_bar_prime: Zdelta) -> [Zp; DELTA] {
    array::from_fn(|j| add_p(rounded(a_sigma_sum, j), pad(pads, j, b_bar_prime)))
}
