//! The equations of the paper's BlindEval.

use core::array;
use pool_prf::modular::{add_p, sub_delta, sub_q};
use pool_prf::params::{DELTA, Zdelta, Zp, Zq};
use pool_prf::round::round_zq_to_zp;

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
