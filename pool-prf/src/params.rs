//! See table 3 in the paper for parameters for security parameter λ of 128 bits.
//!
//! An attempt has been made to make parameters and types generic such that changing
//! values would work automatically, but this requires further more careful work. Till
//! then, make sure you check types and values carefully.

const fn log2(v: Zq) -> u32 {
    assert!(v.is_power_of_two(), "log2 requires a power of 2");
    v.trailing_zeros()
}

/// LWR dimension, same as:
///  * secret key length
///  * number of columns in H's output matrix
pub const N: usize = 482;

/// LWR modulus (must be a power of 2). Equal to 2 ^ 12.
pub const Q: Zq = 4096;

/// log2(Q).
pub const LOG_Q: u32 = log2(Q);

/// Rounding modulus (must be a power of 2, and must divide Q). Equal to 2 ^ 8.
pub const P: Zq = 256;

/// log2(P).
pub const LOG_P: u32 = log2(P);

/// Rounding factor: Δ = q / p.
pub const DELTA_ZQ: Zq = Q / P;

/// Rounding factor, as a usize for lengths and indices.
pub const DELTA: usize = DELTA_ZQ as usize;

/// log2(Δ) = log2(q) - log2(p).
pub const LOG_DELTA: usize = (LOG_Q - LOG_P) as usize;

const _: () = assert!(Q >= P, "Q must be >= P");

/// Element of ℤ_q.
pub type Zq = u16;

/// Element of ℤ_p.
pub type Zp = u8;

/// `Zp` holds elements of [0, P), so the largest is P - 1.
const _: () = assert!(P - 1 <= Zp::MAX as Zq, "P must fit Zp");

/// The largest element of ℤ_p.
pub const ZP_MAX: Zp = (P - 1) as Zp;

/// Element of ℤ_Δ, used as a choice index for a 1-out-of-Δ OT, in [0, Δ).
pub type Zdelta = u8;

/// `Zdelta` holds elements of [0, Δ), so the largest is Δ - 1.
const _: () = assert!(DELTA - 1 <= Zdelta::MAX as usize, "delta must fit Zdelta");

/// Wider type for accumulating sums of ℤ_q elements (e.g. in the inner product).
pub type ZqAccum = u32;

const _: () = assert!(
    N * (Q as usize - 1) <= ZqAccum::MAX as usize,
    "ZqAccum must hold an N-term sum over Zq"
);

/// Wider type for accumulating sums of ℤ_p elements.
pub type ZpAccum = u32;

const _: () = assert!(
    N * (P as usize - 1) <= ZpAccum::MAX as usize,
    "ZpAccum must hold an N-term sum over Zp"
);

/// Number of rows in H's output matrix.
pub const H_ROWS: usize = 16;

/// PRF output length in ℤ_p elements: one per row of H.
pub const OUTPUT_ELEMENTS: usize = H_ROWS;

/// Security parameter λ in bits.
pub const LAMBDA_BITS: usize = 128;

/// Security parameter λ in bytes.
pub const LAMBDA_BYTES: usize = LAMBDA_BITS / 8;
