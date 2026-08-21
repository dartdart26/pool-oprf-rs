//! Modular arithmetic in Zq, Zp and Zdelta.

use crate::params::{DELTA, DELTA_ZQ, P, Q, Zdelta, Zp, ZpAccum, Zq, ZqAccum};

/// Reduce an accumulated sum of Zq elements back into Zq.
///
/// Takes anything that fits a ZqAccum.
#[inline]
pub fn reduce_q<T: Into<ZqAccum>>(x: T) -> Zq {
    (x.into() % ZqAccum::from(Q)) as Zq
}

/// Reduce an accumulated sum of Zp elements back into Zp.
///
/// Takes anything that fits a ZpAccum.
#[inline]
pub fn reduce_p<T: Into<ZpAccum>>(x: T) -> Zp {
    (x.into() % ZpAccum::from(P)) as Zp
}

/// Reduce a Zq element into [0, DELTA).
///
/// Takes anything that fits a Zq.
#[inline]
pub fn reduce_delta<T: Into<Zq>>(x: T) -> Zdelta {
    (x.into() % DELTA_ZQ) as Zdelta
}

/// `x - y mod Q`.
#[inline]
pub fn sub_q(x: Zq, y: Zq) -> Zq {
    assert!(x < Q && y < Q, "operands must be reduced mod q");
    // Add Q first so the subtraction cannot go below zero.
    reduce_q(ZqAccum::from(x) + ZqAccum::from(Q) - ZqAccum::from(y))
}

/// `x + y mod P`.
#[inline]
pub fn add_p(x: Zp, y: Zp) -> Zp {
    assert!(
        Zq::from(x) < P && Zq::from(y) < P,
        "operands must be reduced mod p"
    );
    // x + y < 2p fits ZpAccum for any p representable in Zp.
    reduce_p(ZpAccum::from(x) + ZpAccum::from(y))
}

/// `x - y mod P`.
#[inline]
pub fn sub_p(x: Zp, y: Zp) -> Zp {
    assert!(
        Zq::from(x) < P && Zq::from(y) < P,
        "operands must be reduced mod p"
    );
    // Add p first so the subtraction cannot go below zero.
    reduce_p(ZpAccum::from(x) + ZpAccum::from(P) - ZpAccum::from(y))
}

/// `x - y mod delta`. Both must already be in [0, DELTA).
#[inline]
pub fn sub_delta(x: Zdelta, y: Zdelta) -> Zdelta {
    assert!(
        usize::from(x) < DELTA && usize::from(y) < DELTA,
        "operands must be reduced mod delta"
    );
    ((usize::from(x) + DELTA - usize::from(y)) % DELTA) as Zdelta
}
