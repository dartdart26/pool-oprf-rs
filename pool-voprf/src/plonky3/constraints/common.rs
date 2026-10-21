use crate::plonky3::Val;
use p3_field::integers::QuotientMap;
use pool_prf::params::{N, ZqAccum};

/// (K) starts with the key bits `sk_0 .. sk_{n-1}`, which other constraints
/// read from there.
pub(crate) const KEY_BITS: usize = N;

/// The lowest `count` bits of `value`, as columns.
pub(crate) fn bits(value: ZqAccum, count: usize) -> impl Iterator<Item = Val> {
    (0..count).map(move |k| Val::from_int((value >> k) & 1))
}
