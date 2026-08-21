//! Bit-packed Zq vectors. A Zq element takes LOG_Q bits on the wire.
//!
//! Point a field at this module and serde does the rest:
//!
//! ```text
//! #[serde(with = "crate::packing")]
//! e: [Zq; N],
//! ```

use bitstream_io::{BitRead, BitReader, BitWrite, BitWriter, LittleEndian};
use pool_prf::params::{LOG_Q, Zq};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

// Pack `LOG_Q` bits per element.
fn pack(values: &[Zq]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = BitWriter::endian(&mut out, LittleEndian);
    for &value in values {
        writer.write::<LOG_Q, Zq>(value).expect("write fail");
    }
    writer.byte_align().expect("align fail");
    out
}

// Unpack `LEN` elements, or `None` if `bytes` runs out first.
fn unpack<const LEN: usize>(bytes: &[u8]) -> Option<[Zq; LEN]> {
    let mut reader = BitReader::endian(bytes, LittleEndian);
    let mut values: [Zq; LEN] = [0; LEN];
    for value in &mut values {
        *value = reader.read::<LOG_Q, Zq>().ok()?;
    }
    Some(values)
}

pub(crate) fn serialize<S: Serializer, const LEN: usize>(
    values: &[Zq; LEN],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    (LEN as u64, serde_bytes::Bytes::new(&pack(values))).serialize(serializer)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>, const LEN: usize>(
    deserializer: D,
) -> Result<[Zq; LEN], D::Error> {
    let (count, bytes) = <(u64, serde_bytes::ByteBuf)>::deserialize(deserializer)?;
    if count != LEN as u64 {
        return Err(D::Error::custom(format!(
            "packed vector holds {count} elements, not {LEN}"
        )));
    }
    unpack(&bytes).ok_or_else(|| D::Error::custom("packed bytes are short of the count"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::Options;
    use pool_prf::params::{N, Q};
    use rand::Rng;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Row(#[serde(with = "crate::packing")] [Zq; N]);

    fn codec() -> impl Options {
        bincode::options().with_big_endian().with_varint_encoding()
    }

    fn a_row() -> [Zq; N] {
        let mut rng = rand::rng();
        std::array::from_fn(|_| rng.random_range(0..Q))
    }

    #[test]
    fn round_trips_a_full_row() {
        let values = a_row();
        assert_eq!(unpack::<N>(&pack(&values)).unwrap(), values);
    }

    #[test]
    fn round_trips_the_boundary_values() {
        let values: [Zq; 6] = [0, Q - 1, 1, Q - 2, 0, Q - 1];
        assert_eq!(unpack::<6>(&pack(&values)).unwrap(), values);
    }

    #[test]
    fn round_trips_counts_that_end_mid_byte() {
        fn round_trip<const LEN: usize>() {
            let values: [Zq; LEN] = std::array::from_fn(|i| (i as Zq * 37) % Q);
            assert_eq!(
                unpack::<LEN>(&pack(&values)).unwrap(),
                values,
                "count {LEN}"
            );
        }

        round_trip::<0>();
        round_trip::<1>();
        round_trip::<2>();
        round_trip::<3>();
        round_trip::<4>();
        round_trip::<5>();
        round_trip::<6>();
        round_trip::<7>();
        round_trip::<8>();
    }

    #[test]
    fn rejects_a_count_the_bytes_cannot_fill() {
        assert!(unpack::<100>(&pack(&[0, 0, 0])).is_none());
    }

    #[test]
    fn round_trips_through_serde() {
        let values = a_row();
        let bytes = codec().serialize(&Row(values)).unwrap();
        assert_eq!(codec().deserialize::<Row>(&bytes).unwrap().0, values);
    }

    #[test]
    fn deserialize_rejects_bytes_short_of_the_count() {
        let forged = codec()
            .serialize(&(N as u64, serde_bytes::Bytes::new(&pack(&[3, 42]))))
            .unwrap();
        assert!(codec().deserialize::<Row>(&forged).is_err());
    }

    #[test]
    fn deserialize_rejects_a_count_that_is_not_the_row_length() {
        let short: Vec<Zq> = a_row()[..N - 1].to_vec();
        let forged = codec()
            .serialize(&(short.len() as u64, serde_bytes::Bytes::new(&pack(&short))))
            .unwrap();
        assert!(codec().deserialize::<Row>(&forged).is_err());
    }
}
