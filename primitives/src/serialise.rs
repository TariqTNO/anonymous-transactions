//! Serialisation helper functions.

use bls12_381::Scalar;
use ff::PrimeField;

pub fn u64_array_to_u8_vector(u64_array: &[u64]) -> Vec<u8> {
    let mut u8_array = vec![];
    for value in u64_array {
        for i in (0..8).rev() {
            u8_array.push((value >> (8 * i) & (2_u64.pow(8) - 1)) as u8)
        }
    }
    u8_array
}

pub fn u128_to_u8_vector(u128: u128) -> Vec<u8> {
    let mut u8_array = vec![];
    for i in (0..16).rev() {
        u8_array.push((u128 >> (8 * i) & (2_u128.pow(8) - 1)) as u8)
    }
    u8_array
}

pub fn u8_array_to_u64(u8_array: &[u8]) -> u64 {
    assert_eq!(u8_array.len(), 8);
    let mut u64 = 0;
    for i in 0..8 {
        u64 += (u8_array[7 - i] as u64) << (8 * i) as u64;
    }
    u64
}

pub fn u8_array_to_u128(u8_array: &[u8]) -> u128 {
    assert_eq!(u8_array.len(), 16);
    let mut u128 = 0;
    for i in 0..16 {
        u128 += (u8_array[15 - i] as u128) << (8 * i) as u128;
    }
    u128
}

pub fn fr_from_repr(cm: <Scalar as PrimeField>::Repr) -> std::io::Result<Scalar> {
    match Scalar::from_repr(cm) {
        Some(cm) => Ok(cm),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed conversion from scalar to repr.",
        )),
    }
}
