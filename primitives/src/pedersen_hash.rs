//! This file is a minor adaptation on the version from [ZCash][zcash].
//!
//! [zcash]: https://github.com/zcash/librustzcash/blob/master/zcash_primitives/src/sapling/pedersen_hash.rs

use std::ops::{AddAssign, Neg};

use byteorder::{ByteOrder, LittleEndian};
use ff::PrimeField;
use group::Group;

use crate::constants::{
    PEDERSEN_HASH_CHUNKS_PER_GENERATOR, PEDERSEN_HASH_EXP_TABLE, PEDERSEN_HASH_EXP_WINDOW_SIZE,
};
use crate::merkle_trees::TreeType;

#[derive(Copy, Clone)]
pub enum Personalisation {
    CredCommitment,
    NoteCommitment,
    MemCommitment,
    MemLeaf,
    MerkleTree(TreeType, usize),
}

impl Personalisation {
    pub fn get_bits(&self) -> Vec<bool> {
        match *self {
            Personalisation::CredCommitment => vec![
                true, false, false, false, false, false, false, false, false, false,
            ],
            Personalisation::NoteCommitment => vec![
                true, false, false, false, false, false, false, false, false, true,
            ],
            Personalisation::MemCommitment => vec![
                true, false, false, false, false, false, false, false, true, false,
            ],
            Personalisation::MemLeaf => vec![
                true, false, false, false, false, false, false, false, true, true,
            ],
            Personalisation::MerkleTree(tree_type, num) => {
                assert!(num < 128);

                let mut personalisation = (0..10)
                    .rev()
                    .map(|i| (num >> i) & 1 == 1)
                    .collect::<Vec<_>>();
                personalisation[1] &= (tree_type as u8 >> 1) & 1 == 1;
                personalisation[2] &= tree_type as u8 & 1 == 1;
                personalisation
            }
        }
    }
}

pub fn pedersen_hash<I>(personalisation: Personalisation, bits: I) -> jubjub::SubgroupPoint
where
    I: IntoIterator<Item = bool>,
{
    let mut bits = personalisation
        .get_bits()
        .into_iter()
        .chain(bits.into_iter());

    let mut result = jubjub::SubgroupPoint::identity();
    let mut generators = PEDERSEN_HASH_EXP_TABLE.iter();

    loop {
        let mut acc = jubjub::Scalar::zero();
        let mut cur = jubjub::Scalar::one();
        let mut chunks_remaining = PEDERSEN_HASH_CHUNKS_PER_GENERATOR;
        let mut encountered_bits = false;

        // Grab three bits from the input
        while let Some(a) = bits.next() {
            encountered_bits = true;

            let b = bits.next().unwrap_or(false);
            let c = bits.next().unwrap_or(false);

            // Start computing this portion of the scalar
            let mut tmp = cur;
            if a {
                tmp.add_assign(&cur);
            }
            cur = cur.double(); // 2^1 * cur
            if b {
                tmp.add_assign(&cur);
            }

            // conditionally negate
            if c {
                tmp = tmp.neg();
            }

            acc.add_assign(&tmp);

            chunks_remaining -= 1;

            if chunks_remaining == 0 {
                break;
            } else {
                cur = cur.double().double().double(); // 2^4 * cur
            }
        }

        if !encountered_bits {
            break;
        }

        let mut table: &[Vec<jubjub::SubgroupPoint>] =
            &generators.next().expect("we don't have enough generators");
        let window = PEDERSEN_HASH_EXP_WINDOW_SIZE as usize;
        let window_mask = (1u64 << window) - 1;

        let acc = acc.to_repr();
        let num_limbs: usize = acc.as_ref().len() / 8;
        let mut limbs = vec![0u64; num_limbs + 1];
        LittleEndian::read_u64_into(acc.as_ref(), &mut limbs[..num_limbs]);

        let mut tmp = jubjub::SubgroupPoint::identity();

        let mut pos = 0;
        while pos < jubjub::Scalar::NUM_BITS as usize {
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let i = (if bit_idx + window < 64 {
                // This window's bits are contained in a single u64.
                limbs[u64_idx] >> bit_idx
            } else {
                // Combine the current u64's bits with the bits from the next u64.
                (limbs[u64_idx] >> bit_idx) | (limbs[u64_idx + 1] << (64 - bit_idx))
            } & window_mask) as usize;

            tmp += table[0][i];

            pos += window;
            table = &table[1..];
        }

        result += tmp;
    }

    result
}
