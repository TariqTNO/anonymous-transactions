//! Cryptographic Hash Function (CRH) implementations out-of-circuit

use bitvec::order;
use bitvec::view::AsBits;
use bls12_381::Scalar;
use ff::PrimeField;
use group::Curve;

use crate::definitions::{MemoryCommitment, NoteCommitment, TransactionTime};
use crate::merkle_trees::TreeType;
use crate::pedersen_hash::{pedersen_hash, Personalisation};

/// Compute the hash of two nodes `left` and `right` in a Merkle tree with the given personalisation.
pub fn merkle_tree_hash(
    tree_type: TreeType,
    depth: usize,
    left: &<Scalar as PrimeField>::Repr,
    right: &<Scalar as PrimeField>::Repr,
) -> <Scalar as PrimeField>::Repr {
    assert_eq!(depth >> 8, 0);

    let left = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(left.as_bits::<order::Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    let right = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(right.as_bits::<order::Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    jubjub::ExtendedPoint::from(pedersen_hash(
        Personalisation::MerkleTree(tree_type, depth),
        left.iter()
            .copied()
            .take(Scalar::NUM_BITS as usize)
            .chain(right.iter().copied().take(Scalar::NUM_BITS as usize)),
    ))
    .to_affine()
    .get_u()
    .to_repr()
}

/// Compute the hash of a commitment `cm` and time `t` to obtain a proper leaf value.
fn leaf_hash(cm: Scalar, t: &TransactionTime) -> Scalar {
    let bits_cm = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(cm.to_repr().as_bits::<order::Lsb0>()) {
            *a = *b;
        }
        tmp
    };
    let bits_t = {
        let mut tmp = [false; 64];
        for (a, b) in tmp.iter_mut().zip(t.0.as_bits::<order::Lsb0>()) {
            *a = *b;
        }
        tmp
    };
    jubjub::ExtendedPoint::from(pedersen_hash(
        Personalisation::MemLeaf,
        bits_cm
            .iter()
            .copied()
            .take(Scalar::NUM_BITS as usize)
            .chain(bits_t.iter().copied()),
    ))
    .to_affine()
    .get_u()
}

/// Compute the hash of a note commitment `cm` and time `t` to obtain a proper leaf value.
pub fn note_leaf_hash(cm: NoteCommitment, t: &TransactionTime) -> Scalar {
    leaf_hash(cm, t)
}

/// Compute the hash of a memory commitment `cm` and time `t` to obtain a proper leaf value.
pub fn memory_leaf_hash(cm: MemoryCommitment, t: &TransactionTime) -> Scalar {
    leaf_hash(cm, t)
}
