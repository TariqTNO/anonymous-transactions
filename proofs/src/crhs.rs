//! Implementation of all in-circuit CRH's.

use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::num::AllocatedNum;
use bellman::{ConstraintSystem, SynthesisError};

use primitives::pedersen_hash::Personalisation;

use crate::helper_functions::boolean_vector_switch_le_be;
use crate::pedersen_hash::pedersen_hash;

/// Compute the in-circuit hash of the preimage in a Merkle tree with the given
/// `personalisation` and add this to the circuit. Return the unique `Num` that represents the hash.
pub fn merkle_tree_hash<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    personalisation: Personalisation,
    preimage: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    assert_eq!(preimage.len(), 510);

    pedersen_hash(cs, personalisation, preimage).map(|x| x.get_u().clone())
}

fn leaf_hash<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    cm: &AllocatedNum<bls12_381::Scalar>,
    t: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    assert_eq!(t.len(), 64);

    let mut preimage = vec![];
    preimage.extend(cm.to_bits_le(cs.namespace(|| "cm to bits"))?);
    preimage.extend(boolean_vector_switch_le_be(t));

    pedersen_hash(cs, Personalisation::MemLeaf, &preimage).map(|x| x.get_u().clone())
}

pub fn memory_leaf_hash<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    cm: &AllocatedNum<bls12_381::Scalar>,
    t: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    leaf_hash(cs, cm, t)
}

pub fn note_leaf_hash<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    cm: &AllocatedNum<bls12_381::Scalar>,
    t: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    leaf_hash(cs, cm, t)
}
