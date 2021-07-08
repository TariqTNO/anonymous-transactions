//! Implementation of in-circuit Merkle Tree computations.

use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::gadgets::Assignment;
use bellman::{ConstraintSystem, SynthesisError};

use primitives::constants::{CREDENTIAL_MT_DEPTH, MEMORY_MT_DEPTH, NOTE_MT_DEPTH};
use primitives::definitions::MerkleWitness;
use primitives::merkle_trees::TreeType;
use primitives::pedersen_hash::Personalisation;

use crate::crhs::{memory_leaf_hash, merkle_tree_hash, note_leaf_hash};

/// Compute the Merkle root and position of `cm` in the Merkle tree with `personalisation`, and
/// witness the `witness`. Returns a tuple of the root and the position.
fn merkle_rt<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    tree_type: TreeType,
    tree_depth: usize,
    cm: &AllocatedNum<bls12_381::Scalar>,
    witness: Option<&MerkleWitness>,
) -> Result<(AllocatedNum<bls12_381::Scalar>, Vec<Boolean>), SynthesisError> {
    // Define initial current subtree root value.
    let mut cur_subtree = cm.clone();
    // Define vector to store the bits of the position in reversed order.
    let mut position: Vec<Boolean> = vec![];

    //  Compute the root value of the tree
    for depth in 0..tree_depth {
        let cs = &mut cs.namespace(|| format!("depth {}", depth));

        // Witness the bit that says if the current subtree is on the right side.
        let cur_subtree_is_right = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "cur subtree is right"),
            witness.map(|witness| witness.path[depth].1),
        )?);
        // Store the position bit
        position.push(cur_subtree_is_right.clone());

        // Assign default left and right hand. We assume current subtree is on the left.
        // Also witness the sibling of the current subtree at the current depth.
        let left = cur_subtree;
        let right = AllocatedNum::alloc(cs.namespace(|| "sibling"), || {
            witness
                .map(|witness| witness.path[depth].0)
                .get()
                .map(|x| *x)
        })?;

        // Perform a conditional swap of lhs and rhs on cur_subtree_is_right
        // i.e. we swap lhs and rhs if cur_subtree_is_right is true.
        let (left, right) = AllocatedNum::conditionally_reverse(
            cs.namespace(|| "conditional swap"),
            &left,
            &right,
            &cur_subtree_is_right,
        )?;

        let mut preimage = vec![];
        preimage.extend(left.to_bits_le(cs.namespace(|| "left to bits"))?);
        preimage.extend(right.to_bits_le(cs.namespace(|| "right to bits"))?);

        // Compute the value of the parent.
        cur_subtree = merkle_tree_hash(
            cs.namespace(|| "value of parent"),
            Personalisation::MerkleTree(tree_type, depth),
            &preimage,
        )?;
    }
    // Reverse the bits of the position to obtain it in the correct order.
    position.reverse();

    Ok((cur_subtree, position))
}

/// Compute the Merkle root and position of `cm` in the Credential Merkle tree, given `witness`.
/// Returns a tuple of the root and the position.
pub fn merkle_rt_cred<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    cm: &AllocatedNum<bls12_381::Scalar>,
    witness: Option<&MerkleWitness>,
) -> Result<(AllocatedNum<bls12_381::Scalar>, Vec<Boolean>), SynthesisError> {
    merkle_rt(cs, TreeType::Credential, CREDENTIAL_MT_DEPTH, cm, witness)
}

/// Compute the Merkle root and position of `cm` in the Note Merkle tree, given `witness`.
/// Returns a tuple of the root and the position.
pub fn merkle_rt_note<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    cm: &AllocatedNum<bls12_381::Scalar>,
    t: &[Boolean],
    witness: Option<&MerkleWitness>,
) -> Result<(AllocatedNum<bls12_381::Scalar>, Vec<Boolean>), SynthesisError> {
    // compute the leaf value from the commitment and the time
    let leaf = note_leaf_hash(cs.namespace(|| "leaf computation"), cm, t)?;

    // compute the root using the leaf value
    merkle_rt(cs, TreeType::Note, NOTE_MT_DEPTH, &leaf, witness)
}

/// Compute the Merkle root and position of `cm` in the Memory Merkle tree, given `witness`.
/// Returns a tuple of the root and the position.
pub fn merkle_rt_mem<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    cm: &AllocatedNum<bls12_381::Scalar>,
    t: &[Boolean],
    witness: Option<&MerkleWitness>,
) -> Result<(AllocatedNum<bls12_381::Scalar>, Vec<Boolean>), SynthesisError> {
    // compute the leaf value from the commitment and the time
    let leaf = memory_leaf_hash(cs.namespace(|| "leaf computation"), cm, t)?;

    // compute the root using the leaf value
    merkle_rt(cs, TreeType::Memory, MEMORY_MT_DEPTH, &leaf, witness)
}
