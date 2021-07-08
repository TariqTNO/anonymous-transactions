//! Implementation of all in-circuit commitments.

use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::num::AllocatedNum;
use bellman::{ConstraintSystem, SynthesisError};

use primitives::pedersen_hash::Personalisation;

use crate::constants::{
    FixedGenerator, CRED_COMMITMENT_RANDOMNESS_GENERATOR, MEM_COMMITMENT_RANDOMNESS_GENERATOR,
    NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
};
use crate::ecc::fixed_base_multiplication;
use crate::pedersen_hash::pedersen_hash;

/// Compute in-circuit commitment of the `preimage` using `randomness` and add this to the circuit.
/// Return the unique `Num` that represents the hash.
fn comm<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    randomness: &[Boolean],
    preimage: &[Boolean],
    personalisation: Personalisation,
    fixed_generator: FixedGenerator,
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let hash = pedersen_hash(cs.namespace(|| "hash"), personalisation, preimage)?;
    let randomness =
        fixed_base_multiplication(cs.namespace(|| "randomness"), fixed_generator, randomness)?;

    Ok(hash
        .add(cs.namespace(|| "add hash and randomness"), &randomness)?
        .get_u()
        .clone())
}

/// Compute in-circuit COMM^cred and add this to the circuit.
/// Return the unique `Num` that represents the hash.
pub fn comm_cred<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    s_cred: &[Boolean],
    pk_addr: &[Boolean],
    sk_addr: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    assert_eq!(s_cred.len(), 252);
    assert_eq!(pk_addr.len(), 256);
    assert_eq!(sk_addr.len(), 256);

    let mut preimage = vec![];
    preimage.extend(pk_addr.iter().cloned());
    preimage.extend(sk_addr.iter().cloned());
    comm(
        cs,
        s_cred,
        &preimage,
        Personalisation::CredCommitment,
        &*CRED_COMMITMENT_RANDOMNESS_GENERATOR,
    )
}

/// Compute in-circuit COMM^note and add this to the circuit.
/// Return the unique `Num` that represents the hash.
pub fn comm_note<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    s_note: &[Boolean],
    pk_addr: &[Boolean],
    v_note: &[Boolean],
    t_delta: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    assert_eq!(s_note.len(), 252);
    assert_eq!(pk_addr.len(), 256);
    assert_eq!(v_note.len(), 64);
    assert_eq!(t_delta.len(), 64);

    let mut preimage = vec![];
    preimage.extend(pk_addr.iter().cloned());
    preimage.extend(v_note.iter().cloned());
    preimage.extend(t_delta.iter().cloned());
    comm(
        cs,
        s_note,
        &preimage,
        Personalisation::NoteCommitment,
        &*NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
    )
}

/// Compute in-circuit COMM^mem and add this to the circuit.
/// Return the unique `Num` that represents the hash.
pub fn comm_mem<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    s_mem: &[Boolean],
    pk_addr: &[Boolean],
    v_mem: &[Boolean],
    c_mem: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    assert_eq!(s_mem.len(), 252);
    assert_eq!(pk_addr.len(), 256);
    assert_eq!(v_mem.len(), 64);
    assert_eq!(c_mem.len(), 64);

    let mut preimage = vec![];
    preimage.extend(pk_addr.iter().cloned());
    preimage.extend(v_mem.iter().cloned());
    preimage.extend(c_mem.iter().cloned());
    comm(
        cs,
        s_mem,
        &preimage,
        Personalisation::MemCommitment,
        &*MEM_COMMITMENT_RANDOMNESS_GENERATOR,
    )
}
