//! Implementation of all in-circuit PRF's.

use bellman::gadgets::blake2s::blake2s;
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::{ConstraintSystem, SynthesisError};
use ff::PrimeField;

use primitives::constants::{
    MEMORY_MT_DEPTH, NOTE_MT_DEPTH, PERSONALISATION_PRF_ADDR, PERSONALISATION_PRF_ETA,
    PERSONALISATION_PRF_KAPPA, PERSONALISATION_PRF_MU,
};

use crate::helper_functions::boolean_vector_switch_le_be;

/// Generic PRF used for protocol specific PRF's. Exposes calculation to the circuit, and outputs
/// result in big endian format.
fn prf<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    key: &[Boolean],
    bit1: bool,
    bit2: bool,
    seed: &[Boolean],
    personalisation: &[u8],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(key.len(), 256);
    assert_eq!(seed.len(), 254);

    // obtain preimage in little endian format
    let mut preimage = vec![];
    preimage.extend(key.iter().cloned());
    preimage.push(Boolean::constant(bit1));
    preimage.push(Boolean::constant(bit2));
    preimage.extend(seed.iter().cloned());
    let preimage = boolean_vector_switch_le_be(&preimage);

    // compute/add blake2s hash in-circuit and return it in big endian format
    blake2s(cs, &preimage, personalisation).map(|image| boolean_vector_switch_le_be(&image))
}

/// Compute PRF^addr, expose computation to circuit and output pk_addr in big endian format.
pub fn prf_addr<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    sk_addr: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    prf(
        cs,
        sk_addr,
        false,
        false,
        &(0..254)
            .map(|_| Boolean::constant(false))
            .collect::<Vec<_>>(),
        PERSONALISATION_PRF_ADDR,
    )
}

/// Compute PRF^eta, expose computation to circuit and output eta in big endian format.
pub fn prf_eta<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    sk_addr: &[Boolean],
    pos_note: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(pos_note.len(), NOTE_MT_DEPTH);

    // Compute the seed
    let mut seed = vec![];
    seed.extend((0..(254 - NOTE_MT_DEPTH)).map(|_| Boolean::constant(false)));
    seed.extend(pos_note.iter().cloned());

    prf(cs, sk_addr, false, true, &seed, PERSONALISATION_PRF_ETA)
}

/// Compute PRF^mu, expose computation to circuit and output mu in big endian format.
pub fn prf_mu<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    sk_addr: &[Boolean],
    pos_mem: &[Boolean],
    is_mem: &AllocatedBit,
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(pos_mem.len(), MEMORY_MT_DEPTH);

    // Compute the seed
    let mut seed = vec![];
    seed.extend((0..(254 - MEMORY_MT_DEPTH - 1)).map(|_| Boolean::constant(false)));
    seed.push(Boolean::from(is_mem.clone()));
    seed.extend(pos_mem.iter().cloned());

    prf(cs, sk_addr, true, false, &seed, PERSONALISATION_PRF_MU)
}

/// Compute PRF^kappa, expose computation to circuit and output kappa in big endian format.
pub fn prf_kappa<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    sk_addr: &[Boolean],
    k: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(k.len(), 256);

    prf(
        cs,
        sk_addr,
        true,
        true,
        &k[0..254],
        PERSONALISATION_PRF_KAPPA,
    )
}
