//! In-circuit SAVER functionality.
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use bellman::{ConstraintSystem, SynthesisError};
use ff::PrimeField;

use primitives::constants::SAVER_BLOCK_SIZE;

use crate::helper_functions::conditional_pack_into_inputs;

pub fn conditional_saver_inputise<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    circuit_bits: &[Boolean],
    conditional_bit: &AllocatedBit,
) -> Result<(), SynthesisError> {
    // pad the circuit_bits to the appropriate length
    let mut circuit_bits = circuit_bits.to_vec();
    while circuit_bits.len() % (SAVER_BLOCK_SIZE as usize) != 0 {
        circuit_bits.push(Boolean::constant(false));
    }

    // pack circuit bits per block of size SAVER_BLOCK_SIZE as input conditioned on conditional_bit
    for (i, bits) in circuit_bits
        .chunks_exact(SAVER_BLOCK_SIZE as usize)
        .enumerate()
    {
        conditional_pack_into_inputs(
            cs.namespace(|| format!("chunk {}", i)),
            bits,
            conditional_bit,
        )?;
    }
    Ok(())
}

pub fn conditional_saver_pack<Scalar: PrimeField>(
    message: &[u8],
    conditional_bit: bool,
) -> Vec<Scalar> {
    let mut message_bits = bytes_to_bits(message);
    // pad the message_bits to the appropriate length
    while message_bits.len() % (SAVER_BLOCK_SIZE as usize) != 0 {
        message_bits.push(false);
    }

    //pack circuit bits per block of size SAVER_BLOCK_SIZE as input
    let mut message = vec![];
    for bits in message_bits.chunks_exact_mut(SAVER_BLOCK_SIZE as usize) {
        message.push(if !conditional_bit {
            Scalar::zero()
        } else {
            compute_multipacking::<Scalar>(bits)[0]
        }) // there should only be one element in the vector
    }

    message
}
