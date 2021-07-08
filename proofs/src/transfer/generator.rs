//! Generator functionality for transfer circuit.

use bellman::groth16::Parameters;
use bellman::SynthesisError;
use rand::rngs::OsRng;
use rand::Rng;

use primitives::constants::SAVER_BLOCK_SIZE;
use primitives::definitions::{AddressPublicKey, NoteValue};
use primitives::saver::{generate_groth16_and_saver_parameters, SaverKeys};

use crate::transfer::circuit::Transfer;

pub fn generate_random_parameters(
) -> Result<(Parameters<bls12_381::Bls12>, SaverKeys<bls12_381::Bls12>), SynthesisError> {
    let transfer = Transfer {
        cred: None,
        note_old: None,
        mem_old: None,
        mem_ceil: None,
        credential_merkle_witness: None,
        note_merkle_witness: None,
        memory_merkle_witness: None,
        memory_ceil_merkle_witness: None,
        rt_mem_pub: None,
        note_new: None,
        mem_new: None,
        b_note: None,
        b_mem: None,
        b_saver: None,
        k: None,
    };
    let mut rng = OsRng;

    //obtain n, by determining the length of the values that need to be encrypted from random instantiations
    let _pk_addr: AddressPublicKey = rng.gen();
    let _v_note: NoteValue = rng.gen();

    let no_message_blocks = (2_f64 * ((_pk_addr.len() * 8) as f64 / SAVER_BLOCK_SIZE as f64).ceil()
        + ((_v_note.len() * 8) as f64 / SAVER_BLOCK_SIZE as f64).ceil())
        as u64;
    generate_groth16_and_saver_parameters(transfer, no_message_blocks, &mut rng)
}
