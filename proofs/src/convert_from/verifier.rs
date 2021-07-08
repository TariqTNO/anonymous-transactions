use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use bellman::groth16;
use bellman::groth16::{PreparedVerifyingKey, Proof};

use primitives::definitions::{AddressPublicKey, MerkleRoot, NoteNullifier};

///! Verifier functionality for convert_to circuit

pub fn verify_proof(
    proof: &Proof<bls12_381::Bls12>,
    rt_note: &MerkleRoot,
    eta: &NoteNullifier,
    pk_addr: &AddressPublicKey,
    verifying_key: &PreparedVerifyingKey<bls12_381::Bls12>,
) -> bool {
    let mut packed_public_inputs = vec![*rt_note];

    let mut public_input = vec![];
    public_input.extend(eta);
    public_input.extend(pk_addr);
    packed_public_inputs.extend(compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
        &public_input,
    )));
    groth16::verify_proof(verifying_key, proof, packed_public_inputs.as_ref()).is_ok()
}
