//! Verifier functionality for credential circuit

use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use bellman::groth16::Proof;

use primitives::definitions::{
    MemoryCommitment, MemoryNullifier, MerkleRoot, NoteCommitment, NoteNullifier, SignatureKeyHash,
    SignatureKeyLink, TransactionTime,
};
use primitives::saver::{
    verify_groth16_proof_and_saver_encryption, PreparedVerifyingKeySaver, SaverCiphertext,
    SaverPublicKey,
};

/// Transfer proof verifier
pub fn verify_proof(
    proof: &Proof<bls12_381::Bls12>,
    ciphertext: &SaverCiphertext<bls12_381::Bls12>,
    rt_cred: &MerkleRoot,
    rt_note: Option<&MerkleRoot>,
    rt_mem: &MerkleRoot,
    eta: Option<&NoteNullifier>,
    mu: &MemoryNullifier,
    cm_note_new: &NoteCommitment,
    cm_mem_new: &MemoryCommitment,
    k: &SignatureKeyHash,
    kappa: &SignatureKeyLink,
    t_new: &TransactionTime,
    verifying_key: &PreparedVerifyingKeySaver<bls12_381::Bls12>,
    saver_public_key: &SaverPublicKey<bls12_381::Bls12>,
) -> bool {
    // Pack the public inputs in the right format.
    let mut packed_public_input: Vec<bls12_381::Scalar> =
        vec![rt_note.copied().unwrap_or_else(bls12_381::Scalar::one)];
    packed_public_input.extend(&compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
        eta.unwrap_or_else(|| &[0; 32]),
    )));
    packed_public_input.push(*rt_mem);
    packed_public_input.push(*rt_cred);
    packed_public_input.push(*cm_note_new);
    packed_public_input.push(*cm_mem_new);

    let mut public_input = vec![];
    public_input.extend(mu);
    public_input.extend(k);
    public_input.extend(kappa);
    public_input.extend(&t_new.0);
    packed_public_input.extend(&compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
        &public_input,
    )));

    verify_groth16_proof_and_saver_encryption(
        verifying_key,
        saver_public_key,
        proof,
        ciphertext,
        packed_public_input.as_slice(),
    )
    .is_ok()
}
