///! Verifier functionality for convert_to circuit
use bellman::groth16;
use bellman::groth16::{PreparedVerifyingKey, Proof};

use primitives::definitions::NoteCommitment;

/// Convert_to proof verifier
pub fn verify_proof(
    proof: &Proof<bls12_381::Bls12>,
    cm_note: &NoteCommitment,
    verifying_key: &PreparedVerifyingKey<bls12_381::Bls12>,
) -> bool {
    groth16::verify_proof(verifying_key, proof, &[*cm_note]).is_ok()
}
