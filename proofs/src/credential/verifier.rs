//! Verifier functionality for credential circuit

use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use bellman::groth16;
use bellman::groth16::{PreparedVerifyingKey, Proof};

use primitives::definitions::{AddressPublicKey, CredentialCommitment};

/// Credential proof verifier
pub fn verify_proof(
    proof: &Proof<bls12_381::Bls12>,
    pk_addr: &AddressPublicKey,
    cm_cred: &CredentialCommitment,
    verifying_key: &PreparedVerifyingKey<bls12_381::Bls12>,
) -> bool {
    // Pack the public inputs in the right format.
    let mut packed_public_inputs = vec![*cm_cred];
    packed_public_inputs.extend(compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
        pk_addr,
    )));
    groth16::verify_proof(verifying_key, proof, packed_public_inputs.as_ref()).is_ok()
}
