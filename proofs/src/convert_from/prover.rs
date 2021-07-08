//! Prover functionality for convert_from circuit

use bellman::groth16::{create_random_proof, Parameters, Proof};
use rand::rngs::OsRng;

use primitives::definitions::{Credentials, MerkleWitness, Note};

use crate::convert_from::circuit::ConvertFrom;

/// Convert_from proof constructor
pub fn create_proof(
    cred: &Credentials,
    note_old: &Note,
    note_merkle_witness: &MerkleWitness,
    proving_key: &Parameters<bls12_381::Bls12>,
) -> Proof<bls12_381::Bls12> {
    // Construct circuit
    let c_from = ConvertFrom {
        cred: Some(cred),
        note_old: Some(note_old),
        note_merkle_witness: Some(note_merkle_witness),
    };

    // Initialise secure PRNG
    let mut rng = OsRng;

    create_random_proof(c_from, proving_key, &mut rng).expect("Creating a proof should not fail.")
}
