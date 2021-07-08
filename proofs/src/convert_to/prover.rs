//! Prover functionality for convert_to circuit

use bellman::groth16::{create_random_proof, Parameters, Proof};
use rand::rngs::OsRng;

use primitives::definitions::Note;

use crate::convert_to::circuit::ConvertTo;

/// Convert_to proof constructor
pub fn create_proof(
    note_new: &Note,
    proving_key: &Parameters<bls12_381::Bls12>,
) -> Proof<bls12_381::Bls12> {
    // Construct circuit
    let c_to = ConvertTo {
        note_new: Some(note_new),
    };

    // Initialise secure PRNG
    let mut rng = OsRng;

    create_random_proof(c_to, proving_key, &mut rng).expect("Creating a proof should not fail.")
}
