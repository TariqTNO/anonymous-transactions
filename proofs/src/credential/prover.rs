//! Prover functionality for credential circuit.

use bellman::groth16::{create_random_proof, Parameters, Proof};
use rand::rngs::OsRng;

use primitives::definitions::Credentials;

use crate::credential::circuit::Credential;

/// Credential proof constructor
pub fn create_proof(
    cred: &Credentials,
    proving_key: &Parameters<bls12_381::Bls12>,
) -> Proof<bls12_381::Bls12> {
    // Construct circuit
    let cred = Credential { cred: Some(cred) };

    // Initialise secure PRNG
    let mut rng = OsRng;

    create_random_proof(cred, proving_key, &mut rng).expect("Creating a proof should not fail.")
}
