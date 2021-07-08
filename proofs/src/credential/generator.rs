//! Generator functionality for credential circuit.

use bellman::groth16::Parameters;
use bellman::{groth16, SynthesisError};
use rand::rngs::OsRng;

use crate::credential::circuit::Credential;

pub fn generate_random_parameters() -> Result<Parameters<bls12_381::Bls12>, SynthesisError> {
    let cred = Credential { cred: None };
    let mut rng = OsRng;

    groth16::generate_random_parameters(cred, &mut rng)
}
