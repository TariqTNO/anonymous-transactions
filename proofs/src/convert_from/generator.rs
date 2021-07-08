//! Generator functionality for convert_from circuit.

use bellman::groth16::Parameters;
use bellman::{groth16, SynthesisError};
use rand::rngs::OsRng;

use crate::convert_from::circuit::ConvertFrom;

pub fn generate_random_parameters() -> Result<Parameters<bls12_381::Bls12>, SynthesisError> {
    let c_from = ConvertFrom {
        cred: None,
        note_old: None,
        note_merkle_witness: None,
    };
    let mut rng = OsRng;

    groth16::generate_random_parameters(c_from, &mut rng)
}
