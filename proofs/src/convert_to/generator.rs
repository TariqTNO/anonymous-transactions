//! Generator functionality for convert_to circuit.

use bellman::groth16::Parameters;
use bellman::{groth16, SynthesisError};
use rand::rngs::OsRng;

use crate::convert_to::circuit::ConvertTo;

pub fn generate_random_parameters() -> Result<Parameters<bls12_381::Bls12>, SynthesisError> {
    let c_to = ConvertTo { note_new: None };
    let mut rng = OsRng;

    groth16::generate_random_parameters(c_to, &mut rng)
}
