//! This file is a minor adaptation on the version from [ZCash][zcash].
//!
//! Gadget for Pedersen hash.
//!
//! [zcash]: https://github.com/zcash/librustzcash/blob/master/zcash_proofs/src/circuit/pedersen_hash.rs.

use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::lookup::lookup3_xy_with_conditional_negation;
use bellman::{ConstraintSystem, SynthesisError};

use primitives::pedersen_hash::Personalisation;

use crate::constants::PEDERSEN_CIRCUIT_GENERATORS;
use crate::ecc::{EdwardsPoint, MontgomeryPoint};

fn get_constant_bools(person: &Personalisation) -> Vec<Boolean> {
    person
        .get_bits()
        .into_iter()
        .map(Boolean::constant)
        .collect()
}

pub fn pedersen_hash<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    personalisation: Personalisation,
    bits: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError> {
    let personalisation = get_constant_bools(&personalisation);
    assert_eq!(personalisation.len(), 10);

    let mut edwards_result = None;
    let mut bits = personalisation.iter().chain(bits.iter()).peekable();
    let mut segment_generators = PEDERSEN_CIRCUIT_GENERATORS.iter();
    let boolean_false = Boolean::constant(false);

    let mut segment_i = 0;
    while bits.peek().is_some() {
        let mut segment_result = None;
        let mut segment_windows = &segment_generators.next().expect("enough segments")[..];

        let mut window_i = 0;
        while let Some(a) = bits.next() {
            let b = bits.next().unwrap_or(&boolean_false);
            let c = bits.next().unwrap_or(&boolean_false);

            let tmp = lookup3_xy_with_conditional_negation(
                cs.namespace(|| format!("segment {}, window {}", segment_i, window_i)),
                &[a.clone(), b.clone(), c.clone()],
                &segment_windows[0],
            )?;

            let tmp = MontgomeryPoint::interpret_unchecked(tmp.0, tmp.1);

            match segment_result {
                None => {
                    segment_result = Some(tmp);
                }
                Some(ref mut segment_result) => {
                    *segment_result = tmp.add(
                        cs.namespace(|| {
                            format!("addition of segment {}, window {}", segment_i, window_i)
                        }),
                        segment_result,
                    )?;
                }
            }

            segment_windows = &segment_windows[1..];

            if segment_windows.is_empty() {
                break;
            }

            window_i += 1;
        }

        let segment_result = segment_result.expect(
            "bits is not exhausted due to while condition;
                    thus there must be a segment window;
                    thus there must be a segment result",
        );

        // Convert this segment into twisted Edwards form.
        let segment_result = segment_result.into_edwards(
            cs.namespace(|| format!("conversion of segment {} into edwards", segment_i)),
        )?;

        match edwards_result {
            Some(ref mut edwards_result) => {
                *edwards_result = segment_result.add(
                    cs.namespace(|| format!("addition of segment {} to accumulator", segment_i)),
                    edwards_result,
                )?;
            }
            None => {
                edwards_result = Some(segment_result);
            }
        }

        segment_i += 1;
    }

    Ok(edwards_result.unwrap())
}
