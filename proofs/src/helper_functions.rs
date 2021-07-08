//! Helper functions that do not fit in a specific file, most of these are adapted versions of the
//! originals from `zcash_proofs` or `zcash_primitives`.

use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::{AllocatedNum, Num};
use bellman::gadgets::Assignment;
use bellman::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::PrimeField;

/// Convert a boolean vector from big to little endian format or vice versa.
pub fn boolean_vector_switch_le_be(bits: &[Boolean]) -> Vec<Boolean> {
    assert_eq!(bits.len() % 8, 0);

    bits.chunks(8)
        .flat_map(|byte| byte.iter().rev())
        .cloned()
        .collect()
}

/// Witness some bytes to the circuit.
fn witness_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Option<&[u8]>,
    num_bits: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bit_values = if let Some(value) = value {
        let mut tmp = vec![];
        for b in value
            .iter()
            .flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
        {
            tmp.push(Some(b));
        }
        tmp
    } else {
        vec![None; num_bits]
    };
    assert_eq!(bit_values.len(), num_bits);

    let mut bits = vec![];

    for (i, value) in bit_values.into_iter().enumerate() {
        bits.push(Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("bit {}", i)),
            value,
        )?));
    }

    Ok(bits)
}

/// Witness a string of 32 bytes (i.e. 256 bits).
pub fn witness_u256<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    value: Option<&[u8]>,
) -> Result<Vec<Boolean>, SynthesisError> {
    witness_bits(cs, value, 256)
}

/// Witness a string of 8 bytes (i.e. 64 bits).
pub fn witness_u64<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: CS,
    value: Option<&[u8]>,
) -> Result<Vec<Boolean>, SynthesisError> {
    witness_bits(cs, value, 64)
}

/// Compute a `Num` from a vector of bits.
pub fn num_from_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    bits: &[Boolean],
) -> Num<Scalar> {
    assert!(bits.len() <= Scalar::CAPACITY as usize);
    // Initialise the value in number format.
    let mut value_num = Num::zero();
    // Initialise the coefficient for double-and-add to 1.
    let mut coefficient = Scalar::one();
    // Execute double-and-add algorithm to construct the number format from the bit format.
    // Note: reverse the bits, such that the complete number is correct.
    for bit in bits.iter().rev() {
        value_num = value_num.add_bool_with_coeff(CS::one(), bit, coefficient);

        coefficient = coefficient.double();
    }
    // Return the number format of the input bits.
    value_num
}

/// Compute a `LinearCombination` from a vector of `AllocatedNum`s, that are in fact bits. Used for range checks.
pub fn lc_from_allocated_num_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    bits: &[AllocatedNum<Scalar>],
) -> LinearCombination<Scalar> {
    assert!(bits.len() <= Scalar::CAPACITY as usize);
    // Initialise the value in number format.
    let mut lc = LinearCombination::zero();
    // Initialise the coefficient for double-and-add to 1.
    let mut coefficient = Scalar::one();
    // Execute double-and-add algorithm to construct the number format from the bit format.
    // Note: reverse the bits, such that the complete number is correct.
    for bit in bits.iter().rev() {
        lc = lc + (coefficient, bit.get_variable());

        coefficient = coefficient.double();
    }
    // Return the number format of the input bits.
    lc
}

/// Enforce the constraints that ensure that `value` consists of binary values and that the num
/// representation thereof is strictly greater than `lower_bound`.
pub fn strict_lower_bound_check_u64<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    lower_bound: u64,
    value: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    assert_eq!(value.len(), 64);
    let lower_bound = lower_bound + 1;
    let mut lower_bound_bits = vec![];
    let mut first_one = None;
    for i in (0..64).rev() {
        let bit = lower_bound >> i & 1;
        if first_one != None {
            lower_bound_bits.push(bit);
        } else if bit == 1 {
            lower_bound_bits.push(bit);
            first_one = Some(63 - i);
        }
    }
    // arrays are sorted with most significant bit first and least significant bit last
    let lower_bound_bits = lower_bound_bits;
    let (leading_bits, value_bits) =
        value.split_at(first_one.expect("There should be a first '1'."));

    // boolean constrain leading value bits
    let mut leading_bit_sum = LinearCombination::zero();
    for (i, leading_bit) in leading_bits.iter().enumerate() {
        cs.enforce(
            || format!("Boolean constrain leading bit {}", i),
            |lc| lc + leading_bit.get_variable(),
            |lc| lc + CS::one() - leading_bit.get_variable(),
            |lc| lc,
        );
        leading_bit_sum = leading_bit_sum + leading_bit.get_variable();
    }

    // actual range check
    // --> determine and constrain Pi_n
    let leading_bits = || {
        leading_bits
            .iter()
            .map(|x| x.get_value().get().map(|x| *x))
            .collect::<Result<Vec<_>, _>>()
    };
    let pi_base = AllocatedNum::alloc(cs.namespace(|| "pi_n"), || {
        let b = leading_bits()?.contains(&Scalar::one());
        if b {
            Ok(Scalar::zero())
        } else {
            Ok(Scalar::one())
        }
    })?;
    let leading_bit_sum_inverse =
        AllocatedNum::alloc(cs.namespace(|| "leading bit sum inverse"), || {
            Ok(leading_bits()?
                .iter()
                .fold(Scalar::zero(), |mut acc, b| {
                    acc.add_assign(b);
                    acc
                })
                .invert()
                .unwrap_or(Scalar::one()))
        })?;
    let leading_bit_sum_inverse_inverse = AllocatedNum::alloc(
        cs.namespace(|| "inverse of leading bit sum inverse"),
        || Ok(leading_bit_sum_inverse.get_value().get()?.invert().unwrap()),
    )?;

    cs.enforce(
        || "boolean constrain pi_n",
        |lc| lc + CS::one() - pi_base.get_variable(),
        |lc| lc + pi_base.get_variable(),
        |lc| lc,
    );
    cs.enforce(
        || "leading_bit_sum_inverse is non-zero",
        |lc| lc + leading_bit_sum_inverse.get_variable(),
        |lc| lc + leading_bit_sum_inverse_inverse.get_variable(),
        |lc| lc + CS::one(),
    );
    cs.enforce(
        || "compute pi_n",
        |_| leading_bit_sum,
        |lc| lc + leading_bit_sum_inverse.get_variable(),
        |lc| lc + CS::one() - pi_base.get_variable(),
    );

    // --> determine Pi_i for i in range [n-1,t+1], where t is the number of trailing zero's in c.
    let mut t = 0;
    for (i, &b) in lower_bound_bits.iter().rev().enumerate() {
        if b == 1 {
            t = i;
            break;
        }
    }
    let mut pis = vec![pi_base];
    for (i, (&c, a)) in lower_bound_bits
        .iter()
        .zip(value_bits.iter())
        .rev()
        .skip(t + 1)
        .rev()
        .enumerate()
    {
        let pi_prev = pis.last().expect("This vector is not empty.");
        let pi_new = AllocatedNum::alloc(cs.namespace(|| format!("pi_(n-{})", i + 1)), || {
            if c == 1 {
                pi_prev.get_value().get().map(|&pi| pi)
            } else {
                let pi_prev = *pi_prev.get_value().get()?;
                a.get_value().get().map(|a| {
                    let mut pi_new = Scalar::one();
                    pi_new.sub_assign(a);
                    pi_new.mul_assign(&pi_prev);
                    pi_new
                })
            }
        })?;
        cs.enforce(
            || format!("pi_(n-{}) constraint", i + 1),
            |lc| lc + pi_prev.get_variable(),
            |lc| {
                if c == 1 {
                    lc + CS::one()
                } else {
                    lc + CS::one() - a.get_variable()
                }
            },
            |lc| lc + pi_new.get_variable(),
        );
        pis.push(pi_new);
    }
    // --> constrain value bits
    for (i, (&c, a)) in lower_bound_bits.iter().zip(value_bits.iter()).enumerate() {
        if c == 1 {
            cs.enforce(
                || format!("c=1 constraint for bit n-{}", i + 1),
                |lc| lc + pis[i].get_variable() - a.get_variable(),
                |lc| lc + CS::one() - a.get_variable(),
                |lc| lc,
            );
        } else {
            cs.enforce(
                || format!("c=0 constraint for bit n-{}", i + 1),
                |lc| lc + a.get_variable(),
                |lc| lc + CS::one() - a.get_variable(),
                |lc| lc,
            );
        }
    }
    Ok(())
}

/// Enforce the constraints that ensure that `value` consists of binary values and that the num
/// representation thereof is smaller than or equal to `lower_bound`.
pub fn upper_bound_check_u64<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    upper_bound: u64,
    value: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    assert_eq!(value.len(), 64);
    let mut upper_bound_bits = vec![];
    let mut first_one = None;
    for i in (0..64).rev() {
        let bit = upper_bound >> i & 1;
        if first_one != None {
            upper_bound_bits.push(bit);
        } else if bit == 1 {
            upper_bound_bits.push(bit);
            first_one = Some(63 - i);
        }
    }
    // arrays are sorted with most significant bit first and least significant bit last
    let upper_bound_bits = upper_bound_bits;
    let (leading_bits, value_bits) =
        value.split_at(first_one.expect("There should be a first '1'."));

    // set leading value bits to zero
    for (i, leading_bit) in leading_bits.iter().enumerate() {
        cs.enforce(
            || format!("Zero constrain leading bit {}", i),
            |lc| lc + leading_bit.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );
    }

    // actual range check
    // --> determine Pi_i for i in range [n-1,t+1], where t is the number of trailing one's in c.
    let mut t = 0;
    for (i, &b) in upper_bound_bits.iter().rev().enumerate() {
        if b == 0 {
            t = i;
            break;
        }
    }
    let mut pis = vec![value_bits[0].clone()];
    for (i, (&c, a)) in upper_bound_bits
        .iter()
        .zip(value_bits.iter())
        .rev()
        .skip(t + 1)
        .rev()
        .skip(1)
        .enumerate()
    {
        let pi_prev = pis.last().expect("This vector is not empty.");
        let pi_new = AllocatedNum::alloc(cs.namespace(|| format!("pi_(n-{})", i + 2)), || {
            if c == 0 {
                pi_prev.get_value().get().map(|&pi| pi)
            } else {
                let mut pi_prev = *pi_prev.get_value().get()?;
                a.get_value().get().map(|a| {
                    pi_prev.mul_assign(a);
                    pi_prev
                })
            }
        })?;
        cs.enforce(
            || format!("pi_(n-{}) constraint", i + 2),
            |lc| lc + pi_prev.get_variable(),
            |lc| {
                if c == 0 {
                    lc + CS::one()
                } else {
                    lc + a.get_variable()
                }
            },
            |lc| lc + pi_new.get_variable(),
        );
        pis.push(pi_new);
    }

    // --> constrain value bits
    for (i, (&c, a)) in upper_bound_bits.iter().zip(value_bits.iter()).enumerate() {
        if c == 0 {
            cs.enforce(
                || format!("c=0 constraint for bit n-{}", i + 1),
                |lc| lc + CS::one() - pis[i - 1].get_variable() - a.get_variable(),
                |lc| lc + a.get_variable(),
                |lc| lc,
            );
        } else {
            cs.enforce(
                || format!("c=1 constraint for bit n-{}", i + 1),
                |lc| lc + a.get_variable(),
                |lc| lc + CS::one() - a.get_variable(),
                |lc| lc,
            );
        }
    }

    Ok(())
}

/// Enforce the constraints that ensure that `lower` consists of binary values and that the num
/// representation thereof is smaller than or equal to `upper`.
pub fn comparison<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    lower: &[AllocatedNum<Scalar>],
    upper: &[Boolean],
) -> Result<(), SynthesisError> {
    assert_eq!(lower.len(), upper.len());
    let mut pis = vec![CS::one()];
    let mut pi_values = vec![Some(Scalar::one())];
    for (i, (l, u)) in lower
        .iter()
        .zip(upper.iter())
        .rev()
        .skip(1)
        .rev()
        .enumerate()
    {
        let pi_prev = pis.last().expect("This vector is not empty.");
        let pi_prev_value = *pi_values.last().expect("This vector is not empty.");
        let pi_helper = AllocatedNum::alloc(
            cs.namespace(|| format!("pi_(n-{}) helper bit", i + 1)),
            || {
                if !(*u.get_value().get()?) {
                    Ok(Scalar::one())
                } else {
                    l.get_value().get().map(|&l| l)
                }
            },
        )?;
        cs.enforce(
            || format!("pi_(n-{}) helper bit constraint", i + 1),
            |lc| lc + &u.lc(CS::one(), Scalar::one()),
            |lc| lc + CS::one() - l.get_variable(),
            |lc| lc + CS::one() - pi_helper.get_variable(),
        );
        let pi_new = AllocatedNum::alloc(cs.namespace(|| format!("pi_(n-{})", i + 1)), || {
            if !(*u.get_value().get()?) {
                pi_prev_value.get().map(|&x| x)
            } else {
                let mut pi_prev = *pi_prev_value.get()?;
                l.get_value().get().map(|l| {
                    pi_prev.mul_assign(l);
                    pi_prev
                })
            }
        })?;
        cs.enforce(
            || format!("pi_(n-{}) constraints", i + 1),
            |lc| lc + *pi_prev,
            |lc| lc + pi_helper.get_variable(),
            |lc| lc + pi_new.get_variable(),
        );
        pis.push(pi_new.get_variable());
        pi_values.push(pi_new.get_value());
    }

    // --> constrain lower bits
    for (i, (l, u)) in lower.iter().zip(upper.iter()).enumerate() {
        let effective_pi = AllocatedNum::alloc(
            cs.namespace(|| format!("effective pi for constraint {}", i)),
            || {
                if *u.get_value().get()? {
                    Ok(Scalar::zero())
                } else {
                    pi_values[i].get().map(|&pi| pi)
                }
            },
        )?;
        cs.enforce(
            || format!("effective pi for constraint {} constraint", i),
            |lc| lc + pis[i],
            |lc| lc + CS::one() - &u.lc(CS::one(), Scalar::one()),
            |lc| lc + effective_pi.get_variable(),
        );
        cs.enforce(
            || format!("constrain lower bit n-{}", i + 1),
            |lc| lc + l.get_variable(),
            |lc| lc + CS::one() - effective_pi.get_variable() - l.get_variable(),
            |lc| lc,
        );
    }

    Ok(())
}

/// Take a `Num` that should be input, if the conditional value equals 1. If the selection value
/// equals 0 , the input is set to one (since it does not lie in this Jubjub curve).
pub fn conditional_inputise<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    num: &AllocatedNum<Scalar>,
    conditional_bit: &AllocatedBit,
) -> Result<(), SynthesisError> {
    let input = cs.alloc_input(
        || "input",
        || match conditional_bit.get_value().get()? {
            true => num.get_value().get().map(|x| *x),
            false => Ok(Scalar::one()),
        },
    )?;

    cs.enforce(
        || "selection constraint",
        |lc| lc + num.get_variable() - CS::one(),
        |lc| lc + conditional_bit.get_variable(),
        |lc| lc + input - CS::one(),
    );

    Ok(())
}

/// Take a sequence of booleans and expose them as compact public inputs, if the conditional value
/// equals 1. If the conditional value equals 0, the public inputs are set to 0.
pub fn conditional_pack_into_inputs<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bits: &[Boolean],
    conditional_bit: &AllocatedBit,
) -> Result<(), SynthesisError> {
    for (i, bits) in bits.chunks(Scalar::CAPACITY as usize).enumerate() {
        // Note: we counter-act the reverse in num_from_bits.
        let num = num_from_bits::<Scalar, CS>(&bits.iter().rev().cloned().collect::<Vec<_>>());
        let input = cs.alloc_input(
            || format!("input {}", i),
            || match conditional_bit.get_value() {
                Some(true) => Ok(*num.get_value().get()?),
                Some(false) => Ok(Scalar::zero()),
                None => Err(SynthesisError::AssignmentMissing),
            },
        )?;
        cs.enforce(
            || format!("conditional constraint {}", i),
            |_| num.lc(Scalar::one()),
            |lc| lc + conditional_bit.get_variable(),
            |lc| lc + input,
        );
    }
    Ok(())
}

/// Take a `Num` that should be input, if the selection value equals 1. If the selection value
/// equals 0, the input is set to the alternative `Num`.
pub fn selection_inputise<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    num: &AllocatedNum<Scalar>,
    alt_num: &AllocatedNum<Scalar>,
    selection_bit: &AllocatedBit,
) -> Result<(), SynthesisError> {
    let input = cs.alloc_input(
        || "input",
        || match selection_bit.get_value().get()? {
            true => num.get_value().get().map(|x| *x),
            false => alt_num.get_value().get().map(|x| *x),
        },
    )?;

    cs.enforce(
        || "selection constraint",
        |lc| lc + num.get_variable() - alt_num.get_variable(),
        |lc| lc + selection_bit.get_variable(),
        |lc| lc + input - alt_num.get_variable(),
    );

    Ok(())
}
