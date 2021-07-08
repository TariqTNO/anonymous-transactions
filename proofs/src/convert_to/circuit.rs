//! Convert to anonymous currency circuit implementation

use bellman::gadgets::boolean::{field_into_boolean_vec_le, Boolean};
use bellman::{Circuit, ConstraintSystem, SynthesisError};

use primitives::definitions::Note;

use crate::commitments::comm_note;
use crate::helper_functions::{witness_u256, witness_u64};

/// Auxiliary variables for the ConvertTo circuit
pub struct ConvertTo<'a> {
    pub note_new: Option<&'a Note>,
}

impl<'a> Circuit<bls12_381::Scalar> for ConvertTo<'a> {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Transform and witness auxiliary variables to desired format
        let s_note_new = field_into_boolean_vec_le(
            cs.namespace(|| "s_note_new"),
            self.note_new.map(|note_new| note_new.s_note),
        )?;
        let pk_addr_new = witness_u256(
            cs.namespace(|| "pk_addr_new"),
            self.note_new.map(|note_new| note_new.pk_addr.as_ref()),
        )?;
        let v_note_new = witness_u64(
            cs.namespace(|| "v_note_new"),
            self.note_new.map(|note_new| note_new.v_note.as_ref()),
        )?;
        let t_delta = vec![Boolean::Constant(false); 64];

        // Compute note commitment
        let cm_note_new = comm_note(
            cs.namespace(|| "cm_note_new computation"),
            &s_note_new,
            &pk_addr_new,
            &v_note_new,
            &t_delta,
        )?;

        // Expose public input
        cm_note_new.inputize(cs.namespace(|| "cm_note_new"))
    }
}

#[cfg(test)]
mod test {
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::Circuit;
    use rand::thread_rng;

    use primitives::definitions::Note;

    use crate::convert_to::circuit::ConvertTo;

    #[test]
    /// Test correctness of the circuit and display basic statistics.
    fn test_circuit() {
        // Initialise test constraint system
        let mut cs = TestConstraintSystem::new();
        let mut rng = thread_rng();

        // Construct a new note and compute the commitment to it.
        let note_new = Note::generate_random(&mut rng);
        let cm_note_new = note_new.comm_note();

        // Synthesize circuit
        let c_to = ConvertTo {
            note_new: Some(&note_new),
        };
        c_to.synthesize(&mut cs).unwrap();
        if let Some(statement) = cs.which_is_unsatisfied() {
            println!("Statement '{}' is unsatisfied.", statement);
        }
        assert!(cs.is_satisfied());

        // Describe circuit
        println!("Number of constraints: {}", cs.num_constraints());
        println!("Number of inputs: {}", cs.num_inputs());

        // Verify the correctness of the circuit against expected public inputs
        let result = cs.verify(&[cm_note_new]);
        println!("Verification result: {}", result);
        assert!(result);
    }
}
