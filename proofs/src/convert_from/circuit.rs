//! Convert from anonymous currency circuit implementation.

use bellman::gadgets::boolean::{field_into_boolean_vec_le, Boolean};
use bellman::gadgets::multipack::pack_into_inputs;
use bellman::{Circuit, ConstraintSystem, SynthesisError};

use primitives::definitions::{Credentials, MerkleWitness, Note};

use crate::commitments::comm_note;
use crate::helper_functions::{witness_u256, witness_u64};
use crate::merkle_trees::merkle_rt_note;
use crate::prfs::{prf_addr, prf_eta};

/// Auxiliary variables for the ConvertFrom circuit.
pub struct ConvertFrom<'a> {
    pub cred: Option<&'a Credentials>,
    pub note_old: Option<&'a Note>,
    pub note_merkle_witness: Option<&'a MerkleWitness>,
}

impl<'a> Circuit<bls12_381::Scalar> for ConvertFrom<'a> {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Transform and witness auxiliary variables (except for note_merkle_witness) to desired format.
        let sk_addr = witness_u256(
            cs.namespace(|| "sk_addr"),
            self.cred.map(|cred| cred.sk_addr.as_ref()),
        )?;
        let v_note_old = witness_u64(
            cs.namespace(|| "v_note_old"),
            self.note_old.map(|note_old| note_old.v_note.as_ref()),
        )?;
        let s_note_old = field_into_boolean_vec_le(
            cs.namespace(|| "s_note_old"),
            self.note_old.map(|note_old| note_old.s_note),
        )?;
        let t_delta_old = vec![Boolean::Constant(false); 64];
        let t_note_old = witness_u64(
            cs.namespace(|| "t_note_old"),
            self.note_old.map(|note_old| note_old.t_note.0.as_ref()),
        )?;

        // Compute public address key.
        let pk_addr = prf_addr(cs.namespace(|| "pk_addr computation"), &sk_addr)?;

        // Compute old note commitment.
        let cm_note_old = comm_note(
            cs.namespace(|| "cm_note_old computation"),
            &s_note_old,
            &pk_addr,
            &v_note_old,
            &t_delta_old,
        )?;

        // Compute Note Merkle root and witness note_merkle_witness.
        let (rt_note, pos_note) = merkle_rt_note(
            cs.namespace(|| "rt_note computation"),
            &cm_note_old,
            &t_note_old,
            self.note_merkle_witness,
        )?;

        // Compute nullifier.
        let eta = prf_eta(cs.namespace(|| "eta computation"), &sk_addr, &pos_note)?;

        // Pack boolean public inputs and expose all public inputs.
        let mut public_inputs = vec![];
        rt_note.inputize(cs.namespace(|| "rt_note"))?;
        public_inputs.extend(eta);
        public_inputs.extend(pk_addr);
        pack_into_inputs(cs.namespace(|| "pack inputs"), &public_inputs)
    }
}

#[cfg(test)]
mod test {
    use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::Circuit;
    use rand::{thread_rng, Rng};

    use primitives::definitions::{Credentials, Note};
    use primitives::merkle_trees::{IncrementalMerkleWitness, MerkleTree};

    use crate::convert_from::circuit::ConvertFrom;

    #[test]
    /// Test correctness of the circuit and display basic statistics.
    fn test_circuit() {
        // Initialise test constraint system.
        let mut cs = TestConstraintSystem::new();
        let mut rng = thread_rng();

        // Construct Note Merkle tree.
        let mut mt_note = MerkleTree::new_note();

        // Initialise the note commitment tree with a random amount->[5;105) of random commitments.
        mt_note
            .append_random_commitment_range(&mut rng, 5, 105)
            .expect("Tree should not be full.");

        // Construct random credentials and obtain pk_addr.
        let cred = Credentials::generate_random(&mut rng);
        let pk_addr = cred.pk_addr;

        // Construct random note, and compute the commitment to it.
        let note_old = Note::generate_random_from_pk(cred.pk_addr, &mut rng);
        let cm_note_old = note_old.comm_note();

        // Add commitment to Note Merkle tree and construct an incremental witness for it.
        mt_note
            .append_note_commitment(cm_note_old, &note_old.t_note)
            .expect("Tree should not be full.");
        let mut incremental_note_witness = IncrementalMerkleWitness::from_tree(&mt_note);

        // Add a random amount->[5;105) of random commitments to Note Merkle tree and update the
        // incremental witness accordingly.
        for _ in 0..rng.gen_range(5..105) {
            let node = mt_note
                .append_random_commitment(&mut rng)
                .expect("Tree should not be full.");
            incremental_note_witness
                .append(node)
                .expect("Tree should not be full.");
        }

        // Compute witness to the note in and root of the current state of the tree.
        let note_merkle_witness = incremental_note_witness.witness();
        let rt_note = incremental_note_witness.root_value();
        assert_eq!(rt_note, mt_note.root_value());

        // Compute the note nullifier eta.
        let eta = cred.prf_eta(&note_merkle_witness);

        // Synthesize circuit.
        let c_from = ConvertFrom {
            cred: Some(&cred),
            note_old: Some(&note_old),
            note_merkle_witness: Some(&note_merkle_witness),
        };
        c_from.synthesize(&mut cs).unwrap();
        if let Some(statement) = cs.which_is_unsatisfied() {
            println!("Statement '{}' is unsatisfied.", statement);
        }
        assert!(cs.is_satisfied());

        // Describe circuit.
        println!("Number of constraints: {}.", cs.num_constraints());
        println!("Number of inputs: {}.", cs.num_inputs());

        // Verify the correctness of the circuit against expected public inputs.
        let mut packed_public_inputs = vec![rt_note];

        let mut expected_public_inputs = vec![];
        expected_public_inputs.extend(&eta);
        expected_public_inputs.extend(&pk_addr);
        packed_public_inputs.extend(&compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
            &expected_public_inputs,
        )));
        let result = cs.verify(&packed_public_inputs);
        println!("Verification result: {}.", result);
        assert!(result);
    }
}
