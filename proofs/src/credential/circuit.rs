//! Credential circuit implementation

use bellman::gadgets::boolean::field_into_boolean_vec_le;
use bellman::gadgets::multipack::pack_into_inputs;
use bellman::{Circuit, ConstraintSystem, SynthesisError};

use primitives::definitions::Credentials;

use crate::commitments::comm_cred;
use crate::helper_functions::witness_u256;
use crate::prfs::prf_addr;

/// Auxiliary variables for the credential circuit
pub struct Credential<'a> {
    pub cred: Option<&'a Credentials>,
}

impl<'a> Circuit<bls12_381::Scalar> for Credential<'a> {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Transform and witness auxiliary variables to desired format
        let sk_addr = witness_u256(
            cs.namespace(|| "sk_addr"),
            self.cred.map(|cred| cred.sk_addr.as_ref()),
        )?;
        let s_cred = field_into_boolean_vec_le(
            cs.namespace(|| "s_cred"),
            self.cred.map(|cred| cred.s_cred),
        )?;

        // Compute public address key
        let pk_addr = prf_addr(cs.namespace(|| "pk_addr computation"), &sk_addr)?;

        // Compute credential commitment
        let cm_cred = comm_cred(
            cs.namespace(|| "cm_cred computation"),
            &s_cred,
            &pk_addr,
            &sk_addr,
        )?;
        // Pack boolean public inputs, and expose all public inputs.
        cm_cred.inputize(cs.namespace(|| "cm_cred"))?;
        pack_into_inputs(cs.namespace(|| "pack inputs"), &pk_addr)
    }
}

#[cfg(test)]
mod test {
    use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::Circuit;
    use rand::thread_rng;

    use primitives::definitions::Credentials;

    use crate::credential::circuit::Credential;

    #[test]
    /// Test correctness of the circuit and display basic statistics.
    fn test_circuit() {
        // Initialise test constraint system.
        let mut cs = TestConstraintSystem::new();
        let mut rng = thread_rng();

        // Construct credentials, get pk_addr, and compute credential commitment.
        let credentials = Credentials::generate_random(&mut rng);
        let pk_addr = credentials.pk_addr;
        let cm_cred = credentials.comm_cred();

        // Synthesize circuit
        let cred = Credential {
            cred: Some(&credentials),
        };
        cred.synthesize(&mut cs).unwrap();
        if let Some(statement) = cs.which_is_unsatisfied() {
            println!("Statement '{}' is unsatisfied.", statement);
        }
        assert!(cs.is_satisfied());

        //Describe circuit
        println!("Number of constraints: {}", cs.num_constraints());
        println!("Number of inputs: {}", cs.num_inputs());

        //Verify the correctness of the circuit against expected public inputs
        let mut packed_public_inputs = vec![cm_cred];
        packed_public_inputs.extend(compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
            &pk_addr,
        )));
        let result = cs.verify(&packed_public_inputs);
        println!("Verification result: {}", result);
        assert!(result);
    }
}
