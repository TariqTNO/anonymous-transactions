//! Transfer circuit implementation.

use std::cmp::max;

use bellman::gadgets::boolean::{field_into_boolean_vec_le, AllocatedBit};
use bellman::gadgets::multipack::pack_into_inputs;
use bellman::gadgets::num::AllocatedNum;
use bellman::gadgets::Assignment;
use bellman::{Circuit, ConstraintSystem, SynthesisError};

use primitives::constants::{SPEND_LIMIT, TIME_LIMIT};
use primitives::definitions::{
    Credentials, Memory, MerkleRoot, MerkleWitness, Note, SignatureKeyHash,
};
use primitives::serialise::{u64_array_to_u8_vector, u8_array_to_u64};

use crate::commitments::{comm_cred, comm_mem, comm_note};
use crate::helper_functions::{
    comparison, conditional_inputise, conditional_pack_into_inputs, lc_from_allocated_num_bits,
    num_from_bits, selection_inputise, strict_lower_bound_check_u64, upper_bound_check_u64,
    witness_u256, witness_u64,
};
use crate::merkle_trees::{merkle_rt_cred, merkle_rt_mem, merkle_rt_note};
use crate::prfs::{prf_eta, prf_kappa, prf_mu};
use crate::saver::conditional_saver_inputise;

/// Auxiliary variables (and b_note, k) for the Transfer circuit.
pub struct Transfer<'a> {
    pub cred: Option<&'a Credentials>,
    pub note_old: Option<&'a Note>,
    pub mem_old: Option<&'a Memory>,
    pub mem_ceil: Option<&'a Memory>,
    pub credential_merkle_witness: Option<&'a MerkleWitness>,
    pub note_merkle_witness: Option<&'a MerkleWitness>,
    pub memory_merkle_witness: Option<&'a MerkleWitness>,
    pub memory_ceil_merkle_witness: Option<&'a MerkleWitness>,
    pub rt_mem_pub: Option<&'a MerkleRoot>,
    pub note_new: Option<&'a Note>,
    pub mem_new: Option<&'a Memory>,
    pub b_note: Option<bool>,
    pub b_mem: Option<bool>,
    pub b_saver: Option<bool>,
    pub k: Option<&'a SignatureKeyHash>,
}

impl<'a> Circuit<bls12_381::Scalar> for Transfer<'a> {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Transform and witness auxiliary variables and k (but not merkle_witnesses and booleans)
        // --> cred
        let sk_addr = witness_u256(
            cs.namespace(|| "sk_addr"),
            self.cred.map(|cred| cred.sk_addr.as_ref()),
        )?;
        let pk_addr = witness_u256(
            cs.namespace(|| "pk_addr"),
            self.cred.map(|cred| cred.pk_addr.as_ref()),
        )?;
        let s_cred = field_into_boolean_vec_le(
            cs.namespace(|| "s_cred"),
            self.cred.map(|cred| cred.s_cred),
        )?;

        // --> note_old
        let v_note_old = witness_u64(
            cs.namespace(|| "v_note_old"),
            self.note_old.map(|note_old| note_old.v_note.as_ref()),
        )?;
        let s_note_old = field_into_boolean_vec_le(
            cs.namespace(|| "s_note_old"),
            self.note_old.map(|note_old| note_old.s_note),
        )?;
        let t_delta_old = witness_u64(
            cs.namespace(|| "t_delta_old"),
            self.note_old.map(|note_old| note_old.t_delta.as_ref()),
        )?;
        let t_note_old = witness_u64(
            cs.namespace(|| "t_note_old"),
            self.note_old.map(|note_old| note_old.t_note.0.as_ref()),
        )?;

        // --> mem_old
        let v_mem_old = witness_u64(
            cs.namespace(|| "v_mem_old"),
            self.mem_old.map(|mem_old| mem_old.v_mem.as_ref()),
        )?;
        let s_mem_old = field_into_boolean_vec_le(
            cs.namespace(|| "s_mem_old"),
            self.mem_old.map(|mem_old| mem_old.s_mem),
        )?;
        let c_mem_old = witness_u64(
            cs.namespace(|| "c_mem_old"),
            self.mem_old.map(|mem_old| mem_old.c_mem.as_ref()),
        )?;
        let t_mem_old = witness_u64(
            cs.namespace(|| "t_mem_old"),
            self.mem_old.map(|mem_old| mem_old.t_mem.0.as_ref()),
        )?;

        // --> mem_ceil
        let v_mem_ceil = witness_u64(
            cs.namespace(|| "v_mem_ceil"),
            self.mem_ceil.map(|mem_ceil| mem_ceil.v_mem.as_ref()),
        )?;
        let s_mem_ceil = field_into_boolean_vec_le(
            cs.namespace(|| "s_mem_ceil"),
            self.mem_ceil.map(|mem_ceil| mem_ceil.s_mem),
        )?;
        let c_mem_ceil = witness_u64(
            cs.namespace(|| "c_mem_ceil"),
            self.mem_ceil.map(|mem_ceil| mem_ceil.c_mem.as_ref()),
        )?;
        let t_mem_ceil = witness_u64(
            cs.namespace(|| "t_mem_ceil"),
            self.mem_ceil.map(|mem_ceil| mem_ceil.t_mem.0.as_ref()),
        )?;

        // --> note_new
        let v_note_new = witness_u64(
            cs.namespace(|| "v_note_new"),
            self.note_new.map(|note_new| note_new.v_note.as_ref()),
        )?;
        let s_note_new = field_into_boolean_vec_le(
            cs.namespace(|| "s_note_new"),
            self.note_new.map(|note_new| note_new.s_note),
        )?;
        let pk_addr_new = witness_u256(
            cs.namespace(|| "pk_addr_new"),
            self.note_new.map(|note_new| note_new.pk_addr.as_ref()),
        )?;
        let t_delta_new = witness_u64(
            cs.namespace(|| "t_delta_new"),
            self.note_new.map(|note_new| note_new.t_delta.as_ref()),
        )?;

        // --> mem_new
        let v_mem_new = witness_u64(
            cs.namespace(|| "v_mem_new"),
            self.mem_new.map(|mem_new| mem_new.v_mem.as_ref()),
        )?;
        let s_mem_new = field_into_boolean_vec_le(
            cs.namespace(|| "s_mem_new"),
            self.mem_new.map(|mem_new| mem_new.s_mem),
        )?;
        let c_mem_new = witness_u64(
            cs.namespace(|| "c_mem_new"),
            self.mem_new.map(|mem_new| mem_new.c_mem.as_ref()),
        )?;
        let t_new = witness_u64(
            cs.namespace(|| "t_new"),
            self.mem_new
                .map(|mem_new| {
                    self.note_new.map(|note_new| {
                        u64_array_to_u8_vector(&[max(
                            u8_array_to_u64(&mem_new.t_mem.0),
                            u8_array_to_u64(&note_new.t_note.0),
                        )])
                    })
                })
                .flatten()
                .as_deref(),
        )?;

        // --> signature
        let k = witness_u256(cs.namespace(|| "k"), self.k.map(|k| k.as_ref()))?;

        // Bits.
        let b_note = AllocatedBit::alloc(cs.namespace(|| "b_note"), self.b_note)?;
        let b_mem = AllocatedBit::alloc(cs.namespace(|| "b_mem"), self.b_mem)?;
        let b_saver = AllocatedBit::alloc(cs.namespace(|| "b_saver"), self.b_saver)?;

        // Allocated SAVER inputs conditionally on b_saver.
        // This needs to be done before any other input is assigned.
        // --> saver_pk_sndr = pk_addr
        conditional_saver_inputise(cs.namespace(|| "saver_pk_sndr"), &pk_addr, &b_saver)?;

        // --> saver_pk_rcvr = pk_addr_new
        conditional_saver_inputise(cs.namespace(|| "saver_pk_rcvr"), &pk_addr_new, &b_saver)?;

        // --> saver_v_note = v_note_new
        conditional_saver_inputise(cs.namespace(|| "saver_v_note"), &v_note_new, &b_saver)?;

        // Credentials
        // --> Compute credential commitment
        let cm_cred = comm_cred(
            cs.namespace(|| "cm_cred computation"),
            &s_cred,
            &pk_addr,
            &sk_addr,
        )?;
        // --> Compute Credential Merkle root and witness credential_merkle_witness
        let (rt_cred, _) = merkle_rt_cred(
            cs.namespace(|| "rt_cred computation"),
            &cm_cred,
            self.credential_merkle_witness,
        )?;

        // Old Note
        // --> Compute note_old commitment.
        let cm_note_old = comm_note(
            cs.namespace(|| "cm_note_old"),
            &s_note_old,
            &pk_addr,
            &v_note_old,
            &t_delta_old,
        )?;

        // --> Compute Note Merkle root and witness note_merkle_witness.
        let (rt_note, pos_note) = merkle_rt_note(
            cs.namespace(|| "rt_note computation"),
            &cm_note_old,
            &t_note_old,
            self.note_merkle_witness,
        )?;

        // --> Compute nullifier.
        let eta = prf_eta(cs.namespace(|| "eta computation"), &sk_addr, &pos_note)?;

        // Old Memory
        // --> Compute mem_old commitment.
        let cm_mem_old = comm_mem(
            cs.namespace(|| "cm_mem_old"),
            &s_mem_old,
            &pk_addr,
            &v_mem_old,
            &c_mem_old,
        )?;

        // --> Compute Memory Merkle root and witness memory_merkle_witness.
        let (rt_mem, pos_mem) = merkle_rt_mem(
            cs.namespace(|| "rt_mem computation"),
            &cm_mem_old,
            &t_mem_old,
            self.memory_merkle_witness,
        )?;

        // --> Compute nullifier.
        let mu = prf_mu(
            cs.namespace(|| "mu computation"),
            &sk_addr,
            &pos_mem,
            &b_mem,
        )?;

        // Ceil Memory
        // --> Compute mem_ceil commitment.
        let cm_mem_ceil = comm_mem(
            cs.namespace(|| "cm_mem_ceil"),
            &s_mem_ceil,
            &pk_addr,
            &v_mem_ceil,
            &c_mem_ceil,
        )?;

        // --> Compute Memory Merkle root and witness memory_ceil_merkle_witness.
        let (rt_mem_ceil, _) = merkle_rt_mem(
            cs.namespace(|| "rt_mem_ceil computation"),
            &cm_mem_ceil,
            &t_mem_ceil,
            self.memory_ceil_merkle_witness,
        )?;

        // --> Verify equality of both internal Memory Merkle roots, if c_mem_ceil is non-zero
        let c_mem_ceil_num = num_from_bits::<_, CS>(&c_mem_ceil);
        cs.enforce(
            || "rt_mem = rt_mem_ceil",
            |lc| lc + &c_mem_ceil_num.lc(bls12_381::Scalar::one()),
            |lc| lc + rt_mem.get_variable() - rt_mem_ceil.get_variable(),
            |lc| lc,
        );

        // Compute new note commitment.
        let cm_note_new = comm_note(
            cs.namespace(|| "cm_note_new computation"),
            &s_note_new,
            &pk_addr_new,
            &v_note_new,
            &t_delta_new,
        )?;

        // Compute new memory commitment.
        let cm_mem_new = comm_mem(
            cs.namespace(|| "cm_mem_new computation"),
            &s_mem_new,
            &pk_addr,
            &v_mem_new,
            &c_mem_new,
        )?;

        // Signature link kappa computation.
        let kappa = prf_kappa(cs.namespace(|| "kappa computation"), &sk_addr, &k)?;

        // Value addition check.
        let v_note_old_num = num_from_bits::<_, CS>(&v_note_old);
        let v_mem_old_num = num_from_bits::<_, CS>(&v_mem_old);
        let v_note_new_num = num_from_bits::<_, CS>(&v_note_new);
        let v_mem_new_num = num_from_bits::<_, CS>(&v_mem_new);

        let total_input_value_lc = v_note_old_num.lc(bls12_381::Scalar::one())
            + &v_mem_old_num.lc(bls12_381::Scalar::one());
        let total_output_value_lc = v_note_new_num.lc(bls12_381::Scalar::one())
            + &v_mem_new_num.lc(bls12_381::Scalar::one());

        cs.enforce(
            || "balance constraint",
            |_| total_input_value_lc,
            |lc| lc + CS::one(),
            |_| total_output_value_lc,
        );

        // Total value addition check
        let c_mem_old_num = num_from_bits::<_, CS>(&c_mem_old);
        let c_mem_new_num = num_from_bits::<_, CS>(&c_mem_new);

        cs.enforce(
            || "c_new computation",
            |_| v_note_new_num.lc(bls12_381::Scalar::one()),
            |lc| lc + CS::one() - b_saver.get_variable(),
            |_| {
                c_mem_new_num.lc(bls12_381::Scalar::one())
                    - &c_mem_old_num.lc(bls12_381::Scalar::one())
            },
        );

        // Verify that transaction is not empty.
        let total_note_value_lc = v_note_old_num.lc(bls12_381::Scalar::one())
            + &v_note_new_num.lc(bls12_381::Scalar::one());

        let total_note_value_inv =
            AllocatedNum::alloc(cs.namespace(|| "total(v_note) inverse"), || {
                Ok(
                    (v_note_old_num.get_value().get()? + v_note_new_num.get_value().get()?)
                        .invert()
                        .unwrap_or(bls12_381::Scalar::zero()),
                )
            })?;

        cs.enforce(
            || "non-empty transaction constraint",
            |_| total_note_value_lc,
            |lc| lc + total_note_value_inv.get_variable(),
            |lc| lc + CS::one(),
        );

        // Verify that ceiling memory cell is old enough
        // --> introduce t_mem_diff and verify that t_mem_ceil + t_mem_diff = t_mem_new
        let t_mem_diff = self
            .mem_new
            .map(|mem_new| {
                self.mem_ceil.map(|mem_ceil| {
                    u8_array_to_u64(&mem_new.t_mem.0) - u8_array_to_u64(&mem_ceil.t_mem.0)
                })
            })
            .flatten();
        let t_mem_diff = (0..64)
            .rev()
            .map(|x| {
                AllocatedNum::alloc(
                    cs.namespace(|| format!("t_mem_diff bit {}", 64 - x)),
                    || {
                        let b = *t_mem_diff.get()? >> x & 1;
                        if b == 1 {
                            Ok(bls12_381::Scalar::one())
                        } else {
                            Ok(bls12_381::Scalar::zero())
                        }
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let t_mem_ceil_num = num_from_bits::<_, CS>(&t_mem_ceil);
        let t_mem_diff_lc = lc_from_allocated_num_bits::<_, CS>(&t_mem_diff);
        let t_new_num = num_from_bits::<_, CS>(&t_new);
        cs.enforce(
            || "t_mem_ceil + t_mem_diff = t_new constraints",
            |_| t_mem_ceil_num.lc(bls12_381::Scalar::one()) + &t_mem_diff_lc,
            |lc| lc + CS::one(),
            |_| t_new_num.lc(bls12_381::Scalar::one()),
        );

        // --> Verify that t_mem_diff > T
        strict_lower_bound_check_u64(cs.namespace(|| "t_mem_diff > T"), TIME_LIMIT, &t_mem_diff)?;

        // Verify that the spend limit is not surpassed
        // --> introduce c_diff and verify that c_mem_ceil + c_mem_diff = c_mem_new if b_saver=0, else c_mem_diff = 0
        let c_mem_diff = self
            .mem_new
            .map(|mem_new| {
                self.mem_ceil.map(|mem_ceil| {
                    u8_array_to_u64(&mem_new.c_mem) - u8_array_to_u64(&mem_ceil.c_mem)
                })
            })
            .flatten();
        let c_mem_diff = (0..64)
            .rev()
            .map(|x| {
                AllocatedNum::alloc(cs.namespace(|| format!("c_diff bit {}", 64 - x)), || {
                    if *b_saver.get_value().get()? {
                        Ok(bls12_381::Scalar::zero())
                    } else {
                        let b = *c_mem_diff.get()? >> x & 1;
                        if b == 1 {
                            Ok(bls12_381::Scalar::one())
                        } else {
                            Ok(bls12_381::Scalar::zero())
                        }
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let c_mem_diff_lc = lc_from_allocated_num_bits::<_, CS>(&c_mem_diff);

        cs.enforce(
            || "c_mem_new - c_mem_ceil = c_mem_diff if b_saver=0, else 0 = c_mem_diff",
            |_| {
                c_mem_new_num.lc(bls12_381::Scalar::one())
                    - &c_mem_ceil_num.lc(bls12_381::Scalar::one())
            },
            |lc| lc + CS::one() - b_saver.get_variable(),
            |_| c_mem_diff_lc,
        );

        // --> Verify that c_mem_diff <= L
        upper_bound_check_u64(cs.namespace(|| "c_mem_diff <= L"), SPEND_LIMIT, &c_mem_diff)?;

        // Verify that note_old is unlocked, i.e. t_note_old + t_delta_old <= t_new
        // --> introduce t_note_sum and verify that t_note_old + t_delta_old = t_note_sum
        let t_note_sum = self.note_old.map(|note_old| {
            u8_array_to_u64(&note_old.t_note.0) + u8_array_to_u64(&note_old.t_delta)
        });
        let t_note_sum = (0..64)
            .rev()
            .map(|x| {
                AllocatedNum::alloc(
                    cs.namespace(|| format!("t_note_sum bit {}", 64 - x)),
                    || {
                        let b = *t_note_sum.get()? >> x & 1;
                        if b == 1 {
                            Ok(bls12_381::Scalar::one())
                        } else {
                            Ok(bls12_381::Scalar::zero())
                        }
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let t_note_old_num = num_from_bits::<_, CS>(&t_note_old);
        let t_note_delta_num = num_from_bits::<_, CS>(&t_delta_old);
        let t_note_sum_lc = lc_from_allocated_num_bits::<_, CS>(&t_note_sum);
        cs.enforce(
            || "t_note_old + t_delta_old = t_note_sum constraints",
            |_| {
                t_note_old_num.lc(bls12_381::Scalar::one())
                    + &t_note_delta_num.lc(bls12_381::Scalar::one())
            },
            |lc| lc + CS::one(),
            |lc| lc + &t_note_sum_lc,
        );

        // --> Verify that t_note_sum <= t_new
        comparison(cs.namespace(|| "t_note_sum <= t_new"), &t_note_sum, &t_new)?;

        // b_note
        // --> Check that v_note_old=0 if b_note = 0.
        cs.enforce(
            || "v_note_old = 0 if b_note=0 constraint",
            |_| v_note_old_num.lc(bls12_381::Scalar::one()),
            |lc| lc + b_note.get_variable(),
            |_| v_note_old_num.lc(bls12_381::Scalar::one()),
        );

        // --> Check that rt_note=0 if b_note = 0.
        conditional_inputise(cs.namespace(|| "rt_note given b_note"), &rt_note, &b_note)?;

        // --> Check that eta=0 if b_note = 0.
        conditional_pack_into_inputs(cs.namespace(|| "eta given b_note"), &eta, &b_note)?;

        // b_mem
        // --> Check that v_mem_old = 0 if b_mem = 0.
        cs.enforce(
            || "v_mem_old=0 if b_mem=0 constraint",
            |_| v_mem_old_num.lc(bls12_381::Scalar::one()),
            |lc| lc + b_mem.get_variable(),
            |_| v_mem_old_num.lc(bls12_381::Scalar::one()),
        );

        // --> Check that c_mem_old = 0 if b_mem = 0.
        cs.enforce(
            || "c_mem_old=0 if b_mem=0 constraint",
            |_| c_mem_old_num.lc(bls12_381::Scalar::one()),
            |lc| lc + b_mem.get_variable(),
            |_| c_mem_old_num.lc(bls12_381::Scalar::one()),
        );

        // --> Check that c_mem_ceil = 0 if b_mem = 0.
        let c_mem_ceil_num = num_from_bits::<_, CS>(&c_mem_ceil);

        cs.enforce(
            || "c_mem_ceil=0 if b_mem=0 constraint",
            |_| c_mem_ceil_num.lc(bls12_381::Scalar::one()),
            |lc| lc + b_mem.get_variable(),
            |_| c_mem_ceil_num.lc(bls12_381::Scalar::one()),
        );

        // --> Check that pos_mem = 0 if b_mem = 0.
        let pos_mem_num = num_from_bits::<_, CS>(&pos_mem);
        cs.enforce(
            || "pos_mem = 0 if b_mem=0 constraint",
            |_| pos_mem_num.lc(bls12_381::Scalar::one()),
            |lc| lc + b_mem.get_variable(),
            |_| pos_mem_num.lc(bls12_381::Scalar::one()),
        );

        // --> Witness the input rt_mem_pub and set rt_mem_pub as input if b_mem=0, otherwise rt_mem
        // is input.
        let rt_mem_pub = AllocatedNum::alloc(cs.namespace(|| "rt_mem_pub"), || {
            self.rt_mem_pub.get().map(|x| **x)
        })?;
        selection_inputise(
            cs.namespace(|| "rt_mem given b_mem"),
            &rt_mem,
            &rt_mem_pub,
            &b_mem,
        )?;

        // Pack boolean public inputs and expose all public inputs
        // (except rt_note, rt_mem and eta, since they have been exposed above).
        rt_cred.inputize(cs.namespace(|| "rt_cred"))?;
        cm_note_new.inputize(cs.namespace(|| "cm_note_new"))?;
        cm_mem_new.inputize(cs.namespace(|| "cm_mem_new"))?;
        let mut public_inputs = vec![];
        public_inputs.extend(mu);
        public_inputs.extend(k);
        public_inputs.extend(kappa);
        public_inputs.extend(t_new);
        pack_into_inputs(cs.namespace(|| "pack inputs"), &public_inputs)
    }
}

#[cfg(test)]
mod test {
    use std::cmp::min;
    use std::convert::TryInto;

    use bellman::gadgets::multipack::{bytes_to_bits, compute_multipacking};
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::Circuit;
    use rand::{thread_rng, Rng};
    use rand_core::OsRng;

    use primitives::constants::SPEND_LIMIT;
    use primitives::definitions::{Credentials, Memory, MerkleRoot, Note, TransactionTime};
    use primitives::merkle_trees::{IncrementalMerkleWitness, MerkleTree};
    use primitives::prfs::prf_kappa;
    use primitives::saver::{decrypt, prepare_verifying_key_saver, verify_decryption};
    use primitives::serialise::u8_array_to_u64;

    use crate::saver::conditional_saver_pack;
    use crate::transfer::circuit::Transfer;
    use crate::transfer::generator::generate_random_parameters;
    use crate::transfer::prover::create_proof;
    use crate::transfer::verifier::verify_proof;

    #[test]
    /// Test correctness of the circuit with a notelock, in the setting with all inputs and display
    /// basic statistics.
    fn test_circuit_with_notelock() {
        // Initialise random values satisfying the balance equation.
        // Initialise random values satisfying the balance equation.
        let mut rng = thread_rng();
        let max_c: u64 = rng.gen_range(0..SPEND_LIMIT + 1);
        let min_c: u64 = rng.gen_range(0..max_c + 1);
        let max_v: u64 = rng.gen();
        let min_v_old: u64 = rng.gen_range(0..max_v + 1);
        let min_v_new: u64 = rng.gen_range(0..min(max_v, SPEND_LIMIT - max_c) + 1);
        let diff_old = max_v - min_v_old;
        let diff_new = max_v - min_v_new;
        let v_note_old = u64_to_u8_array(min_v_old);
        let v_mem_old = u64_to_u8_array(diff_old);
        let c_mem_old = u64_to_u8_array(max_c);
        let v_note_new = u64_to_u8_array(min_v_new);
        let v_mem_new = u64_to_u8_array(diff_new);
        let c_mem_new = u64_to_u8_array(max_c + min_v_new);
        let v_mem_ceil = u64_to_u8_array(rng.gen_range(0..min_c + 1));
        let c_mem_ceil = u64_to_u8_array(min_c);
        generic_test(
            &mut rng, true, true, true, false, true, v_note_old, v_mem_old, c_mem_old, v_note_new,
            v_mem_new, c_mem_new, v_mem_ceil, c_mem_ceil,
        )
    }

    #[test]
    /// Test correctness of the circuit with SAVER, in the setting with all inputs and display
    /// basic statistics.
    fn test_circuit_with_saver() {
        // Initialise random values satisfying the balance equation.
        let mut rng = thread_rng();
        let max_c: u64 = rng.gen_range(0..SPEND_LIMIT + 1);
        let min_c: u64 = rng.gen_range(0..max_c + 1);
        let max_v: u64 = rng.gen();
        let min_v_old: u64 = rng.gen_range(0..max_v + 1);
        let min_v_new: u64 = rng.gen_range(0..min(max_v, SPEND_LIMIT - max_c) + 1);
        let diff_old = max_v - min_v_old;
        let diff_new = max_v - min_v_new;
        let v_note_old = u64_to_u8_array(min_v_old);
        let v_mem_old = u64_to_u8_array(diff_old);
        let c_mem_old = u64_to_u8_array(max_c);
        let v_note_new = u64_to_u8_array(min_v_new);
        let v_mem_new = u64_to_u8_array(diff_new);
        let c_mem_new = u64_to_u8_array(max_c);
        let v_mem_ceil = u64_to_u8_array(rng.gen_range(0..min_c + 1));
        let c_mem_ceil = u64_to_u8_array(min_c);
        generic_test(
            &mut rng, true, true, true, true, false, v_note_old, v_mem_old, c_mem_old, v_note_new,
            v_mem_new, c_mem_new, v_mem_ceil, c_mem_ceil,
        )
    }

    #[test]
    /// Test correctness of the circuit with no previous memory and display basic statistics.
    /// Does not use SAVER.
    fn test_circuit_no_mem() {
        // Initialise random values satisfying the balance equation.
        let mut rng = thread_rng();
        let max_v: u64 = rng.gen();
        let min_v: u64 = rng.gen_range(0..min(max_v, SPEND_LIMIT) + 1);
        let diff = max_v - min_v;
        let v_note_old = u64_to_u8_array(max_v);
        let v_note_new = u64_to_u8_array(min_v);
        let v_mem_new = u64_to_u8_array(diff);
        let c_mem_new = u64_to_u8_array(min_v);
        generic_test(
            &mut rng, true, false, false, false, false, v_note_old, [0; 8], [0; 8], v_note_new,
            v_mem_new, c_mem_new, [0; 8], [0; 8],
        )
    }

    #[test]
    /// Test correctness of the circuit with no previous note and display basic statistics.
    /// Does not use SAVER.
    fn test_circuit_no_note() {
        // Initialise random values satisfying the balance equation.
        let mut rng = thread_rng();
        let max_c: u64 = rng.gen_range(0..SPEND_LIMIT + 1);
        let min_c: u64 = rng.gen_range(0..max_c + 1);
        let max_v: u64 = rng.gen();
        let min_v: u64 = rng.gen_range(0..min(max_v, SPEND_LIMIT - max_c + min_c) + 1);
        let diff = max_v - min_v;
        let v_mem_old = u64_to_u8_array(max_v);
        let c_mem_old = u64_to_u8_array(max_c);
        let v_note_new = u64_to_u8_array(min_v);
        let v_mem_new = u64_to_u8_array(diff);
        let c_mem_new = u64_to_u8_array(max_c + min_v);
        let v_mem_ceil = u64_to_u8_array(rng.gen_range(0..min_c + 1));
        let c_mem_ceil = u64_to_u8_array(min_c);
        generic_test(
            &mut rng, false, true, true, false, false, [0; 8], v_mem_old, c_mem_old, v_note_new,
            v_mem_new, c_mem_new, v_mem_ceil, c_mem_ceil,
        )
    }

    #[test]
    /// Test correctness of the circuit with no old enough ceiling memory cell (but with old memory
    ///  cell) and display basic statistics.
    /// Does not use SAVER.
    fn test_circuit_too_new_ceil() {
        // Initialise random values satisfying the balance equation.
        let mut rng = thread_rng();
        let c_mem: u64 = rng.gen_range(0..SPEND_LIMIT + 1);
        let max_v: u64 = rng.gen();
        let min_v_old: u64 = rng.gen_range(0..max_v + 1);
        let min_v_new: u64 = rng.gen_range(0..min(max_v, SPEND_LIMIT - c_mem) + 1);
        let diff_old = max_v - min_v_old;
        let diff_new = max_v - min_v_new;
        let v_note_old = u64_to_u8_array(min_v_old);
        let v_mem_old = u64_to_u8_array(diff_old);
        let c_mem_old = u64_to_u8_array(c_mem);
        let v_note_new = u64_to_u8_array(min_v_new);
        let v_mem_new = u64_to_u8_array(diff_new);
        let c_mem_new = u64_to_u8_array(c_mem + min_v_new);
        generic_test(
            &mut rng, true, true, false, false, false, v_note_old, v_mem_old, c_mem_old,
            v_note_new, v_mem_new, c_mem_new, [0; 8], [0; 8],
        )
    }

    #[test]
    /// Test correctness of the circuit with a previous note ánd previous memory ánd cel memory
    /// and display basic statistics.
    /// Does not use SAVER.
    fn test_circuit() {
        // Initialise random values satisfying the balance equation.
        let mut rng = thread_rng();
        let max_c: u64 = rng.gen_range(0..SPEND_LIMIT + 1);
        let min_c: u64 = rng.gen_range(0..max_c + 1);
        let max_v: u64 = rng.gen();
        let min_v_old: u64 = rng.gen_range(0..max_v + 1);
        let min_v_new: u64 = rng.gen_range(0..min(max_v, SPEND_LIMIT - max_c) + 1);
        let diff_old = max_v - min_v_old;
        let diff_new = max_v - min_v_new;
        let v_note_old = u64_to_u8_array(min_v_old);
        let v_mem_old = u64_to_u8_array(diff_old);
        let c_mem_old = u64_to_u8_array(max_c);
        let v_note_new = u64_to_u8_array(min_v_new);
        let v_mem_new = u64_to_u8_array(diff_new);
        let c_mem_new = u64_to_u8_array(max_c + min_v_new);
        let v_mem_ceil = u64_to_u8_array(rng.gen_range(0..min_c + 1));
        let c_mem_ceil = u64_to_u8_array(min_c);
        generic_test(
            &mut rng, true, true, true, false, false, v_note_old, v_mem_old, c_mem_old, v_note_new,
            v_mem_new, c_mem_new, v_mem_ceil, c_mem_ceil,
        )
    }

    fn generic_test<R: Rng>(
        rng: &mut R,
        b_note: bool,
        b_mem: bool,
        b_ceil: bool,
        b_saver: bool,
        note_lock: bool,
        v_note_old: [u8; 8],
        v_mem_old: [u8; 8],
        c_mem_old: [u8; 8],
        v_note_new: [u8; 8],
        v_mem_new: [u8; 8],
        c_mem_new: [u8; 8],
        v_mem_ceil: [u8; 8],
        c_mem_ceil: [u8; 8],
    ) {
        // Initialise test constraint system.
        let mut cs = TestConstraintSystem::new();

        // Construct Merkle trees
        let mut mt_cred = MerkleTree::new_cred();
        let mut mt_note = MerkleTree::new_note();
        let mut mt_mem = MerkleTree::new_mem();

        // Initialise the commitment trees with a random amount->[5;105) of random commitments.
        for tree in [&mut mt_cred, &mut mt_note, &mut mt_mem].iter_mut() {
            tree.append_random_commitment_range(rng, 5, 105)
                .expect("Tree should not be full.");
        }

        // Initialise random value for k.
        let k = rng.gen();

        // Construct credentials, old note, old memory and compute their commitments.
        let cred = Credentials::generate_random(rng);
        let cm_cred = cred.comm_cred();
        let (t_delta_old, t_delta_new) = match note_lock {
            true => (
                u64_to_u8_array(rng.gen_range(0..u8_array_to_u64(&TransactionTime::current().0))),
                rng.gen(),
            ),
            false => ([0; 8], [0; 8]),
        };
        let note_old = match b_note {
            true => Note::generate_random_from_pk_v_t_and_t_delta(
                cred.pk_addr,
                v_note_old,
                TransactionTime::before_time_lock(t_delta_old),
                t_delta_old,
                rng,
            ),
            false => Note::empty_from_pk(cred.pk_addr),
        };
        let cm_note_old = note_old.comm_note();
        let mem_old = match b_mem {
            true => {
                Memory::generate_random_from_pk_v_and_c(cred.pk_addr, v_mem_old, c_mem_old, rng)
            }
            false => Memory::empty_from_pk(cred.pk_addr),
        };
        let cm_mem_old = mem_old.comm_mem();
        let mem_ceil = match b_ceil {
            true => Memory::generate_random_from_pk_v_t_and_c(
                cred.pk_addr,
                v_mem_ceil,
                TransactionTime::before_time_limit(),
                c_mem_ceil,
                rng,
            ),
            false => {
                Memory::empty_from_pk_and_t(cred.pk_addr, TransactionTime::before_time_limit())
            }
        };
        let cm_mem_ceil = mem_ceil.comm_mem();

        // Add credentials or old commitments to corresponding trees and construct the corresponding
        // incremental witnesses.
        mt_cred
            .append_credential_commitment(cm_cred)
            .expect("Tree should not be full.");
        let mut incremental_cred_witness = IncrementalMerkleWitness::from_tree(&mt_cred);
        if b_note {
            mt_note
                .append_note_commitment(cm_note_old, &note_old.t_note)
                .expect("Tree should not be full.");
        }
        let mut incremental_note_witness = match b_note {
            true => IncrementalMerkleWitness::from_tree(&mt_note),
            false => {
                let mut mt_note = MerkleTree::new_note();
                mt_note
                    .append_note_commitment(cm_note_old, &note_old.t_note)
                    .expect("Tree should not be full.");
                IncrementalMerkleWitness::from_tree(&mt_note)
            }
        };
        if b_ceil {
            mt_mem
                .append_memory_commitment(cm_mem_ceil, &mem_ceil.t_mem)
                .expect("Tree should not be full.");
        }
        let mut incremental_ceil_witness = match b_ceil {
            true => IncrementalMerkleWitness::from_tree(&mt_mem),
            false => {
                let mut mt_mem = MerkleTree::new_mem();
                mt_mem
                    .append_memory_commitment(cm_mem_ceil, &mem_ceil.t_mem)
                    .expect("Tree should not be full.");
                IncrementalMerkleWitness::from_tree(&mt_mem)
            }
        };
        if b_mem {
            let node = mt_mem
                .append_memory_commitment(cm_mem_old, &mem_old.t_mem)
                .expect("Tree should not be full.");
            incremental_ceil_witness
                .append(node)
                .expect("Tree should not be full.");
        }
        let mut incremental_mem_witness = match b_mem {
            true => IncrementalMerkleWitness::from_tree(&mt_mem),
            false => {
                let mut mt_mem = MerkleTree::new_mem();
                let node = mt_mem
                    .append_memory_commitment(cm_mem_old, &mem_old.t_mem)
                    .expect("Tree should not be full.");
                incremental_ceil_witness
                    .append(node)
                    .expect("Tree should not be full.");
                IncrementalMerkleWitness::from_tree(&mt_mem)
            }
        };

        // Add a random amount->[5;105) of random commitments to the Merkle Trees
        // and update the incremental witnesses accordingly.
        for (tree, incremental_witnesses) in
            [&mut mt_cred, &mut mt_note, &mut mt_mem].iter_mut().zip(
                [
                    vec![&mut incremental_cred_witness],
                    vec![&mut incremental_note_witness],
                    vec![&mut incremental_mem_witness, &mut incremental_ceil_witness],
                ]
                .iter_mut(),
            )
        {
            for _ in 0..rng.gen_range(5..105) {
                let node = tree
                    .append_random_commitment(rng)
                    .expect("Tree should not be full.");
                for incremental_witness in incremental_witnesses.iter_mut() {
                    incremental_witness
                        .append(node)
                        .expect("Tree should not be full.");
                }
            }
        }

        // Compute witnesses to the credential and old commitments.
        // Also compute the Merkle roots to the current states of the corresponding trees.
        let credential_merkle_witness = incremental_cred_witness.witness();
        let note_merkle_witness = incremental_note_witness.witness();
        let memory_merkle_witness = incremental_mem_witness.witness();
        let memory_ceil_merkle_witness = incremental_ceil_witness.witness();
        let rt_cred = incremental_cred_witness.root_value();
        let rt_note = match b_note {
            true => incremental_note_witness.root_value(),
            false => bls12_381::Scalar::one(),
        };
        let rt_mem = match b_mem {
            true => incremental_mem_witness.root_value(),
            false => mt_mem.root_value(),
        };
        assert_eq!(mt_cred.root_value(), rt_cred);
        assert!(!b_note || mt_note.root_value() == rt_note);
        assert!(!b_mem || mt_mem.root_value() == rt_mem);

        // Construct new note and compute its commitment.
        let note_new = Note::generate_random_from_v_and_t_delta(v_note_new, t_delta_new, rng);
        let cm_note_new = note_new.comm_note();

        // Construct new memory and compute its commitment
        let mem_new =
            Memory::generate_random_from_pk_v_and_c(cred.pk_addr, v_mem_new, c_mem_new, rng);
        let cm_mem_new = mem_new.comm_mem();

        // Compute the note and memory nullifiers.
        let eta = match b_note {
            true => cred.prf_eta(&note_merkle_witness),
            false => [0; 32],
        };
        let mu = cred.prf_mu(&memory_merkle_witness, b_mem);

        // Compute the signature link kappa.
        let kappa = prf_kappa(&cred, &k);

        // Synthesize circuit.
        let transfer = Transfer {
            cred: Some(&cred),
            note_old: Some(&note_old),
            mem_old: Some(&mem_old),
            mem_ceil: Some(&mem_ceil),
            credential_merkle_witness: Some(&credential_merkle_witness),
            note_merkle_witness: Some(&note_merkle_witness),
            memory_merkle_witness: Some(&memory_merkle_witness),
            memory_ceil_merkle_witness: Some(&memory_ceil_merkle_witness),
            rt_mem_pub: Some(&rt_mem),
            note_new: Some(&note_new),
            mem_new: Some(&mem_new),
            b_note: Some(b_note),
            b_mem: Some(b_mem),
            b_saver: Some(b_saver),
            k: Some(&k),
        };
        transfer.synthesize(&mut cs).unwrap();
        if let Some(statement) = cs.which_is_unsatisfied() {
            println!("Statement '{}' is unsatisfied.", statement);
        }
        assert!(cs.is_satisfied());

        // Describe circuit.
        println!("Number of constraints: {}.", cs.num_constraints());
        println!("Number of inputs: {}.", cs.num_inputs());

        // Compute the packed public inputs.
        let mut packed_public_inputs: Vec<bls12_381::Scalar> = vec![];
        packed_public_inputs.extend(&conditional_saver_pack::<bls12_381::Scalar>(
            &cred.pk_addr,
            b_saver,
        ));
        packed_public_inputs.extend(&conditional_saver_pack::<bls12_381::Scalar>(
            &note_new.pk_addr,
            b_saver,
        ));
        packed_public_inputs.extend(&conditional_saver_pack::<bls12_381::Scalar>(
            &note_new.v_note,
            b_saver,
        ));

        packed_public_inputs.push(rt_note);
        packed_public_inputs.extend(&compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
            &eta,
        )));
        packed_public_inputs.push(rt_mem);
        packed_public_inputs.push(rt_cred);
        packed_public_inputs.push(cm_note_new);
        packed_public_inputs.push(cm_mem_new);

        let mut expected_public_inputs = vec![];
        expected_public_inputs.extend(&mu);
        expected_public_inputs.extend(&k);
        expected_public_inputs.extend(&kappa);
        expected_public_inputs.extend(&mem_new.t_mem.0);
        packed_public_inputs.extend(&compute_multipacking::<bls12_381::Scalar>(&bytes_to_bits(
            &expected_public_inputs,
        )));

        // Verify the correctness of the circuit against expected public inputs.
        let result = cs.verify(&packed_public_inputs);
        println!("Verification result: {}.", result);
        assert!(result);
    }

    fn u64_to_u8_array(value: u64) -> [u8; 8] {
        (0..8)
            .rev()
            .map(|x| (value >> (8 * x) & (2_u64.pow(8) - 1)) as u8)
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .expect("This should fit.")
    }

    #[test]
    /// Test correctness of the implementation of saver, for a hardcoded set of variables. Change
    /// these variables in code to test a different setting. Note: this test is (very) slow, so
    /// better not use it.
    pub fn saver_test() {
        let mut rng = OsRng;
        let b_note = true;
        let b_mem = false;
        let b_ceil = false;
        let b_saver = true;
        let v_note_old = [0, 0, 0, 0, 0, 0, 0, 1];
        let v_mem_old = [0; 8];
        let c_mem_old = [0; 8];
        let v_note_new = [0, 0, 0, 0, 0, 0, 0, 1];
        let v_mem_new = [0; 8];
        let c_mem_new = [0; 8];
        let v_mem_ceil = [0; 8];
        let c_mem_ceil = [0; 8];

        // Construct Merkle trees
        let mut mt_cred = MerkleTree::new_cred();
        let mut mt_note = MerkleTree::new_note();
        let mut mt_mem = MerkleTree::new_mem();

        // Initialise the commitment trees with a random amount->[5;105) of random commitments.
        for tree in [&mut mt_cred, &mut mt_note, &mut mt_mem].iter_mut() {
            tree.append_random_commitment_range(&mut rng, 5, 105)
                .expect("Tree should not be full.");
        }

        // Initialise random value for k.
        let k = rng.gen();

        // Construct credentials, old note, old memory and compute their commitments.
        let cred = Credentials::generate_random(&mut rng);
        let cm_cred: bls12_381::Scalar = cred.comm_cred();
        let note_old = match b_note {
            true => Note::generate_random_from_pk_and_v(cred.pk_addr, v_note_old, &mut rng),
            false => Note::empty_from_pk(cred.pk_addr),
        };
        let cm_note_old: bls12_381::Scalar = note_old.comm_note();
        let mem_old = match b_mem {
            true => Memory::generate_random_from_pk_v_and_c(
                cred.pk_addr,
                v_mem_old,
                c_mem_old,
                &mut rng,
            ),
            false => Memory::empty_from_pk(cred.pk_addr),
        };
        let cm_mem_old: bls12_381::Scalar = mem_old.comm_mem();
        let mem_ceil = match b_ceil {
            true => Memory::generate_random_from_pk_v_t_and_c(
                cred.pk_addr,
                v_mem_ceil,
                TransactionTime::before_time_limit(),
                c_mem_ceil,
                &mut rng,
            ),
            false => {
                Memory::empty_from_pk_and_t(cred.pk_addr, TransactionTime::before_time_limit())
            }
        };
        let cm_mem_ceil: bls12_381::Scalar = mem_ceil.comm_mem();

        // Add credentials or old commitments to corresponding trees and construct the corresponding
        // incremental witnesses.
        mt_cred
            .append_credential_commitment(cm_cred)
            .expect("Tree should not be full.");
        let mut incremental_cred_witness = IncrementalMerkleWitness::from_tree(&mt_cred);
        if b_note {
            mt_note
                .append_note_commitment(cm_note_old, &note_old.t_note)
                .expect("Tree should not be full.");
        }
        let mut incremental_note_witness = match b_note {
            true => IncrementalMerkleWitness::from_tree(&mt_note),
            false => {
                let mut mt_note = MerkleTree::new_note();
                mt_note
                    .append_note_commitment(cm_note_old, &note_old.t_note)
                    .expect("Tree should not be full.");
                IncrementalMerkleWitness::from_tree(&mt_note)
            }
        };
        if b_ceil {
            mt_mem
                .append_memory_commitment(cm_mem_ceil, &mem_ceil.t_mem)
                .expect("Tree should not be full.");
        }
        let mut incremental_ceil_witness = match b_ceil {
            true => IncrementalMerkleWitness::from_tree(&mt_mem),
            false => {
                let mut mt_mem = MerkleTree::new_mem();
                mt_mem
                    .append_memory_commitment(cm_mem_ceil, &mem_ceil.t_mem)
                    .expect("Tree should not be full.");
                IncrementalMerkleWitness::from_tree(&mt_mem)
            }
        };
        if b_mem {
            let node = mt_mem
                .append_memory_commitment(cm_mem_old, &mem_old.t_mem)
                .expect("Tree should not be full.");
            incremental_ceil_witness
                .append(node)
                .expect("Tree should not be full.");
        }
        let mut incremental_mem_witness = match b_mem {
            true => IncrementalMerkleWitness::from_tree(&mt_mem),
            false => {
                let mut mt_mem = MerkleTree::new_mem();
                let node = mt_mem
                    .append_memory_commitment(cm_mem_old, &mem_old.t_mem)
                    .expect("Tree should not be full.");
                incremental_ceil_witness
                    .append(node)
                    .expect("Tree should not be full.");
                IncrementalMerkleWitness::from_tree(&mt_mem)
            }
        };

        // Add a random amount->[5;105) of random commitments to the Merkle Trees
        // and update the incremental witnesses accordingly.
        for (tree, incremental_witnesses) in
            [&mut mt_cred, &mut mt_note, &mut mt_mem].iter_mut().zip(
                [
                    vec![&mut incremental_cred_witness],
                    vec![&mut incremental_note_witness],
                    vec![&mut incremental_mem_witness, &mut incremental_ceil_witness],
                ]
                .iter_mut(),
            )
        {
            for _ in 0..rng.gen_range(5..105) {
                let node = tree
                    .append_random_commitment(&mut rng)
                    .expect("Tree should not be full.");
                for incremental_witness in incremental_witnesses.iter_mut() {
                    incremental_witness
                        .append(node)
                        .expect("Tree should not be full.");
                }
            }
        }

        // Compute witnesses to the credential and old commitments.
        // Also compute the Merkle roots to the current states of the corresponding trees.
        let credential_merkle_witness = incremental_cred_witness.witness();
        let note_merkle_witness = incremental_note_witness.witness();
        let memory_merkle_witness = incremental_mem_witness.witness();
        let memory_ceil_merkle_witness = incremental_ceil_witness.witness();
        let rt_cred: MerkleRoot = incremental_cred_witness.root_value();
        let rt_note: MerkleRoot = match b_note {
            true => incremental_note_witness.root_value(),
            false => bls12_381::Scalar::one(),
        };
        let rt_mem: MerkleRoot = match b_mem {
            true => incremental_mem_witness.root_value(),
            false => mt_mem.root_value(),
        };
        assert_eq!(mt_cred.root_value(), rt_cred);
        assert!(!b_note || mt_note.root_value() == rt_note);
        assert!(!b_mem || mt_mem.root_value() == rt_mem);

        // Construct new note and compute its commitment.
        let note_new = Note::generate_random_from_v(v_note_new, &mut rng);
        let cm_note_new: bls12_381::Scalar = note_new.comm_note();

        // Construct new memory and compute its commitment
        let mem_new =
            Memory::generate_random_from_pk_v_and_c(cred.pk_addr, v_mem_new, c_mem_new, &mut rng);
        let cm_mem_new: bls12_381::Scalar = mem_new.comm_mem();

        // Compute the note and memory nullifiers.
        let eta = match b_note {
            true => cred.prf_eta(&note_merkle_witness),
            false => [0; 32],
        };
        let mu = cred.prf_mu(&memory_merkle_witness, b_mem);

        // Compute the signature link kappa.
        let kappa = prf_kappa(&cred, &k);

        let (proving_key, saver_keys) = generate_random_parameters().unwrap();
        let (proof, ciphertext) = create_proof(
            &cred,
            if b_note { Some(&note_old) } else { None },
            if b_mem { Some(&mem_old) } else { None },
            if b_ceil { Some(&mem_ceil) } else { None },
            &credential_merkle_witness,
            if b_note {
                Some(&note_merkle_witness)
            } else {
                None
            },
            if b_mem {
                Some(&memory_merkle_witness)
            } else {
                None
            },
            if b_ceil {
                Some(&memory_ceil_merkle_witness)
            } else {
                None
            },
            Some(&rt_mem),
            &note_new,
            &mem_new,
            &k,
            b_saver,
            &proving_key,
            &saver_keys.pk,
        );
        let result = verify_proof(
            &proof,
            &ciphertext,
            &rt_cred,
            Some(&rt_note),
            &rt_mem,
            Some(&eta),
            &mu,
            &cm_note_new,
            &cm_mem_new,
            &k,
            &kappa,
            &mem_new.t_mem,
            &prepare_verifying_key_saver(&proving_key.vk),
            &saver_keys.pk,
        );
        println!("Result {}", result);
        assert!(result);
        let plaintext = decrypt(&ciphertext, &proving_key, &saver_keys.sk, &saver_keys.vk).unwrap();
        let mut plaintext_original = vec![];
        plaintext_original.extend_from_slice(&cred.pk_addr);
        plaintext_original.extend_from_slice(&note_new.pk_addr);
        plaintext_original.extend_from_slice(&note_new.v_note);
        let result = plaintext_original == plaintext.as_u8().0;
        println!("Plaintext matches original input? {}", result);
        assert!(result);
        let result = verify_decryption(
            &plaintext,
            &ciphertext,
            &proving_key,
            &saver_keys.pk,
            &saver_keys.vk,
        );
        println!("Decryption verification successful? {}", result);
        assert!(result)
    }
}
