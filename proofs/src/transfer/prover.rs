//! Prover functionality for transfer circuit

use bellman::groth16::{Parameters, Proof};
use rand::rngs::OsRng;

use primitives::constants::{MEMORY_MT_DEPTH, NOTE_MT_DEPTH};
use primitives::definitions::{
    Credentials, Memory, MerkleRoot, MerkleWitness, Note, SignatureKeyHash, TransactionTime,
};
use primitives::saver::{
    create_groth16_proof_and_saver_encryption, SaverCiphertext, SaverPublicKey,
};

use crate::saver::conditional_saver_pack;
use crate::transfer::circuit::Transfer;

/// Transfer proof constructor
pub fn create_proof(
    cred: &Credentials,
    note_old: Option<&Note>,
    mem_old: Option<&Memory>,
    mem_ceil: Option<&Memory>,
    credential_merkle_witness: &MerkleWitness,
    note_merkle_witness: Option<&MerkleWitness>,
    memory_merkle_witness: Option<&MerkleWitness>,
    memory_ceil_merkle_witness: Option<&MerkleWitness>,
    rt_mem: Option<&MerkleRoot>,
    note_new: &Note,
    mem_new: &Memory,
    k: &SignatureKeyHash,
    use_saver: bool,
    proving_key: &Parameters<bls12_381::Bls12>,
    saver_public_key: &SaverPublicKey<bls12_381::Bls12>,
) -> (Proof<bls12_381::Bls12>, SaverCiphertext<bls12_381::Bls12>) {
    assert!(note_old.is_some() || mem_old.is_some());
    assert!(mem_old.is_some() || rt_mem.is_some());
    assert!(if mem_ceil.is_some() {
        mem_old.is_some()
    } else {
        true
    });
    assert_eq!(note_old.is_some(), note_merkle_witness.is_some());
    assert_eq!(mem_old.is_some(), memory_merkle_witness.is_some());
    assert_eq!(mem_ceil.is_some(), memory_ceil_merkle_witness.is_some());

    let note_old_alt = Note::empty_from_pk(cred.pk_addr);
    let mem_old_alt = Memory::empty_from_pk(cred.pk_addr);
    let mem_ceil_alt =
        Memory::empty_from_pk_and_t(cred.pk_addr, TransactionTime::before_time_limit());
    let note_merkle_witness_alt = MerkleWitness::empty(NOTE_MT_DEPTH);
    let memory_merkle_witness_alt = MerkleWitness::empty(MEMORY_MT_DEPTH);
    let memory_ceil_merkle_witness_alt = MerkleWitness::empty(MEMORY_MT_DEPTH);
    let rt_mem_pub = bls12_381::Scalar::one();

    // Initialise secure PRNG
    let mut rng = OsRng;

    // Obtain message
    let mut message = vec![];
    message.extend(&conditional_saver_pack::<bls12_381::Scalar>(
        &cred.pk_addr,
        use_saver,
    ));
    message.extend(&conditional_saver_pack::<bls12_381::Scalar>(
        &note_new.pk_addr,
        use_saver,
    ));
    message.extend(&conditional_saver_pack::<bls12_381::Scalar>(
        &note_new.v_note,
        use_saver,
    ));

    let transfer = Transfer {
        cred: Some(cred),
        note_old: note_old.or(Some(&note_old_alt)),
        mem_old: mem_old.or(Some(&mem_old_alt)),
        mem_ceil: mem_ceil.or(Some(&mem_ceil_alt)),
        credential_merkle_witness: Some(credential_merkle_witness),
        note_merkle_witness: note_merkle_witness.or(Some(&note_merkle_witness_alt)),
        memory_merkle_witness: memory_merkle_witness.or(Some(&memory_merkle_witness_alt)),
        memory_ceil_merkle_witness: memory_ceil_merkle_witness
            .or(Some(&memory_ceil_merkle_witness_alt)),
        rt_mem_pub: rt_mem.or(Some(&rt_mem_pub)),
        note_new: Some(note_new),
        mem_new: Some(mem_new),
        b_note: Some(note_old.is_some()),
        b_mem: Some(mem_old.is_some()),
        b_saver: Some(use_saver),
        k: Some(k),
    };

    create_groth16_proof_and_saver_encryption(
        transfer,
        message,
        proving_key,
        saver_public_key,
        &mut rng,
    )
    .expect("Creating a proof should not fail.")
}
