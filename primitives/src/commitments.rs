//! Implementation of all out-circuit commitments

use bls12_381::Scalar;
use group::Curve;

use crate::constants::{
    CRED_COMMITMENT_RANDOMNESS_GENERATOR, MEM_COMMITMENT_RANDOMNESS_GENERATOR,
    NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
};
use crate::definitions::{Credentials, Memory, Note};
use crate::pedersen_hash::{pedersen_hash, Personalisation};

/// Compute COMM^cred.
impl Credentials {
    pub fn comm_cred(&self) -> Scalar {
        assert_eq!(self.pk_addr.len(), 32);
        assert_eq!(self.sk_addr.len(), 32);

        let mut preimage = vec![];
        preimage.extend(&self.pk_addr);
        preimage.extend(&self.sk_addr);
        let hash = pedersen_hash(
            Personalisation::CredCommitment,
            preimage
                .iter()
                .flat_map(|byte: &u8| (0..8).rev().map(move |i| byte >> i & 1 == 1)),
        );

        jubjub::ExtendedPoint::from((*CRED_COMMITMENT_RANDOMNESS_GENERATOR * self.s_cred) + hash)
            .to_affine()
            .get_u()
    }
}

/// Compute COMM^note.
impl Note {
    pub fn comm_note(&self) -> Scalar {
        assert_eq!(self.pk_addr.len(), 32);
        assert_eq!(self.v_note.len(), 8);

        let mut preimage = vec![];
        preimage.extend(&self.pk_addr);
        preimage.extend(&self.v_note);
        preimage.extend(&self.t_delta);

        let hash = pedersen_hash(
            Personalisation::NoteCommitment,
            preimage
                .iter()
                .flat_map(|byte: &u8| (0..8).rev().map(move |i| byte >> i & 1 == 1)),
        );

        jubjub::ExtendedPoint::from((*NOTE_COMMITMENT_RANDOMNESS_GENERATOR * self.s_note) + hash)
            .to_affine()
            .get_u()
    }
}

/// Compute COMM^mem.
impl Memory {
    pub fn comm_mem(&self) -> Scalar {
        assert_eq!(self.pk_addr.len(), 32);
        assert_eq!(self.v_mem.len(), 8);

        let mut preimage = vec![];
        preimage.extend(&self.pk_addr);
        preimage.extend(&self.v_mem);
        preimage.extend(&self.c_mem);

        let hash = pedersen_hash(
            Personalisation::MemCommitment,
            preimage
                .iter()
                .flat_map(|byte: &u8| (0..8).rev().map(move |i| byte >> i & 1 == 1)),
        );

        jubjub::ExtendedPoint::from((*MEM_COMMITMENT_RANDOMNESS_GENERATOR * self.s_mem) + hash)
            .to_affine()
            .get_u()
    }
}
