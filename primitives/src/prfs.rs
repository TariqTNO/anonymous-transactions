//! Implementation of all out-circuit PRF's

use bit_vec::BitVec;

use crate::constants::{
    MEMORY_MT_DEPTH, NOTE_MT_DEPTH, PERSONALISATION_PRF_ADDR, PERSONALISATION_PRF_ETA,
    PERSONALISATION_PRF_KAPPA, PERSONALISATION_PRF_MU,
};
use crate::definitions::{Credentials, MerkleWitness, SignatureKeyHash, SignatureKeyLink};

/// Generic PRF used for protocol specific PRF's.
fn prf(key: &[u8], bit1: bool, bit2: bool, seed: &[bool], personalisation: &[u8]) -> [u8; 32] {
    assert_eq!(key.len(), 32);
    assert_eq!(seed.len(), 254);
    assert_eq!(personalisation.len(), 8);

    *blake2s_simd::Params::new()
        .hash_length(32)
        .personal(personalisation)
        .to_state()
        .update(key)
        .update(
            &[bit1, bit2]
                .iter()
                .cloned()
                .chain(seed.iter().cloned())
                .collect::<BitVec>()
                .to_bytes(),
        )
        .finalize()
        .as_array()
}

/// Compute PRF^addr
impl Credentials {
    pub fn prf_addr(sk_addr: &[u8; 32]) -> [u8; 32] {
        prf(
            sk_addr,
            false,
            false,
            &[false; 254],
            PERSONALISATION_PRF_ADDR,
        )
    }
}

/// Compute PRF^eta
impl Credentials {
    pub fn prf_eta(&self, note_merkle_witness: &MerkleWitness) -> [u8; 32] {
        // Compute the seed
        let mut seed = vec![];
        seed.extend((0..(254 - NOTE_MT_DEPTH)).map(|_| false));
        seed.extend(
            (0..NOTE_MT_DEPTH)
                .rev()
                .map(|i| (note_merkle_witness.position >> i as u128 & 1 == 1)),
        );

        // Compute eta
        prf(
            self.sk_addr.as_ref(),
            false,
            true,
            &seed,
            PERSONALISATION_PRF_ETA,
        )
    }
}

/// Compute PRF^mu
impl Credentials {
    pub fn prf_mu(&self, memory_merkle_witness: &MerkleWitness, is_mem: bool) -> [u8; 32] {
        // Compute the seed
        let mut seed = vec![];
        seed.extend((0..(254 - MEMORY_MT_DEPTH - 1)).map(|_| false));
        seed.push(is_mem);
        seed.extend(
            (0..MEMORY_MT_DEPTH)
                .rev()
                .map(|i| memory_merkle_witness.position >> i as u128 & 1 == 1),
        );

        // Compute eta
        prf(
            self.sk_addr.as_ref(),
            true,
            false,
            &seed,
            PERSONALISATION_PRF_MU,
        )
    }
}

/// Compute PRF^kappa
pub fn prf_kappa(cred: &Credentials, k: &SignatureKeyHash) -> SignatureKeyLink {
    // Compute the seed
    let mut seed = vec![];
    for byte in k {
        seed.extend((0..8).rev().map(|i: u8| byte >> i & 1 == 1));
    }

    // Compute eta
    prf(
        cred.sk_addr.as_ref(),
        true,
        true,
        &seed[0..254],
        PERSONALISATION_PRF_KAPPA,
    )
}
