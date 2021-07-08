//! Out-circuit signature functionality.

use ring::error::{KeyRejected, Unspecified};
use ring::pkcs8::Document;
use ring::rand::SecureRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, Signature, UnparsedPublicKey, ED25519};

use crate::constants::PERSONALISATION_K;
use crate::definitions::SignatureKeyHash;

/// Generate a valid Ed25519 signature key pair.
pub fn generate_keypair(rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
    Ed25519KeyPair::generate_pkcs8(rng)
}

/// Sign a `message` and return the signature using an Ed25519 `key_pair`.
pub fn sign(message: &[u8], key_pair: &Ed25519KeyPair) -> Result<Signature, KeyRejected> {
    Ok(key_pair.sign(message))
}

/// Verify a `signature` on a `message`, given the Ed25519 `public_key`.
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let public_key = UnparsedPublicKey::new(&ED25519, public_key);
    public_key.verify(message, signature).is_ok()
}

/// Compute k: the hash of the Ed25519 public signature key `public_key`.
pub fn compute_k(public_key: &<Ed25519KeyPair as KeyPair>::PublicKey) -> SignatureKeyHash {
    *blake2s_simd::Params::new()
        .hash_length(32)
        .personal(PERSONALISATION_K)
        .to_state()
        .update(public_key.as_ref())
        .finalize()
        .as_array()
}
