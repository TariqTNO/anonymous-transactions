//! Out-circuit encryption functionality.

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305,
};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::error;
use ring::error::Unspecified;
use ring::hkdf::{Salt, HKDF_SHA512};
use ring::rand::{SecureRandom, SystemRandom};

use crate::constants::SALT_ENCRYPTION;

/// Generate a valid X25519 asymmetric encryption/decryption key pair.
pub fn generate_keypair(
    rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, PublicKey), error::Unspecified> {
    let private_key = EphemeralPrivateKey::generate(&X25519, rng)?;
    let public_key = private_key.compute_public_key()?;
    Ok((private_key, public_key))
}

/// Encrypt the plaintext `message` in-place, given the `context` and the receiver`s `public_key`.
/// Return the ephemeral public key that is needed for decrypting this message.
pub fn encrypt<B: AsRef<[u8]>>(
    message: &mut Vec<u8>,
    context: &[u8],
    public_key: &UnparsedPublicKey<B>,
) -> Result<UnparsedPublicKey<PublicKey>, error::Unspecified> {
    // Generate ephemeral keys.
    let rng = SystemRandom::new();
    let ephemeral_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let ephemeral_public_key = ephemeral_private_key.compute_public_key()?;
    let ephemeral_public_key = UnparsedPublicKey::new(&X25519, ephemeral_public_key);

    // Encryption
    let key = key_agreement(context, ephemeral_private_key, public_key)?;
    SealingKey::new(key, OneNonceSequence::new())
        .seal_in_place_append_tag(Aad::empty(), message)?;

    Ok(ephemeral_public_key)
}

/// Decrypt the ciphertext `message` in-place, given the `context`, the receiver's `private_key` and
/// the `ephemeral_public_key` of this `message`.
pub fn decrypt<'a, B: AsRef<[u8]>>(
    message: &'a mut Vec<u8>,
    context: &[u8],
    private_key: EphemeralPrivateKey,
    ephemeral_public_key: &UnparsedPublicKey<B>,
) -> Result<&'a mut [u8], Unspecified> {
    let key = key_agreement(context, private_key, ephemeral_public_key)?;
    OpeningKey::new(key, OneNonceSequence::new()).open_in_place(Aad::empty(), message)
}

/// Compute the shared key material from a private and public key.
fn key_agreement<B: AsRef<[u8]>>(
    context: &[u8],
    private_key: EphemeralPrivateKey,
    public_key: &UnparsedPublicKey<B>,
) -> Result<UnboundKey, error::Unspecified> {
    let context = &[context];
    agree_ephemeral(
        private_key,
        public_key,
        error::Unspecified,
        |shared_secret| {
            Ok(UnboundKey::from(
                Salt::new(HKDF_SHA512, SALT_ENCRYPTION)
                    .extract(shared_secret)
                    .expand(context, &CHACHA20_POLY1305)?,
            ))
        },
    )
}

/// Simple Nonce struct that always returns maximally one zero Nonce, we thus assume that each key
/// is only used once.
struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    /// Construct a new `OneNonceSequence`.
    fn new() -> Self {
        OneNonceSequence(Some(Nonce::assume_unique_for_key([0; 12])))
    }
}

impl NonceSequence for OneNonceSequence {
    /// Return the `Nonce` stored in this struct, if it has not yet been used.
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}
