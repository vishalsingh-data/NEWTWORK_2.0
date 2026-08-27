use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand_core::RngCore;
use std::convert::TryInto;
use x25519_dalek::{EphemeralSecret, PublicKey};
use sha2::{Digest, Sha256};

/// message ko encrypt krke sign karega using ChaCha20-Poly1305 and Ed25519.
pub fn encrypt_and_sign(
    shared_key: &[u8; 32],
    signing_key: &SigningKey,
    message: &[u8],
) -> (Vec<u8>, [u8; 12], Vec<u8>) {
    let key = Key::from_slice(shared_key);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message)
        .expect("Encryption failed");

    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&nonce_bytes);
    data_to_sign.extend_from_slice(&ciphertext);

    let signature = signing_key.sign(&data_to_sign).to_bytes().to_vec();

    (ciphertext, nonce_bytes, signature)
}

/// signature verify karega aur cipher text ko decrypt karegaa
pub fn decrypt_and_verify(
    shared_key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    signature: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<Vec<u8>, &'static str> {
    let key = Key::from_slice(shared_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_obj = Nonce::from_slice(nonce);

    let mut data_to_verify = Vec::new();
    data_to_verify.extend_from_slice(nonce);
    data_to_verify.extend_from_slice(ciphertext);

    let array: &[u8; 64] = signature.try_into().map_err(|_| "Invalid signature length")?;
    let sig = Signature::try_from(array).map_err(|_| "Signature parsing failed")?;

    verifying_key
        .verify(&data_to_verify, &sig)
        .map_err(|_| "Signature verification failed")?;

    cipher
        .decrypt(nonce_obj, ciphertext.as_ref())
        .map_err(|_| "Decryption failed")
}

/// Derives a shared 32-byte key using X25519 ECDH and SHA256 hash.
pub fn derive_shared_key(secret: EphemeralSecret, public: &PublicKey) -> [u8; 32] {
    let shared_secret = secret.diffie_hellman(public);

    let shared_bytes = shared_secret.to_bytes(); //  FIXED
    let hash = Sha256::digest(shared_bytes);

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}
