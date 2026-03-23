use x25519_dalek::{EphemeralSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Sha256, Digest};

pub struct Identity {
    pub x25519_secret: Option<EphemeralSecret>,
    pub x25519_public: PublicKey,
    pub ed25519_secret: SigningKey,
    pub ed25519_public: VerifyingKey,
    pub tag: Vec<u8>,
}

impl Identity {
    pub fn new() -> Self {
        let rng = OsRng;

        let x25519_secret = EphemeralSecret::random_from_rng(rng);
        let x25519_public = PublicKey::from(&x25519_secret);

        let ed25519_secret = SigningKey::generate(&mut OsRng);
        let ed25519_public = ed25519_secret.verifying_key();

        let mut hasher = Sha256::new();
        hasher.update(x25519_public.as_bytes());
        hasher.update(ed25519_public.as_bytes());
        let tag = hasher.finalize().to_vec();

        Identity {
            x25519_secret: Some(x25519_secret),
            x25519_public,
            ed25519_secret,
            ed25519_public,
            tag,
        }
    }
}

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct PeerKeys {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}