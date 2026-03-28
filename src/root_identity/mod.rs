use rpassword::read_password;
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};

pub struct RootIdentity {
    pub id: String,      // user-friendly ephemeral ID
    pub password_hash: Vec<u8>,
}

impl RootIdentity {
    /// Generate a new ephemeral root identity
    pub fn new() -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 16]; // 128-bit random root ID
        rng.fill_bytes(&mut bytes);

        // Convert to hex string for easy remembering
        let id = hex::encode(bytes);

        // Prompt user for password
        println!("🔑 Enter a password to secure your root identity:");
        let password = read_password().expect("Failed to read password");

        let password_hash = Sha256::digest(password.as_bytes()).to_vec();

        Self { id, password_hash }
    }

    /// Verify password
    pub fn verify(&self, password: &str) -> bool {
        let hash = Sha256::digest(password.as_bytes()).to_vec();
        self.password_hash == hash
    }
}