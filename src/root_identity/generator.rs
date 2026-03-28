use rand::RngCore;
use sha2::{Digest, Sha256};
use rpassword::read_password;

pub struct RootIdentity {
    pub mnemonic: String,
    pub hashed_password: String,
}

impl RootIdentity {
    pub fn new() -> Self {
        // Generate a 32-byte random entropy
        let mut entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);

        // Convert entropy to hex as a simple mnemonic (can replace with BIP39 later)
        let mnemonic = hex::encode(entropy);

        println!("📝 Your ephemeral root mnemonic is: {}", &mnemonic);

        // Prompt for password
        println!("🔐 Enter a password to protect your identity:");
        let password = read_password().expect("Failed to read password");

        let hashed_password = Self::hash_password(&password);

        RootIdentity { mnemonic, hashed_password }
    }

    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn verify_password(&self, password: &str) -> bool {
        Self::hash_password(password) == self.hashed_password
    }
}