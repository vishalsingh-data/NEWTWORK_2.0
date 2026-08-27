// src/root_identity/mod.rs
use rpassword::read_password;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct RootIdentity {
    pub id: String,             // ephemeral ID
    password_hash: String,      // SHA256 hash hex
}

impl RootIdentity {
    /// Entry point to get identity: either load existing or create new
    pub fn load_or_create() -> Self {
        let path = Path::new("root_id.json");

        if path.exists() {
            // Returning user
            let data = fs::read_to_string(path).expect("Failed to read root_id.json");
            let identity: RootIdentity = serde_json::from_str(&data).expect("Invalid JSON");

            println!(" Welcome back! Please enter your password to unlock your root identity:");
            let password = read_password().expect("Failed to read password");

            if identity.verify(&password) {
                println!(" Password verified successfully!");
                return identity;
            } else {
                println!(" Incorrect password! Exiting.");
                std::process::exit(1);
            }
        } else {
            // First-time user
            println!(" Generating root ephemeral identity...");

            let mut bytes = [0u8; 16]; // 128-bit random ID
            OsRng.fill_bytes(&mut bytes);
            let id = hex::encode(bytes);

            println!(" Your root ID: {}", &id);
            println!("Keep it safe! You will need your password to verify it.");

            println!(" Enter a password to secure your root identity:");
            let password = read_password().expect("Failed to read password");

            let password_hash = Self::hash_password(&password);

            let identity = RootIdentity { id, password_hash };
            let json = serde_json::to_string_pretty(&identity).expect("Failed to serialize");
            fs::write(path, json).expect("Failed to save root_id.json");

            return identity;
        }
    }

    fn hash_password(password: &str) -> String {
        let hash = Sha256::digest(password.as_bytes());
        hex::encode(hash)
    }

    /// Verify password
    pub fn verify(&self, password: &str) -> bool {
        self.password_hash == Self::hash_password(password)
    }
}
