use newtwork_prototype_2::root_identity::RootIdentity;

fn main() {
    println!("🟢 Generating root ephemeral identity...");
    let identity = RootIdentity::new();

    println!("\n🎯 Your root ID: {}", identity.id);
    println!("Keep it safe! You will need your password to verify it.");

    // Test verification
    println!("\n🔑 Re-enter password to verify:");
    let password = rpassword::read_password().expect("Failed to read password");

    if identity.verify(&password) {
        println!("✅ Password verified successfully!");
    } else {
        println!("❌ Incorrect password!");
    }
}