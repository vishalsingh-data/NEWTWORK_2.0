// src/bin/test_root_identity.rs
use newtwork_prototype_2::root_identity::RootIdentity;

fn main() {
    // Load or create identity
    let identity = RootIdentity::load_or_create();

    println!("\n📝 Your ephemeral root ID: {}", identity.id);
}