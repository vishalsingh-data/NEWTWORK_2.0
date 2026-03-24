mod identity;
mod sender;
mod receiver;
mod crypto;
mod packet;
mod logger;

use identity::Identity;
use std::env;
use std::fs;
use std::error::Error;
use ed25519_dalek::VerifyingKey;
use x25519_dalek::PublicKey;

use crate::identity::PeerKeys;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let mode = get_arg_value(&args, "--mode").expect("Missing --mode");

    let mut my_identity = Identity::new();

    let my_keys = PeerKeys {
        x25519: my_identity.x25519_public.to_bytes(),
        ed25519: my_identity.ed25519_public.to_bytes(),
    };
    fs::write("my_keys.json", serde_json::to_string_pretty(&my_keys)?)?;

    let peer_keys_path = get_arg_value(&args, "--peer-keys").expect("Missing --peer-keys");
    let peer_keys_data = fs::read_to_string(peer_keys_path)?;
    let peer_keys: PeerKeys = serde_json::from_str(&peer_keys_data)?;

    let peer_x25519 = PublicKey::from(peer_keys.x25519);
    let peer_ed25519 = VerifyingKey::from_bytes(&peer_keys.ed25519)?;

    let my_port = get_arg_value(&args, "--my-port").expect("Missing --my-port");
    let peer_ip = get_arg_value(&args, "--peer-ip").expect("Missing --peer-ip");
    let peer_port = get_arg_value(&args, "--peer-port").expect("Missing --peer-port");

    let my_x_sk = my_identity
        .x25519_secret
        .take()
        .expect("Secret already taken");

    match mode.as_str() {
        "receive" => {
            receiver::run_receiver(
                &my_port,
                &peer_ip,
                &peer_port,
                &peer_x25519,
                &peer_ed25519,
                my_x_sk,
                &my_identity.ed25519_secret,
            )?;
        }

        "send" => {
            sender::run_sender(
                &my_port,
                &peer_ip,
                &peer_port,
                &peer_keys,
                my_x_sk,
                &my_identity.x25519_public,
                &my_identity.ed25519_secret,
            )?;
        }

        _ => println!("Invalid mode"),
    }

    Ok(())
}

fn get_arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|x| x == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}