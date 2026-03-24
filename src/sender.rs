use crate::crypto::{encrypt_and_sign, decrypt_and_verify};
use crate::packet::NewtworkPacket;
use crate::identity::PeerKeys;

use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use std::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

use std::io::{self, BufRead};
use std::thread;
use std::time::Duration;
use rand_core::OsRng;

pub fn run_sender(
    my_port: &str,
    peer_ip: &str,
    peer_port: &str,
    peer_keys: &PeerKeys,
    _my_x25519_secret: EphemeralSecret,
    _my_x25519_public: &PublicKey,
    my_ed25519_secret: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", my_port))?;
    socket.set_nonblocking(true)?;

    let peer_addr = format!("{}:{}", peer_ip, peer_port);

    // 🔥 STEP 1 — CREATE EPHEMERAL
    let my_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let my_eph_public = PublicKey::from(&my_eph_secret);

    // 🔥 STEP 2 — SIGN IT
    let signature = my_ed25519_secret.sign(my_eph_public.as_bytes());

    // 🔥 STEP 3 — SEND HANDSHAKE INIT
    let init_packet = NewtworkPacket {
        packet_type: 0,
        version: 1,
        source_tag: vec![],
        destination_tag: vec![],
        nonce: vec![],
        ciphertext: vec![],
        signature: signature.to_bytes().to_vec(),
        ephemeral_pubkey: my_eph_public.as_bytes().to_vec(),
        ed25519_pubkey: my_ed25519_secret.verifying_key().to_bytes().to_vec(),
        fragment_id: 0,
        sequence_number: 0,
        total_fragments: 1,
        is_file: false,
    };

    let encoded = bincode::serialize(&init_packet)?;
    socket.send_to(&encoded, &peer_addr)?;

    println!("🔄 Handshake INIT sent...");

    // 🔥 STEP 4 — WAIT FOR RESPONSE
    let mut buf = [0u8; 4096];
    let shared_key;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                let packet: NewtworkPacket =
                    bincode::deserialize(&buf[..len]).unwrap();

                if packet.packet_type == 1 {
                    println!("✅ Handshake RESPONSE received");

                    let peer_eph: [u8; 32] =
                        packet.ephemeral_pubkey.as_slice().try_into().unwrap();

                    let peer_eph_pub = PublicKey::from(peer_eph);

                    let shared = my_eph_secret.diffie_hellman(&peer_eph_pub);
                    shared_key = *shared.as_bytes();

                    break;
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    println!("🔐 Secure session established!");
    println!("Chat started! Type message or /exit");

    // 🔥 CHAT LOOP
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let input = line?;

        if input == "/exit" {
            break;
        }

        let (ciphertext, nonce, signature) =
            encrypt_and_sign(&shared_key, my_ed25519_secret, input.as_bytes());

        let packet = NewtworkPacket {
            packet_type: 2,
            version: 1,
            source_tag: vec![],
            destination_tag: vec![],
            nonce: nonce.to_vec(),
            ciphertext,
            signature,
            ephemeral_pubkey: vec![],
            ed25519_pubkey: my_ed25519_secret.verifying_key().to_bytes().to_vec(),
            fragment_id: 0,
            sequence_number: 0,
            total_fragments: 1,
            is_file: false,
        };

        let encoded = bincode::serialize(&packet)?;
        socket.send_to(&encoded, &peer_addr)?;
    }

    Ok(())
}