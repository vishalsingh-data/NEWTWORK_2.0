use crate::crypto::{decrypt_and_verify, encrypt_and_sign};
use crate::packet::NewtworkPacket;

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::thread;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub fn run_receiver(
    my_port: &str,
    peer_ip: &str,
    peer_port: &str,
    peer_x25519: &PublicKey,
    _peer_ed25519: &VerifyingKey,
    my_x25519_secret: EphemeralSecret,
    my_ed25519_secret: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", my_port))?;
    socket.set_nonblocking(true)?;

    let send_socket = socket.try_clone()?;
    let recv_socket = socket;

    let peer_addr = format!("{}:{}", peer_ip, peer_port);

    let running = Arc::new(AtomicBool::new(true));
    let running_recv = running.clone();

    let base_shared = my_x25519_secret.diffie_hellman(peer_x25519);
    let shared_key = *base_shared.as_bytes();

    // 🔥 RECEIVER THREAD
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut fragment_store: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();

        while running_recv.load(Ordering::SeqCst) {
            match recv_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let packet: NewtworkPacket =
                        bincode::deserialize(&buf[..len]).unwrap();

                    let ed_bytes: [u8; 32] = packet.ed25519_pubkey
                        .as_slice()
                        .try_into()
                        .unwrap();

                    let verifying_key = VerifyingKey::from_bytes(&ed_bytes).unwrap();

                    match decrypt_and_verify(
                        &shared_key,
                        packet.nonce.as_slice().try_into().unwrap(),
                        &packet.ciphertext,
                        &packet.signature,
                        &verifying_key,
                    ) {
                        Ok(plaintext) => {
                            println!("\nPeer: {}", String::from_utf8_lossy(&plaintext));
                        }
                        Err(_) => {
                            println!("\nFailed to decrypt");
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });

    // 🔥 SENDER LOOP
    println!("Chat started! Type message or /exit");

    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let input = line?;

        if input == "/exit" {
            running.store(false, Ordering::SeqCst);
            println!("Session ended.");
            break;
        }

        let (ciphertext, nonce, signature) =
            encrypt_and_sign(&shared_key, my_ed25519_secret, input.as_bytes());

        let packet = NewtworkPacket {
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
        send_socket.send_to(&encoded, &peer_addr)?;
    }

    Ok(())
}