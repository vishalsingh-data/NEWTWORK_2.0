use crate::crypto::{decrypt_and_verify, encrypt_and_sign};
use crate::packet::NewtworkPacket;

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::thread;
use rand_core::OsRng;

pub fn run_receiver(
    my_port: &str,
    peer_x25519: &PublicKey,
    _peer_ed25519: &VerifyingKey,
    my_x25519_secret: EphemeralSecret,
    my_ed25519_secret: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", my_port))?;
    println!("Listening on port {}", my_port);

    let send_socket = socket.try_clone()?;
    let recv_socket = socket;

    let mut buf = [0u8; 4096];

    // ✅ derive ONCE and NEVER reuse secret again
    let base_shared = my_x25519_secret.diffie_hellman(peer_x25519);
    let base_shared_key = base_shared.as_bytes().to_vec();

    let mut fragment_store: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();

    // =========================
    // 🔥 RECEIVER THREAD
    // =========================
    let shared_key_recv = base_shared_key.clone();
    let shared_key_for_thread = shared_key_recv.clone();

    thread::spawn(move || {
        loop {
            let (len, _) = recv_socket.recv_from(&mut buf).expect("Receive failed");

            let packet: NewtworkPacket =
                bincode::deserialize(&buf[..len]).expect("Deserialization failed");

            let ed_bytes: [u8; 32] = packet.ed25519_pubkey
                .as_slice()
                .try_into()
                .expect("Invalid Ed25519 key");

            let verifying_key =
                VerifyingKey::from_bytes(&ed_bytes).expect("Invalid verifying key");

            // ✅ use ephemeral handshake if available
            let shared_key = if !packet.ephemeral_pubkey.is_empty() {

                let eph_pub = PublicKey::from(
                    <[u8; 32]>::try_from(packet.ephemeral_pubkey.as_slice()).unwrap()
                );

                // 🔥 generate fresh secret EVERY TIME
                let temp_secret = EphemeralSecret::random_from_rng(OsRng);
                let shared = temp_secret.diffie_hellman(&eph_pub);

                shared.as_bytes().to_vec()
            } else {
                shared_key_for_thread.clone()
            };

            let key_array: [u8; 32] = shared_key
                .as_slice()
                .try_into()
                .expect("Invalid key length");

            match decrypt_and_verify(
                &key_array,
                packet.nonce.as_slice().try_into().unwrap(),
                &packet.ciphertext,
                &packet.signature,
                &verifying_key,
            ) {
                Ok(plaintext) => {

                    let entry = fragment_store
                        .entry(packet.fragment_id)
                        .or_insert(vec![Vec::new(); packet.total_fragments as usize]);

                    entry[packet.sequence_number as usize] = plaintext;

                    if entry.iter().all(|x| !x.is_empty()) {

                        let mut full_data = Vec::new();
                        for chunk in entry.iter() {
                            full_data.extend_from_slice(chunk);
                        }

                        if packet.is_file {
                            let filename = format!("received_{}.jpg", packet.fragment_id);
                            fs::write(&filename, &full_data).unwrap();
                            println!(" Image received: {}", filename);
                        } else {
                            println!("Peer: {}", String::from_utf8_lossy(&full_data));
                        }

                        fragment_store.remove(&packet.fragment_id);
                    }
                }

                Err(e) => {
                    eprintln!(" Failed to decrypt: {}", e);
                }
            }
        }
    });

    // =========================
    // 🔥 SENDER LOOP
    // =========================

    println!(" Chat started! Type messages or 'file:<path>'");

    let stdin = io::stdin();
    let peer_addr = "127.0.0.1:9000";

    for line in stdin.lock().lines() {
        let input = line?;

        let (data, is_file) = if input.starts_with("file:") {
            let path = input.replace("file:", "");
            let file_bytes = fs::read(path)?;
            (file_bytes, true)
        } else {
            (input.into_bytes(), false)
        };

        let chunk_size = 1024;
        let total_fragments = ((data.len() + chunk_size - 1) / chunk_size) as u32;
        let fragment_id = rand::random::<u32>();

        for (i, chunk) in data.chunks(chunk_size).enumerate() {

            let key_array: [u8; 32] = shared_key_recv
                .as_slice()
                .try_into()
                .expect("Invalid key length");

            let (ciphertext, nonce, signature) =
                encrypt_and_sign(&key_array, my_ed25519_secret, chunk);

            let packet = NewtworkPacket {
                version: 1,
                source_tag: vec![],
                destination_tag: vec![],
                nonce: nonce.to_vec(),
                ciphertext,
                signature,
                ephemeral_pubkey: vec![],
                ed25519_pubkey: my_ed25519_secret.verifying_key().to_bytes().to_vec(),
                fragment_id,
                sequence_number: i as u32,
                total_fragments,
                is_file,
            };

            let encoded = bincode::serialize(&packet)?;
            send_socket.send_to(&encoded, peer_addr)?;
        }

        println!("You: sent {} fragments", total_fragments);
    }

    Ok(())
}