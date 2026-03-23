use crate::crypto::{encrypt_and_sign, derive_shared_key, decrypt_and_verify};
use crate::packet::NewtworkPacket;
use crate::identity::PeerKeys;

use rand_core::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

use std::fs;
use std::io::{self, BufRead};
use std::thread;
use std::collections::HashMap;

/// Sends AND receives (2-way chat mode)
pub fn run_sender(
    my_port: &str,
    peer_ip: &str,
    peer_port: &str,
    peer_keys: &PeerKeys,
    my_x25519_secret: EphemeralSecret,
    _my_x25519_public: &PublicKey,
    my_ed25519_secret: &SigningKey,
    _message: Option<String>,
    _file_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", my_port))?;
    socket.set_nonblocking(true)?;

    let peer_x25519 = PublicKey::from(peer_keys.x25519);

    // ✅ base shared key
    let base_shared_key = derive_shared_key(my_x25519_secret, &peer_x25519);

    let send_socket = socket.try_clone()?;
    let recv_socket = socket;

    let peer_addr = format!("{}:{}", peer_ip, peer_port);

    // =========================
    // 🔥 RECEIVER THREAD
    // =========================
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut fragment_store: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();

        loop {
            match recv_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let packet: NewtworkPacket =
                        bincode::deserialize(&buf[..len]).unwrap();

                    let ed_bytes: [u8; 32] = packet.ed25519_pubkey
                        .as_slice()
                        .try_into()
                        .unwrap();

                    let verifying_key = VerifyingKey::from_bytes(&ed_bytes).unwrap();

                    // ✅ shared key (fixed type)
                    let shared_key: [u8; 32] = if !packet.ephemeral_pubkey.is_empty() {
                        let eph_pub = PublicKey::from(
                            <[u8; 32]>::try_from(packet.ephemeral_pubkey.as_slice()).unwrap()
                        );

                        // ⚠️ fallback (still safe for now)
                        let temp_secret = EphemeralSecret::random_from_rng(OsRng);
                        let shared = temp_secret.diffie_hellman(&eph_pub);
                        *shared.as_bytes()
                    } else {
                        base_shared_key
                    };

                    match decrypt_and_verify(
                        &shared_key,
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
                                    println!("\nImage received: {}", filename);
                                } else {
                                    println!("\nPeer: {}", String::from_utf8_lossy(&full_data));
                                }

                                fragment_store.remove(&packet.fragment_id);
                            }
                        }

                        Err(_) => {
                            println!("\nFailed to decrypt message");
                        }
                    }
                }

                Err(_) => {}
            }
        }
    });

    // =========================
    // 🔥 SENDER LOOP
    // =========================

    println!("Chat started! Type messages or 'file:<path>'");

    let stdin = io::stdin();

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

        // ✅ ephemeral key per message
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_public = PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&peer_x25519);
        let shared_key = *shared.as_bytes();

        for (i, chunk) in data.chunks(chunk_size).enumerate() {

            let (ciphertext, nonce, signature) =
                encrypt_and_sign(&shared_key, my_ed25519_secret, chunk);

            let packet = NewtworkPacket {
                version: 1,
                source_tag: vec![],
                destination_tag: vec![],
                nonce: nonce.to_vec(),
                ciphertext,
                signature,
                ephemeral_pubkey: eph_public.as_bytes().to_vec(),
                ed25519_pubkey: my_ed25519_secret.verifying_key().to_bytes().to_vec(),
                fragment_id,
                sequence_number: i as u32,
                total_fragments,
                is_file,
            };

            let encoded = bincode::serialize(&packet)?;
            send_socket.send_to(&encoded, &peer_addr)?;
        }

        println!("You: sent {} fragments", total_fragments);
    }

    Ok(())
}