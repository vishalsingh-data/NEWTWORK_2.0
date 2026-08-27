use std::net::UdpSocket;
use std::thread;
use std::io::{self, BufRead};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::crypto::{encrypt_and_sign, decrypt_and_verify};

const MSG_DATA: u8 = 3;

pub fn start_chat(
    socket: UdpSocket,
    peer_addr: String,
    shared_key: [u8; 32],
    my_signing_key: SigningKey,
    peer_verifying_key: VerifyingKey,
) {
    let recv_socket = socket.try_clone().expect("Failed to clone socket");
    let send_socket = socket;

    let key_recv = shared_key.clone();
    let key_send = shared_key.clone();

    let verify_key = peer_verifying_key.clone();
    let sign_key = my_signing_key.clone();

    //  RECEIVE THREAD
    thread::spawn(move || {
        let mut buf = [0u8; 2048];

        loop {
            match recv_socket.recv_from(&mut buf) {
                Ok((size, _)) => {
                    let data = &buf[..size];

                    //  Ignore handshake/control packets
                    if data.len() < 1 {
                        continue;
                    }

                    let msg_type = data[0];

                    // Only process DATA packets
                    if msg_type != MSG_DATA {
                        continue;
                    }

                    //  DATA FORMAT: [TYPE(1) | nonce(12) | signature(64) | ciphertext]
                    if data.len() < 1 + 12 + 64 {
                        println!(" Invalid packet");
                        continue;
                    }

                    let nonce = &data[1..13];
                    let signature = &data[13..77];
                    let ciphertext = &data[77..];

                    match decrypt_and_verify(
                        &key_recv,
                        nonce.try_into().unwrap(),
                        ciphertext,
                        signature,
                        &verify_key,
                    ) {
                        Ok(plaintext) => {
                            match String::from_utf8(plaintext) {
                                Ok(msg) => println!("\nPeer: {}", msg),
                                Err(_) => println!(" Invalid UTF-8 message"),
                            }
                        }
                        Err(_) => {
                            println!(" Decryption/Verification failed");
                        }
                    }
                }
                Err(e) => {
                    println!("Receive error: {}", e);
                }
            }
        }
    });

    //  SEND LOOP
    println!("Chat started! Type message or /exit");

    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let msg = line.unwrap();

        if msg == "/exit" {
            println!("Exiting...");
            break;
        }

        let (ciphertext, nonce, signature) =
            encrypt_and_sign(&key_send, &sign_key, msg.as_bytes());

        //  PACK FORMAT: [TYPE | nonce | signature | ciphertext]
        let mut packet = Vec::new();
        packet.push(MSG_DATA); //  CRITICAL FIX
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&signature);
        packet.extend_from_slice(&ciphertext);

        let _ = send_socket.send_to(&packet, &peer_addr);
    }
}
