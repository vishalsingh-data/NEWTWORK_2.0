use crate::crypto::{decrypt_and_verify, encrypt_and_sign};
use crate::packet::NewtworkPacket;

use ed25519_dalek::{SigningKey, VerifyingKey, Verifier, Signer};
use std::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

use std::io::{self, BufRead};
use rand_core::OsRng;

pub fn run_receiver(
    my_port: &str,
    peer_ip: &str,
    peer_port: &str,
    _peer_x25519: &PublicKey,
    _peer_ed25519: &VerifyingKey,
    _my_x25519_secret: EphemeralSecret,
    my_ed25519_secret: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", my_port))?;

    let peer_addr = format!("{}:{}", peer_ip, peer_port);

    println!("⏳ Waiting for handshake INIT...");

    let mut buf = [0u8; 4096];

    //  WAIT FOR INIT
    let (shared_key, _) = loop {
        let (len, src) = socket.recv_from(&mut buf)?;

        let packet: NewtworkPacket =
            bincode::deserialize(&buf[..len]).unwrap();

        if packet.packet_type == 0 {
            println!(" Handshake INIT received");

            let peer_eph: [u8; 32] =
                packet.ephemeral_pubkey.as_slice().try_into().unwrap();

            let peer_eph_pub = PublicKey::from(peer_eph);

            // VERIFY SIGNATURE
            let ed_bytes: [u8; 32] =
                packet.ed25519_pubkey.as_slice().try_into().unwrap();

            let verifying_key = VerifyingKey::from_bytes(&ed_bytes).unwrap();

            let sig_bytes: [u8; 64] =
                packet.signature.as_slice().try_into().unwrap();

            verifying_key.verify(&peer_eph, &sig_bytes.into()).unwrap();

            // CREATE OWN EPHEMERAL
            let my_eph_secret = EphemeralSecret::random_from_rng(OsRng);
            let my_eph_public = PublicKey::from(&my_eph_secret);

            let signature = my_ed25519_secret.sign(my_eph_public.as_bytes());

            // SEND RESPONSE
            let response_packet = NewtworkPacket {
                packet_type: 1,
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

            let encoded = bincode::serialize(&response_packet)?;
            socket.send_to(&encoded, src)?;

            println!(" Handshake RESPONSE sent");

            let shared = my_eph_secret.diffie_hellman(&peer_eph_pub);
            let shared_key = *shared.as_bytes();

            break (shared_key, src);
        }
    };

    println!(" Secure session established!");
    println!("Chat started! Type message or /exit");

    //  CHAT LOOP
    loop {
        let (len, _) = socket.recv_from(&mut buf)?;

        let packet: NewtworkPacket =
            bincode::deserialize(&buf[..len]).unwrap();

        if packet.packet_type == 2 {
            let ed_bytes: [u8; 32] =
                packet.ed25519_pubkey.as_slice().try_into().unwrap();

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
                Err(e) => {
                    println!("Decrypt failed: {}", e);
                }
            }
        }
    }
}
