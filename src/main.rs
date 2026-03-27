mod identity;
mod crypto;
mod packet;
mod logger;
mod network;

use identity::Identity;
use std::env;
use std::error::Error;
use std::net::UdpSocket;

use x25519_dalek::PublicKey;
use crate::crypto::derive_shared_key;

use ed25519_dalek::VerifyingKey;

const MSG_KEY: u8 = 1;
const MSG_ACK: u8 = 2;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let mode = get_arg_value(&args, "--mode").expect("Missing --mode (send/receive)");
    let my_port = get_arg_value(&args, "--my-port").expect("Missing --my-port");

    let my_addr = format!("127.0.0.1:{}", my_port);
    let socket = UdpSocket::bind(&my_addr)?;
    socket.set_nonblocking(false)?;

    println!("🟢 Node started on {}", my_addr);

    if mode == "send" {
        run_sender(socket, &args)?;
    } else if mode == "receive" {
        run_receiver(socket)?;
    } else {
        panic!("Invalid mode. Use send or receive");
    }

    Ok(())
}

fn run_sender(socket: UdpSocket, args: &[String]) -> Result<(), Box<dyn Error>> {
    let peer_ip = get_arg_value(args, "--peer-ip").expect("Missing --peer-ip");
    let peer_port = get_arg_value(args, "--peer-port").expect("Missing --peer-port");

    let peer_addr = format!("{}:{}", peer_ip, peer_port);

    let mut identity = Identity::new();

    let my_secret = identity
        .x25519_secret
        .take()
        .expect("Secret already taken");

    let my_public = identity.x25519_public;

    let mut buf = [0u8; 1024];

    let mut peer_pub: Option<PublicKey> = None;
    let mut peer_ed25519: Option<VerifyingKey> = None;
    let mut got_ack = false;

    println!("⏳ Performing handshake...");

    loop {
        let mut key_packet = vec![MSG_KEY];
        key_packet.extend_from_slice(my_public.as_bytes());
        key_packet.extend_from_slice(identity.ed25519_public.to_bytes().as_slice());

        socket.send_to(&key_packet, &peer_addr)?;

        let (size, _) = socket.recv_from(&mut buf)?;

        match buf[0] {
            MSG_KEY => {
                if size == 65 {
                    let x25519_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
                    let ed25519_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

                    peer_pub = Some(PublicKey::from(x25519_bytes));
                    peer_ed25519 =
                        Some(VerifyingKey::from_bytes(&ed25519_bytes).unwrap());

                    println!("✅ Received peer public key");
                }
            }
            MSG_ACK => {
                got_ack = true;
                println!("🤝 Received ACK");
            }
            _ => {}
        }

        if peer_pub.is_some() {
            socket.send_to(&[MSG_ACK], &peer_addr)?;
        }

        if peer_pub.is_some() && peer_ed25519.is_some() && got_ack {
            break;
        }
    }

    let shared_key = derive_shared_key(my_secret, &peer_pub.unwrap());

    println!("🔐 Secure session established!");
    println!("💬 Chat started! Type message or /exit");

    network::start_chat(
        socket,
        peer_addr,
        shared_key,
        identity.ed25519_secret.clone(),
        peer_ed25519.unwrap(),
    );

    Ok(())
}

fn run_receiver(socket: UdpSocket) -> Result<(), Box<dyn Error>> {
    loop {
        println!("\n🟡 Waiting for incoming connection...");

        let mut identity = Identity::new();

        let my_secret = identity
            .x25519_secret
            .take()
            .expect("Secret already taken");

        let my_public = identity.x25519_public;

        let mut buf = [0u8; 1024];

        let mut peer_pub: Option<PublicKey> = None;
        let mut peer_ed25519: Option<VerifyingKey> = None;
        let mut peer_addr: Option<String> = None;

        loop {
            let (size, src) = socket.recv_from(&mut buf)?;

            match buf[0] {
                MSG_KEY => {
                    if size == 65 {
                        println!("📥 Incoming handshake from {}", src);

                        let x25519_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
                        let ed25519_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

                        peer_pub = Some(PublicKey::from(x25519_bytes));
                        peer_ed25519 =
                            Some(VerifyingKey::from_bytes(&ed25519_bytes).unwrap());

                        peer_addr = Some(src.to_string());

                        println!("✅ Received peer public key");

                        // Send our key
                        let mut key_packet = vec![MSG_KEY];
                        key_packet.extend_from_slice(my_public.as_bytes());
                        key_packet.extend_from_slice(identity.ed25519_public.to_bytes().as_slice());

                        socket.send_to(&key_packet, src)?;

                        // Send ACK
                        socket.send_to(&[MSG_ACK], src)?;
                        println!("🤝 Sent ACK");

                        break;
                    }
                }
                _ => {}
            }
        }

        let shared_key = derive_shared_key(my_secret, &peer_pub.unwrap());

        println!("🔐 Secure session established!");
        println!("💬 Chat started! Type message or /exit");

        network::start_chat(
            socket.try_clone()?,
            peer_addr.unwrap(),
            shared_key,
            identity.ed25519_secret.clone(),
            peer_ed25519.unwrap(),
        );

        println!("🔚 Session ended. Returning to listening...");
    }
}

fn get_arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|x| x == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}