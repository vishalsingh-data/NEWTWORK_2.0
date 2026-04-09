// src/bin/newtwork.rs

use crossterm::{
    cursor,
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use newtwork_prototype_2::root_identity::RootIdentity;
use newtwork_prototype_2::identity::Identity;
use newtwork_prototype_2::crypto::derive_shared_key;
use newtwork_prototype_2::network::start_chat;

use std::io::{self, Write};
use std::net::UdpSocket;
use x25519_dalek::PublicKey;
use ed25519_dalek::VerifyingKey;

const MSG_KEY: u8 = 1;
const MSG_ACK: u8 = 2;

// ── Banner ────────────────────────────────────────────────────────────────────

fn print_banner(stdout: &mut io::Stdout) -> io::Result<()> {
    execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    queue!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print(
            r#"
  ███╗   ██╗███████╗██╗    ██╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
  ████╗  ██║██╔════╝██║    ██║╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
  ██╔██╗ ██║█████╗  ██║ █╗ ██║   ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
  ██║╚██╗██║██╔══╝  ██║███╗██║   ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
  ██║ ╚████║███████╗╚███╔███╔╝   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
  ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝    ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
"#
        ),
    )?;
    queue!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::White),
        Print("  Identity-Based Encrypted Routing  //  Handler-Asset Communication Layer\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  version  "),
        SetForegroundColor(Color::Cyan),
        Print("0.1.0-prototype\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n\n"),
        ResetColor,
    )?;
    stdout.flush()?;
    Ok(())
}

// ── Identity cards ────────────────────────────────────────────────────────────

fn print_first_time_identity(stdout: &mut io::Stdout, identity: &RootIdentity) -> io::Result<()> {
    queue!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("\n  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::Cyan),
        Print("  ROOT IDENTITY ESTABLISHED\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  root-id  "),
        SetForegroundColor(Color::White),
        Print(format!("{}\n", identity.id)),
        SetForegroundColor(Color::DarkGrey),
        Print("  status   "),
        SetForegroundColor(Color::Green),
        Print("ACTIVE"),
        SetForegroundColor(Color::DarkGrey),
        Print("  //  ephemeral  //  cryptographically bound to this session key\n"),
        Print("\n  This identity is your permanent root anchor.\n"),
        Print("  Operational identities layered on top will be assigned per-asset.\n"),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        ResetColor,
    )?;
    stdout.flush()?;
    Ok(())
}

fn print_returning_identity(stdout: &mut io::Stdout, identity: &RootIdentity) -> io::Result<()> {
    queue!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("\n  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::Cyan),
        Print("  IDENTITY UNLOCKED\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  root-id  "),
        SetForegroundColor(Color::White),
        Print(format!("{}\n", identity.id)),
        SetForegroundColor(Color::DarkGrey),
        Print("  status   "),
        SetForegroundColor(Color::Green),
        Print("ACTIVE"),
        SetForegroundColor(Color::DarkGrey),
        Print("  //  session key verified\n"),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        ResetColor,
    )?;
    stdout.flush()?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn prompt(label: &str) -> String {
    let mut stdout = io::stdout();
    queue!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print(format!("\n  {} ", label)),
        ResetColor,
    )
    .ok();
    stdout.flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

fn print_divider(stdout: &mut io::Stdout, title: &str) {
    queue!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("\n  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::Cyan),
        Print(format!("  {}\n", title)),
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        ResetColor,
    )
    .ok();
    io::stdout().flush().ok();
}

fn print_menu(stdout: &mut io::Stdout) -> io::Result<()> {
    queue!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("\n  ─────────────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::Cyan),
        Print("  MAIN MENU\n"),
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
    )?;
    let options = [
        ("1", "Listen for incoming connection", "(receiver / asset)"),
        ("2", "Connect to a peer             ", "(sender  / handler)"),
        ("3", "Exit                          ", ""),
    ];
    for (key, label, hint) in &options {
        queue!(
            stdout,
            SetForegroundColor(Color::Cyan),
            Print(format!("  [{}]  ", key)),
            SetForegroundColor(Color::White),
            Print(format!("{}", label)),
            SetForegroundColor(Color::DarkGrey),
            Print(format!("  {}\n", hint)),
        )?;
    }
    queue!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("  ─────────────────────────────────────────────────────────────────────────────\n"),
        ResetColor,
    )?;
    stdout.flush()?;
    Ok(())
}

// ── Status line ───────────────────────────────────────────────────────────────

fn status(stdout: &mut io::Stdout, color: Color, msg: &str) {
    queue!(
        stdout,
        SetForegroundColor(color),
        Print(format!("  {}\n", msg)),
        ResetColor,
    )
    .ok();
    stdout.flush().ok();
}

// ── Listen mode (receiver) ────────────────────────────────────────────────────

fn run_listen_mode(stdout: &mut io::Stdout) {
    print_divider(stdout, "LISTEN MODE  //  waiting for incoming connection");

    let port_input = prompt("Your listen port  [default: 8000] →");
    let port = if port_input.is_empty() { "8000".to_string() } else { port_input };

    let my_addr = format!("127.0.0.1:{}", port);
    status(stdout, Color::DarkGrey, &format!("Binding to {} ...", my_addr));

    let socket = match UdpSocket::bind(&my_addr) {
        Ok(s) => s,
        Err(e) => {
            status(stdout, Color::Red, &format!("Failed to bind: {}", e));
            return;
        }
    };
    socket.set_nonblocking(false).ok();

    // outer loop — after /exit, come back here and wait again
    loop {
        status(stdout, Color::Yellow, "Waiting for incoming connection ...");

        let mut identity = Identity::new();
        let my_secret = identity.x25519_secret.take().expect("secret taken");
        let my_public = identity.x25519_public;
        let mut buf = [0u8; 1024];
        let mut peer_pub: Option<PublicKey> = None;
        let mut peer_ed25519: Option<VerifyingKey> = None;
        let mut peer_addr_str: Option<String> = None;

        // handshake loop
        loop {
            let (size, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => { status(stdout, Color::Red, &format!("Recv error: {}", e)); return; }
            };

            if buf[0] == MSG_KEY && size == 65 {
                status(stdout, Color::DarkGrey, &format!("Incoming handshake from {}", src));

                let x25519_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
                let ed25519_bytes: [u8; 32] = buf[33..65].try_into().unwrap();
                peer_pub = Some(PublicKey::from(x25519_bytes));
                peer_ed25519 = Some(VerifyingKey::from_bytes(&ed25519_bytes).unwrap());
                peer_addr_str = Some(src.to_string());

                let mut key_packet = vec![MSG_KEY];
                key_packet.extend_from_slice(my_public.as_bytes());
                key_packet.extend_from_slice(identity.ed25519_public.to_bytes().as_slice());
                socket.send_to(&key_packet, src).ok();
                socket.send_to(&[MSG_ACK], src).ok();

                status(stdout, Color::Green, "Handshake complete  //  secure session established");
                break;
            }
        }

        let shared_key = derive_shared_key(my_secret, &peer_pub.unwrap());

        print_divider(stdout, "SESSION ACTIVE  //  type a message  //  /exit to end");

        start_chat(
            socket.try_clone().expect("clone failed"),
            peer_addr_str.unwrap(),
            shared_key,
            identity.ed25519_secret.clone(),
            peer_ed25519.unwrap(),
        );

        print_divider(stdout, "SESSION ENDED  //  returning to listen ...");
    }
}

// ── Connect mode (sender) ─────────────────────────────────────────────────────

fn run_connect_mode(stdout: &mut io::Stdout) {
    print_divider(stdout, "CONNECT MODE  //  initiating secure handshake");

    let my_port_input = prompt("Your local port   [default: 8001] →");
    let my_port = if my_port_input.is_empty() { "8001".to_string() } else { my_port_input };

    let peer_ip_input = prompt("Peer IP address   [default: 127.0.0.1] →");
    let peer_ip = if peer_ip_input.is_empty() { "127.0.0.1".to_string() } else { peer_ip_input };

    let peer_port_input = prompt("Peer port         [default: 8000] →");
    let peer_port = if peer_port_input.is_empty() { "8000".to_string() } else { peer_port_input };

    let my_addr = format!("127.0.0.1:{}", my_port);
    let peer_addr = format!("{}:{}", peer_ip, peer_port);

    status(stdout, Color::DarkGrey, &format!("Connecting {} → {} ...", my_addr, peer_addr));

    let socket = match UdpSocket::bind(&my_addr) {
        Ok(s) => s,
        Err(e) => {
            status(stdout, Color::Red, &format!("Failed to bind: {}", e));
            return;
        }
    };
    socket.set_nonblocking(false).ok();

    let mut identity = Identity::new();
    let my_secret = identity.x25519_secret.take().expect("secret taken");
    let my_public = identity.x25519_public;
    let mut buf = [0u8; 1024];
    let mut peer_pub: Option<PublicKey> = None;
    let mut peer_ed25519: Option<VerifyingKey> = None;
    let mut got_ack = false;

    status(stdout, Color::Yellow, "Performing handshake ...");

    // handshake loop — mirrors main.rs run_sender exactly
    loop {
        let mut key_packet = vec![MSG_KEY];
        key_packet.extend_from_slice(my_public.as_bytes());
        key_packet.extend_from_slice(identity.ed25519_public.to_bytes().as_slice());
        socket.send_to(&key_packet, &peer_addr).ok();

        let (size, _) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => { status(stdout, Color::Red, &format!("Recv error: {}", e)); return; }
        };

        match buf[0] {
            MSG_KEY => {
                if size == 65 {
                    let x25519_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
                    let ed25519_bytes: [u8; 32] = buf[33..65].try_into().unwrap();
                    peer_pub = Some(PublicKey::from(x25519_bytes));
                    peer_ed25519 = Some(VerifyingKey::from_bytes(&ed25519_bytes).unwrap());
                }
            }
            MSG_ACK => { got_ack = true; }
            _ => {}
        }

        if peer_pub.is_some() {
            socket.send_to(&[MSG_ACK], &peer_addr).ok();
        }

        if peer_pub.is_some() && peer_ed25519.is_some() && got_ack {
            break;
        }
    }

    status(stdout, Color::Green, "Handshake complete  //  secure session established");

    let shared_key = derive_shared_key(my_secret, &peer_pub.unwrap());

    print_divider(stdout, "SESSION ACTIVE  //  type a message  //  /exit to end");

    start_chat(
        socket,
        peer_addr,
        shared_key,
        identity.ed25519_secret.clone(),
        peer_ed25519.unwrap(),
    );

    print_divider(stdout, "SESSION ENDED");
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let mut stdout = io::stdout();
    let is_first_time = !std::path::Path::new("root_id.json").exists();

    print_banner(&mut stdout).expect("Failed to render banner");

    if is_first_time {
        println!("  First run detected. Setting up your root identity.\n");
        println!("  Enter a password to secure your root identity:");
    } else {
        println!("  Enter your password to unlock your root identity:");
    }

    let identity = RootIdentity::load_or_create();

    if is_first_time {
        print_first_time_identity(&mut stdout, &identity).expect("Failed to render identity");
        println!("  Your root identity has been saved.\n");
    } else {
        print_returning_identity(&mut stdout, &identity).expect("Failed to render identity");
        println!("  Welcome back.\n");
    }

    loop {
        print_menu(&mut stdout).expect("Failed to render menu");
        let choice = prompt("Select an option →");

        match choice.as_str() {
            "1" => run_listen_mode(&mut stdout),
            "2" => run_connect_mode(&mut stdout),
            "3" | "q" | "exit" => {
                status(&mut stdout, Color::DarkGrey, "\n  Session closed. Identity secured.\n");
                break;
            }
            _ => status(&mut stdout, Color::Red, "Invalid option. Enter 1, 2, or 3."),
        }
    }
}