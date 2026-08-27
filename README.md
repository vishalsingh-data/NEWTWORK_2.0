# NEWTWORK 2.0

> *"What if your messages left no trace — not even of who sent them?"*

---

I started this project because I got tired of reading about cryptography and wanted to actually **build** something with it. Not a CTF challenge. Not a tutorial clone. Something that asked a real question:

**What does secure communication look like if you strip away every static identifier?**

No usernames. No persistent keys. No account. Just math, a terminal, and a message that disappears the moment it arrives.

This is that experiment.

---

## What is NEWTWORK?

NEWTWORK is a peer-to-peer encrypted chat tool that runs entirely in your terminal. There's no server in the middle. No account to create. No app to install. You run it, two people connect directly, keys are negotiated on the spot, messages are encrypted end-to-end, and when the session ends — those keys are gone forever.

It's not trying to replace Signal or WhatsApp. It's trying to answer the question: *how does this actually work under the hood?*

Every version of NEWTWORK is a step deeper into that question.

### The Prototype 1 problem

The first version (`NEWTWORK_PROTOTYPE_1`) could send **one encrypted message** from one terminal to another and then both sides would shut down. You had to manually copy a key file between terminals. It was clunky, one-directional, and you had to restart everything for every single message.

But it proved the idea worked.

### What 2.0 fixes

NEWTWORK 2.0 turns that into an actual **chat session**:

- Both sides can type and receive at the same time
- Keys are exchanged automatically — no file copying
- You get a **root identity** (password-protected) that persists across sessions
- The receiver automatically waits for the next connection after a session ends
- Works from a single command: `cargo run --bin newtwork`

---

## How the security actually works

Here's the short version of what's happening under the hood every time two nodes connect:

**1. Fresh keys, every time.**
When you start a session, the program generates a brand new X25519 keypair and Ed25519 keypair. These keys exist only in memory. They're never saved to disk. The moment the session ends, they're gone.

**2. Key exchange without a server.**
Both sides send each other their public keys directly over the wire. Using X25519 Diffie-Hellman, they each independently compute the same shared secret — without ever transmitting that secret. A SHA-256 hash of that shared secret becomes the encryption key.

**3. Every message is encrypted AND signed.**
Messages are encrypted with ChaCha20-Poly1305 (an AEAD cipher — it detects tampering). Then the `nonce + ciphertext` is signed with Ed25519. If even one bit of the packet is changed in transit, the signature verification fails and the message is dropped.

**4. What an attacker sees.**
If someone captures your UDP packet they get:
- Random-looking encrypted bytes
- A nonce
- A signature
- Two public keys (which are useless without the corresponding private keys)

No message content. No identity. No reusable credentials. And since the keys are ephemeral, capturing old packets doesn't help them decrypt future ones either — that's **Perfect Forward Secrecy**.

---

## The stack

```
Language:       Rust (edition 2021)
Transport:      UDP (on the same machine or LAN)
Key Exchange:   X25519 (ECDH)
Encryption:     ChaCha20-Poly1305 (AEAD)
Signing:        Ed25519
Key Derivation: SHA-256
TUI:            crossterm
Identity:       128-bit random root ID, password-protected (SHA-256 for now)
```

---

## Getting started

### Prerequisites

- [Rust](https://rustup.rs/) installed (`rustup`, `cargo`, `rustc`)
- Two terminal windows (on the same machine, or two devices on the same network)
- That's it. No external services, no config files, no setup scripts.

### Clone and build

```bash
git clone https://github.com/your-username/NEWTWORK_2.0.git
cd NEWTWORK_2.0
cargo build --bin newtwork
```

Or just let cargo compile on the first run:

```bash
cargo run --bin newtwork
```

---

## Running it — the full walkthrough

You need **two terminal windows** open. They can be on the same machine (different tabs/panes), two computers on the same LAN, or even a computer and an Android phone running Termux.

---

### Terminal A — the receiver

Open your first terminal and navigate to the project directory:

```bash
cd NEWTWORK_2.0
cargo run --bin newtwork
```

The first time you run it, you'll be asked to set a password. This creates your **root identity** — a persistent ID saved to `root_id.json`. Every time after that, you enter this password to unlock.

Once you're past the identity screen, you'll see the main menu:

```
  [1]  Listen for incoming connection   (receiver / asset)
  [2]  Connect to a peer                (sender  / handler)
  [3]  Exit
```

Press **`1`** and hit enter. It'll ask for a port (just hit enter for the default `8000`).

Terminal A is now listening. It will sit there waiting for an incoming connection.

---

### Terminal B — the sender

Open a second terminal window in the same project directory:

```bash
cd NEWTWORK_2.0
cargo run --bin newtwork
```

Enter your password. From the menu, press **`2`** (connect to a peer).

It'll ask:
- **Your local port** — press enter for default (`8001`)
- **Peer IP address** — press enter for default (`127.0.0.1`) if both terminals are on the same machine
- **Peer port** — type `8000` (whatever Terminal A is listening on)

The handshake happens automatically. You'll see both terminals confirm:

```
  Handshake complete  //  secure session established
```

---

### Chatting

Both terminals are now in a live encrypted session. Type a message in either one and hit enter — it appears on the other side.

```
# Terminal B types:
hey, is this actually encrypted?

# Terminal A sees:
Peer: hey, is this actually encrypted?
```

```
# Terminal A replies:
yes — ChaCha20-Poly1305 + Ed25519 signed. the key lives in RAM only.

# Terminal B sees:
Peer: yes — ChaCha20-Poly1305 + Ed25519 signed. the key lives in RAM only.
```

Type `/exit` in either terminal to end the session. The receiver side automatically goes back to waiting for the next connection — you don't have to restart anything.

---

## What it looks like (desktop)

> <img width="665" height="741" alt="image" src="https://github.com/user-attachments/assets/fa169738-6e42-4bb4-b531-6de792117089" />


&nbsp;

> *[Screenshot — Terminal B: connect mode, entering peer details]*

&nbsp;

> *[Screenshot — both terminals side by side, active chat session]*

&nbsp;

---

## Running on Android (Termux)

One of the things I wanted to test was whether this could work on a phone. The answer is yes — Termux on Android runs Rust just fine.

### Setup on Termux

```bash
# Update packages
pkg update && pkg upgrade

# Install Rust
pkg install rust

# Install git
pkg install git

# Clone the project
git clone https://github.com/your-username/NEWTWORK_2.0.git
cd NEWTWORK_2.0

# Run it
cargo run --bin newtwork
```

> The first `cargo build` on Termux takes a while — Rust is compiling everything from scratch on your phone's CPU. Be patient. After the first build, incremental builds are fast.

### Connecting phone ↔ desktop (LAN)

To connect a phone and a desktop on the same Wi-Fi network:

1. Find your desktop's local IP: `ipconfig` (Windows) or `ip a` (Linux/Mac)
2. On the desktop — run in **listen mode**, set a port (e.g., `8000`)
3. On the phone (Termux) — run in **connect mode**, enter the desktop's local IP and port `8000`

> **Known limitation:** Cross-device connections over LAN are currently blocked by a bug where the sender socket binds to `127.0.0.1` regardless of the peer IP you enter. This is being fixed in the next version. For now, both terminals need to be on the same machine.

---

## What it looks like on Termux

> *[Screenshot — Termux on Android: running `cargo run --bin newtwork`]*

&nbsp;

> *[Screenshot — Termux: identity unlock screen + main menu]*

&nbsp;

> *[Screenshot — phone and desktop in active session (side by side photo)]*

&nbsp;

---

## Project structure (for the curious)

```
NEWTWORK_2.0/
├── Cargo.toml                  # dependencies
├── root_id.json                # your root identity (auto-created, don't share this)
└── src/
    ├── bin/
    │   └── newtwork.rs         # the actual binary — TUI, menu, handshake, session flow
    ├── crypto.rs               # encrypt_and_sign, decrypt_and_verify, key derivation
    ├── identity.rs             # ephemeral keypair generation (fresh every session)
    ├── network.rs              # the chat engine — two threads, send + receive loop
    ├── root_identity/
    │   └── mod.rs              # password-protected persistent root ID
    ├── packet.rs               # NewtworkPacket struct (planned full packet format)
    ├── handshake.rs            # HandshakeInit/Resp structs (planned typed handshake)
    ├── session.rs              # Session + SessionManager (multi-session, planned)
    └── logger.rs               # structured logging (Info/Warn/Error/Security)
```

The `packet.rs`, `handshake.rs`, and `session.rs` files contain structs I've designed for future versions — message fragmentation, file transfer, and multi-session management. They compile fine, they're just not hooked into the main flow yet.

---

## Limitations (being honest)

This is a prototype. Here's what it can't do yet:

- **No cross-device support yet** — the sender socket binds to localhost. This will be fixed.
- **No TCP** — UDP works, but messages can technically be dropped. Switching to TCP is planned.
- **Password hashing is SHA-256** — no salt, no key stretching. Argon2 is coming.
- **No message history** — sessions are fully ephemeral. Nothing is logged.
- **No peer discovery** — you have to know and type the IP manually.
- **No group chat** — it's 1-to-1 right now. The session architecture is being designed with groups in mind though.
- **No anonymity layer** — both peers can see each other's IP addresses. This is a direct connection, not an onion network.

---

## What's next

The things I'm actively thinking about for the next version:

- Fix the binding bug and enable real LAN + Termux connections
- Switch from UDP to TCP for reliable message delivery
- Upgrade password hashing to Argon2id
- Wire up the `NewtworkPacket` struct for a proper, extensible packet format
- Add message timestamps
- Design multi-peer session support

---

## Why "NEWTWORK"?

It's a typo that stuck. Started as "NETWORK" but became its own thing. Felt right for a project that's questioning what a network should be — or what it could look like if you rebuilt the assumptions from scratch.

---

## Disclaimer

This is a learning project. It is **not audited**, **not production-ready**, and **not meant for protecting sensitive real-world communications**. If you need that, use Signal.

This exists to learn, question, and experiment.

---

*— built by a cybersecurity student who got tired of reading about crypto and decided to write it instead.*
