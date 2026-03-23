// src/handshake.rs

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeInit {
    pub eph_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub session_id: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeResp {
    pub eph_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub session_id: Vec<u8>,
}