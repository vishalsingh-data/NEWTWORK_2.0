use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NewtworkPacket {
    pub version: u8,

    pub source_tag: Vec<u8>,
    pub destination_tag: Vec<u8>,

    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,

    pub ephemeral_pubkey: Vec<u8>,
    pub ed25519_pubkey: Vec<u8>,

    pub fragment_id: u32,
    pub sequence_number: u32,
    pub total_fragments: u32,
    pub is_file: bool,
}