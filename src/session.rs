// src/session.rs

use std::collections::HashMap;

#[derive(Clone)]
pub struct Session {
    pub session_id: Vec<u8>,
    pub shared_key: [u8; 32],
    pub peer_identity: Vec<u8>,
}

pub struct SessionManager {
    pub sessions: HashMap<Vec<u8>, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn add_session(&mut self, session: Session) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    pub fn get_session(&self, session_id: &Vec<u8>) -> Option<&Session> {
        self.sessions.get(session_id)
    }
}