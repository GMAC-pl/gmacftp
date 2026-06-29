//! In-memory credential store — for unit tests and as a non-macOS fallback.

use std::collections::HashMap;
use std::sync::Mutex;

use super::creds::{CredentialError, CredentialStore};

#[derive(Default)]
pub struct InMemoryStore {
    secrets: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl CredentialStore for InMemoryStore {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        self.secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .get(&(host.to_string(), user.to_string()))
            .cloned()
            .ok_or(CredentialError::NotFound)
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        self.secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .insert((host.to_string(), user.to_string()), secret.to_vec());
        Ok(())
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        self.secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .remove(&(host.to_string(), user.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_delete() {
        let s = InMemoryStore::default();
        assert!(matches!(s.get("h", "u"), Err(CredentialError::NotFound)));
        s.set("h", "u", b"secret").unwrap();
        assert_eq!(s.get("h", "u").unwrap(), b"secret");
        s.delete("h", "u").unwrap();
        assert!(matches!(s.get("h", "u"), Err(CredentialError::NotFound)));
        // idempotent delete
        s.delete("h", "u").unwrap();
    }
}
