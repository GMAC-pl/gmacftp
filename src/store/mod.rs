//! Persistent storage: an encrypted private vault for secrets (no macOS Keychain prompt),
//! config-dir JSON for connection metadata. The Keychain is kept only as a one-time
//! migration source inside [`MigratingStore`].

pub mod cloud;
pub mod creds;
pub mod connections;
pub mod memory;
pub mod settings;
pub mod vault;
#[cfg(target_os = "macos")]
pub mod keychain;

pub use connections::{load_filezilla, load_metadata, load_seed, save_metadata, ImportError};
pub use creds::{CredentialError, CredentialStore, SERVICE_PREFIX};
pub use memory::InMemoryStore;
pub use vault::{FileVault, MigratingStore};
#[cfg(target_os = "macos")]
pub use keychain::MacCredentialStore;

/// The credential store to use: the encrypted private vault with lazy Keychain migration,
/// so reads are silent (no macOS prompt) once a credential is in the vault.
pub fn default_store() -> MigratingStore {
    MigratingStore::new()
}
