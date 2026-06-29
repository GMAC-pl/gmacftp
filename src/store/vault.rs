//! Private encrypted credential vault. FTP/SFTP passwords live in an AES-256-GCM
//! encrypted file under the app's config dir — NOT in the macOS Keychain — so the
//! "gmacFTP wants to use confidential data in your keychain" prompt never appears.
//!
//! ## Master key storage (CRYP-1, fixed)
//! The 32-byte AES key is stored in the **macOS Keychain** as a generic-password item
//! (`security-framework` `set_generic_password_options`), NOT as a plaintext file next to
//! the ciphertext. This gives hardware-backed (Secure Enclave keybag) at-rest protection
//! and ACL binding to the app signature, instead of a world-readable-on-disk key.
//!
//! On upgrade, a legacy plaintext `master.key` is read once, pushed to the Keychain, and
//! shredded off disk. If Keychain access is refused (or the build is non-macOS), the key
//! falls back to the file so the app keeps working — the file path is an emergency
//! fallback, never the primary store.
//!
//! Layout (config dir = `…/app.mackftp.client/`):
//!   vault.bin   — nonce(12) ‖ AES-256-GCM(json), written atomically (ciphertext only — safe on disk)
//!   master.key  — EMERGENCY FALLBACK ONLY; absent on macOS once migrated to the Keychain
//! Keychain item: service = `{MACKFTP_BUNDLE_ID}.master-key`, account = `default`.
//!
//! `MigratingStore` wraps the vault and falls back to the Keychain ONCE per credential
//! (lazy migration), writing through to the vault so the next read is silent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

use super::creds::{CredentialError, CredentialStore};
#[cfg(target_os = "macos")]
use super::keychain::MacCredentialStore;

fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().to_path_buf())
}

/// NUL-separated "host\x00user" — hostnames/usernames never contain NUL.
fn pack_key(host: &str, user: &str) -> String {
    format!("{host}\x00{user}")
}

/// Encrypted at-rest credential store (in-memory decrypted map mirrored to vault.bin).
pub struct FileVault {
    map: Mutex<HashMap<String, String>>, // "host\x00user" -> base64(secret)
    key: [u8; 32], // resolved once at open: Keychain > migrated-from-file > generated
    vault_path: PathBuf,
}

impl FileVault {
    /// Open (or create) the vault. Missing key → generated (into the Keychain); missing/
    /// corrupt vault → empty.
    pub fn open() -> Self {
        let dir = config_dir().unwrap_or_else(|| PathBuf::from("."));
        let _ = std::fs::create_dir_all(&dir);
        let key_path = dir.join("master.key");
        let vault_path = dir.join("vault.bin");

        let key = resolve_master_key(&key_path);
        let map = match std::fs::read(&vault_path) {
            Ok(blob) if blob.len() > 12 => match decrypt(&key, &blob) {
                Ok(plaintext) => match serde_json::from_slice::<HashMap<String, String>>(&plaintext) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "vault parse failed; starting empty");
                        preserve_unreadable(&vault_path);
                        HashMap::new()
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "vault decrypt failed; starting empty");
                    preserve_unreadable(&vault_path);
                    HashMap::new()
                }
            },
            _ => HashMap::new(),
        };
        Self { map: Mutex::new(map), key, vault_path }
    }

    fn persist(&self) {
        // The plaintext JSON of ALL secrets is the most sensitive transient buffer — wipe it.
        let plaintext = {
            let map = match self.map.lock() {
                Ok(m) => m,
                Err(_) => return,
            };
            match serde_json::to_vec(&*map) {
                Ok(v) => Zeroizing::new(v),
                Err(_) => return,
            }
        };
        // Reuse the in-memory key (Keychain-resolved at open) — do NOT re-hit the Keychain
        // or the master.key file on every write.
        match encrypt(&self.key, &plaintext) {
            Ok(blob) => {
                if let Err(e) = atomic_write(&self.vault_path, &blob) {
                    tracing::warn!(error = %e, "vault write failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "vault encrypt failed"),
        }
        // Mirror the updated vault.bin (and connections.json) to iCloud if sync is on.
        crate::store::cloud::push_state();
    }
}

impl CredentialStore for FileVault {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        let key = pack_key(host, user);
        match self.map.lock().expect("vault").get(&key) {
            Some(b64) => B64.decode(b64).map_err(|e| CredentialError::Other(e.to_string())),
            None => Err(CredentialError::NotFound),
        }
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        let b64 = B64.encode(secret);
        self.map
            .lock()
            .expect("vault")
            .insert(pack_key(host, user), b64);
        self.persist();
        Ok(())
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        self.map.lock().expect("vault").remove(&pack_key(host, user));
        self.persist();
        Ok(())
    }
}

/// Vault first; Keychain as a one-time lazy-migration source. After migration the vault
/// holds every credential, so reads are silent (no macOS prompt).
pub struct MigratingStore {
    vault: FileVault,
    #[cfg(target_os = "macos")]
    keychain: MacCredentialStore,
}

impl MigratingStore {
    #[cfg(target_os = "macos")]
    pub fn new() -> Self {
        Self { vault: FileVault::open(), keychain: MacCredentialStore::new() }
    }
    #[cfg(not(target_os = "macos"))]
    pub fn new() -> Self {
        Self { vault: FileVault::open() }
    }
}

impl CredentialStore for MigratingStore {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        if let Ok(b) = self.vault.get(host, user) {
            return Ok(b);
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(b) = self.keychain.get(host, user) {
                let _ = self.vault.set(host, user, &b); // migrate; future reads hit the vault
                tracing::info!(%host, %user, "migrated credential from Keychain to vault");
                return Ok(b);
            }
        }
        let _ = (host, user);
        Err(CredentialError::NotFound)
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        self.vault.set(host, user, secret)
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        let _ = self.vault.delete(host, user);
        #[cfg(target_os = "macos")]
        {
            let _ = self.keychain.delete(host, user);
        }
        Ok(())
    }
}

// ── master-key resolution: Keychain (primary) > legacy file (migrate) > generate ──

/// Resolve the AES master key. Order:
/// 1. Keychain (primary — hardware-backed, not on disk).
/// 2. Legacy plaintext `master.key` (one-time migration: read → push to Keychain → shred).
/// 3. Generate a new key and store it in the Keychain (never written to disk on macOS).
///
/// The macOS Keychain path is skipped (file used directly) on non-macOS or when the
/// Keychain refuses access — the app must keep working.
fn resolve_master_key(key_path: &Path) -> [u8; 32] {
    let sync = crate::store::settings::load().sync_via_icloud;

    #[cfg(target_os = "macos")]
    {
        if let Some(k) = keychain_master_key::load() {
            return k; // already in the Keychain
        }
    }

    // Legacy plaintext file present → migrate it into the Keychain, then shred.
    if let Ok(bytes) = std::fs::read(key_path) {
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            #[cfg(target_os = "macos")]
            {
                match keychain_master_key::store(&k, sync) {
                    Ok(()) => {
                        tracing::info!("migrated master key from plaintext file into Keychain");
                        shred_file(key_path); // CRYP-1: remove plaintext from disk
                        return k;
                    }
                    Err(e) => {
                        // Keychain refused (access denied). Keep the legacy file so the user
                        // doesn't lose their vault, and surface it.
                        tracing::warn!(error = %e, "Keychain store failed; keeping legacy master.key");
                        return k;
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            return k;
        }
    }

    // No key anywhere → generate and store in the Keychain (never hits disk on macOS).
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = keychain_master_key::store(&k, sync) {
            tracing::warn!(error = %e, "Keychain store failed; writing emergency master.key fallback");
            let _ = atomic_write(key_path, &k);
            let _ = set_mode_0600(key_path);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = atomic_write(key_path, &k);
        let _ = set_mode_0600(key_path);
    }
    k
}

/// Best-effort overwrite+unlink. APFS is copy-on-write so this isn't a forensic shred, but
/// removing the plaintext from the live filesystem is the goal.
fn shred_file(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let zeros = vec![0u8; meta.len() as usize];
        let _ = std::fs::write(path, &zeros);
    }
    let _ = std::fs::remove_file(path);
}

// ── macOS Keychain backing for the master key (security-framework) ──

#[cfg(target_os = "macos")]
mod keychain_master_key {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    use crate::store::creds::SERVICE_PREFIX;

    const ACCOUNT: &str = "default";

    fn service() -> String {
        format!("{SERVICE_PREFIX}.master-key")
    }

    /// Store the 32-byte key. `sync=true` writes it as an iCloud-Keychain item (requires the
    /// user to have iCloud Keychain enabled); `sync=false` keeps it device-local.
    pub fn store(key: &[u8], sync: bool) -> Result<(), String> {
        let mut o = PasswordOptions::new_generic_password(&service(), ACCOUNT);
        o.set_access_synchronized(Some(sync)); // kSecAttrSynchronizable
        set_generic_password_options(key, o).map_err(|e| e.to_string())
    }

    /// Load the key. `get_generic_password` builds a query WITHOUT a sync filter, so it
    /// matches the item in either the iCloud-Keychain store or the local login-keychain
    /// store — a toggled `sync_via_icloud` setting therefore still finds the existing key.
    pub fn load() -> Option<[u8; 32]> {
        match get_generic_password(&service(), ACCOUNT) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                Some(k)
            }
            _ => None,
        }
    }

    /// Delete the key (idempotent, both stores). Used if the vault is ever reset.
    #[allow(dead_code)]
    pub fn delete_all() {
        let _ = delete_generic_password(&service(), ACCOUNT);
    }

    /// Move the master key between the device-local and iCloud-syncing Keychain stores — used
    /// when the user toggles Settings.sync_via_icloud. Lossless: load (either store) → delete
    /// both → re-store in the chosen store. No-op if no key exists yet.
    pub fn promote_to_sync(sync: bool) {
        let Some(k) = load() else { return };
        delete_all();
        let _ = store(&k, sync);
    }
}

/// Public entry: move the master key to/from the iCloud-syncing Keychain store.
#[cfg(target_os = "macos")]
pub fn set_master_key_syncable(sync: bool) {
    keychain_master_key::promote_to_sync(sync);
}
#[cfg(not(target_os = "macos"))]
pub fn set_master_key_syncable(_sync: bool) {}

// ── crypto + io helpers ──

/// Stash the unreadable vault aside so the user can recover/re-import before a later `set()`
/// overwrites it. Without this, a corrupt/undecryptable vault silently becomes empty and the
/// next persist destroys the original. Best-effort (read-only fs just loses the convenience).
fn preserve_unreadable(vault_path: &Path) {
    let Some(stem) = vault_path.file_name().and_then(|s| s.to_str()) else { return };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = vault_path.with_file_name(format!("{stem}.corrupt-{secs}"));
    if std::fs::copy(vault_path, &backup).is_ok() {
        tracing::error!(backup = %backup.display(), "vault unreadable — preserved a copy aside");
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher.decrypt(nonce, &blob[12..]).map_err(|e| e.to_string())
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // CRYP-3: pid-suffixed temp name (defeats a pre-planted same-name symlink) + O_EXCL
    // (create_new) + mode 0600 applied AT creation (the secret is never briefly
    // world-readable at 0644), plus fsync so a crash between write and rename can't
    // leave the vault empty.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));

    let write_tmp = || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, data)?;
            set_mode_0600(&tmp)?;
        }
        Ok(())
    };

    if let Err(e) = write_tmp() {
        // A stale temp from a crashed prior run (same pid — rare) blocks create_new; remove
        // it and retry. remove_file on a symlink unlinks the link, NOT its target, so this
        // stays symlink-safe.
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(&tmp);
            write_tmp()?;
        } else {
            return Err(e);
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip_in_temp() {
        // Exercise the crypto helpers directly (the store wraps them; FileVault::open hits
        // the real macOS Keychain on this machine, which we deliberately avoid in unit tests).
        let key = {
            let mut k = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut k);
            k
        };
        let pt = br#"{"a\x00b":"c2VjcmV0"}"#; // {"a\0b":"base64(secret)"}
        let blob = encrypt(&key, pt).unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), pt);
        // tamper → decrypt fails
        let mut bad = blob.clone();
        bad[20] ^= 0xff;
        assert!(decrypt(&key, &bad).is_err());
    }
}
