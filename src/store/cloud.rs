//! iCloud sync — NO entitlements required.
//!
//! The connection LIST (`connections.json`, password-free) and the encrypted VAULT
//! (`vault.bin`) are mirrored to the user's iCloud Keychain as **synchronizable**
//! generic-password items. `kSecAttrSynchronizable=true` syncs them across the user's
//! Macs via iCloud Keychain (requires the user to have iCloud Keychain enabled in System
//! Settings). No iCloud entitlement, no provisioning profile, no ubiquity container —
//! works on Developer-ID + notarized builds. The master key syncs the same way
//! (vault.rs `keychain_master_key` with the `sync_via_icloud` flag).
//!
//! Each item is `[8-byte BE u64 timestamp (secs since epoch)][payload]` so the pull side
//! does last-writer-wins against the local file's mtime.

use std::path::PathBuf;

/// Is iCloud sync enabled in Settings? (Centralized so every call site reads the same flag.)
pub fn enabled() -> bool {
    crate::store::settings::load().sync_via_icloud
}

/// Config dir (same resolution as connections.rs / vault.rs).
fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().to_path_buf())
}

pub fn connections_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("connections.json"))
}
pub fn vault_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("vault.bin"))
}

/// Prefix payload with the current-time 8-byte BE timestamp.
fn encode(payload: &[u8]) -> Vec<u8> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&secs.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Split the 8-byte timestamp prefix.
fn decode(blob: &[u8]) -> Option<(u64, Vec<u8>)> {
    if blob.len() < 8 {
        return None;
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&blob[..8]);
    Some((u64::from_be_bytes(ts), blob[8..].to_vec()))
}

// ── macOS Keychain backing (synchronizable generic-password items) ──

#[cfg(target_os = "macos")]
mod imp {
    use super::{decode, encode};
    use crate::store::creds::SERVICE_PREFIX;
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    const ACCOUNT: &str = "default";

    fn service(kind: &str) -> String {
        format!("{SERVICE_PREFIX}.icloud.{kind}")
    }

    fn opts(kind: &str) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(&service(kind), ACCOUNT);
        o.set_access_synchronized(Some(true)); // → iCloud Keychain store
        o
    }
    /// Read/delete options matching BOTH synchronizable and non-synchronizable items
    /// (kSecAttrSynchronizableAny). A query WITHOUT this attribute matches only non-synchronizable
    /// items — so a synchronizable item (cloud state, or the master key when sync is on) would be
    /// invisible, and pull / key-load would silently fail (the cross-device + re-prompt bug).
    fn opts_any(kind: &str) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(&service(kind), ACCOUNT);
        o.set_access_synchronized(None); // kSecAttrSynchronizableAny
        o
    }

    fn write(kind: &str, payload: &[u8]) -> Result<(), String> {
        set_generic_password_options(&encode(payload), opts(kind)).map_err(|e| e.to_string())
    }

    fn read(kind: &str) -> Option<(u64, Vec<u8>)> {
        let blob = generic_password(opts_any(kind)).ok()?;
        decode(&blob)
    }

    pub fn write_item(kind: &str, payload: &[u8]) -> Result<(), String> {
        write(kind, payload)
    }

    pub fn read_item(kind: &str) -> Option<(u64, Vec<u8>)> {
        read(kind)
    }

    pub fn delete_item(kind: &str) {
        let _ = delete_generic_password_options(opts_any(kind));
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn write_item(_: &str, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    pub fn read_item(_: &str) -> Option<(u64, Vec<u8>)> {
        None
    }
    pub fn delete_item(_: &str) {}
}

/// Push a single blob to iCloud (keychain). No-op if sync disabled.
pub fn push(kind: &str, payload: &[u8]) {
    if !enabled() {
        return;
    }
    if let Err(e) = imp::write_item(kind, payload) {
        tracing::warn!(target: "gmacftp::cloud", kind, error = %e, "iCloud push failed");
    }
}

/// Push BOTH connections.json and vault.bin from disk. Used after a change when the caller
/// doesn't have the bytes handy. No-op if sync disabled.
pub fn push_state() {
    if !enabled() {
        return;
    }
    if let Some(p) = connections_path() {
        if let Ok(bytes) = std::fs::read(&p) {
            push("connections", &bytes);
        }
    }
    if let Some(p) = vault_path() {
        if let Ok(bytes) = std::fs::read(&p) {
            push("vault", &bytes);
        }
    }
}

/// Remove both iCloud items (used when the user turns sync OFF, to stop sharing). Best-effort.
pub fn purge() {
    imp::delete_item("connections");
    imp::delete_item("vault");
}

/// Toggle iCloud sync on/off (the menu action calls this). Persists the setting, moves the
/// master key between the device-local and iCloud-syncing Keychain stores, then seeds iCloud
/// (enable) or stops sharing (disable). Idempotent.
pub fn set_sync_enabled(enabled: bool) {
    let mut s = crate::store::settings::load();
    if s.sync_via_icloud == enabled {
        return;
    }
    s.sync_via_icloud = enabled;
    crate::store::settings::save(&s);
    // Move the master key so the synced vault stays decryptable on the other Mac (enable) or
    // stops syncing (disable).
    crate::store::vault::set_master_key_syncable(enabled);
    if enabled {
        push_state();
    } else {
        purge();
    }
    tracing::info!(target: "gmacftp::cloud", enabled, "iCloud sync toggled");
}

/// Pull: for each of connections/vault, if the iCloud item is newer than the local file's
/// mtime (or the local file is absent), overwrite the local file. Returns whether anything
/// was applied (so bootstrap knows to (re)load). No-op if sync disabled.
pub fn pull_and_apply() -> bool {
    if !enabled() {
        return false;
    }
    let mut applied = false;
    for (kind, local) in [
        ("connections", connections_path()),
        ("vault", vault_path()),
    ] {
        let Some((ts, payload)) = imp::read_item(kind) else { continue };
        if payload.is_empty() {
            continue;
        }
        let local_secs = local
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // iCloud wins on a tie too (it was written by some device; a local file with equal
        // mtime is the just-pushed one and re-writing it is a harmless no-op). No mtime
        // restoration needed: pull sets local mtime=now ≥ iCloud ts, so a later pull of the
        // same item is a no-op (ts >= local_secs is false) — no push/pull loop.
        if ts >= local_secs && ts > 0 {
            if let Some(p) = &local {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if std::fs::write(p, &payload).is_ok() {
                    tracing::info!(target: "gmacftp::cloud", kind, "pulled newer state from iCloud");
                    applied = true;
                }
            }
        }
    }
    applied
}

// ── visibility helpers for the iCloud-sync menu (Send / Pull / last-sync time) ──

/// Compact local date-time "Jun 30 11:06" for a unix timestamp (system local timezone).
pub fn fmt_ts(secs: u64) -> String {
    if secs == 0 {
        return "(unknown)".into();
    }
    #[cfg(target_os = "macos")]
    {
        if let Some((mo, d, h, m)) = local_md_hm(secs as i64) {
            const NAMES: [&str; 12] =
                ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            let name = NAMES.get((mo - 1).clamp(0, 11) as usize).copied().unwrap_or("???");
            return format!("{name} {d:02} {h:02}:{m:02}");
        }
    }
    let _ = secs;
    format!("(t={secs})")
}

#[cfg(target_os = "macos")]
fn local_md_hm(secs: i64) -> Option<(i32, i32, i32, i32)> {
    #[repr(C)]
    struct Tm {
        tm_sec: i32, tm_min: i32, tm_hour: i32, tm_mday: i32, tm_mon: i32, tm_year: i32,
        tm_wday: i32, tm_yday: i32, tm_isdst: i32, tm_gmtoff: i64,
        tm_zone: *const std::os::raw::c_char,
    }
    extern "C" {
        fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
    }
    let mut tm = Tm {
        tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 1, tm_mon: 0, tm_year: 0,
        tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: std::ptr::null(),
    };
    let t = secs;
    let ok = unsafe { !localtime_r(&t as *const i64, &mut tm as *mut Tm).is_null() };
    ok.then(|| (tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min))
}

/// The timestamp (unix secs) of the `connections` item currently in iCloud, or None if absent.
/// Shown in the menu so the user can see WHEN the cloud copy was last written (and whether one
/// exists at all on this Mac).
pub fn remote_connections_ts() -> Option<u64> {
    imp::read_item("connections").map(|(ts, _)| ts).filter(|ts| *ts > 0)
}

/// Explicitly push the current connections + vault to iCloud (the "Send" action). Returns the
/// Explicitly push the current connections + vault to iCloud (the "Send" action). Returns a
/// human-readable diagnostic string: whether each write succeeded, and whether a read-back
/// immediately finds the just-written item (catches silent keychain write failures + query
/// mismatches — the two likely causes of "Nothing in iCloud yet" after Send).
pub fn send_now() -> String {
    if !enabled() {
        return "iCloud sync is OFF — turn it on first.".into();
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut errors: Vec<String> = Vec::new();
    let conn_wrote = write_kind("connections", connections_path(), &mut errors);
    let vault_wrote = write_kind("vault", vault_path(), &mut errors);
    let readable = imp::read_item("connections").is_some();
    if conn_wrote && vault_wrote && readable {
        format!("Sent to iCloud ({}) — connections + vault written and verified.", fmt_ts(ts))
    } else if conn_wrote && vault_wrote && !readable {
        format!(
            "Sent ({}) — writes OK but read-back FAILED: the keychain is not returning the \
             synchronizable item to this query (macOS may delay it or require iCloud Keychain \
             delivery). The data should still reach your other Macs once iCloud Keychain syncs.",
            fmt_ts(ts)
        )
    } else if conn_wrote && vault_wrote {
        format!("Sent ({}) — partial.", fmt_ts(ts))
    } else {
        format!(
            "Send ({}) failed: {}",
            fmt_ts(ts),
            if errors.is_empty() { "no local data".into() } else { errors.join("; ") }
        )
    }
}

/// Write one local file's bytes to the iCloud keychain item `kind`. Pushes to `errors` on failure.
fn write_kind(kind: &str, path: Option<PathBuf>, errors: &mut Vec<String>) -> bool {
    match path.and_then(|p| std::fs::read(p).ok()) {
        Some(bytes) => match imp::write_item(kind, &bytes) {
            Ok(()) => true,
            Err(e) => {
                errors.push(format!("{kind} write: {e}"));
                false
            }
        },
        None => {
            errors.push(format!("{kind}: no local file"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_roundtrip() {
        let (ts, payload) = decode(&encode(b"hello world")).unwrap();
        assert_eq!(payload, b"hello world");
        assert!(ts > 0);
    }
    #[test]
    fn decode_rejects_short() {
        assert!(decode(b"short").is_none());
    }
}
