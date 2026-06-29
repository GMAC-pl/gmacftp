//! In-app update check — lightweight, no Sparkle framework.
//!
//! "Check for Updates…" (App menu) queries the GitHub Releases API for the latest release,
//! compares the version, and if newer, downloads the notarized DMG to ~/Downloads and opens it
//! in Finder (the user drags gmacFTP to Applications — the standard DMG install). This is
//! "update directly from the app" without embedding/signing a 3rd-party framework. Pure Rust
//! (`ureq`) + the system `open` command to mount the DMG.

use std::io::Read;
use std::path::{Path, PathBuf};

/// The GitHub repo that hosts releases (also where the app pulls its source + updates from).
const REPO: &str = "GMAC-pl/gmacftp";
/// The running build's version (e.g. "0.0.2"), baked in at compile time.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A newer release found on GitHub (None if the running build is current or newer).
#[derive(Debug, Clone)]
pub struct LatestUpdate {
    /// Version without the leading "v" (e.g. "0.0.3").
    pub version: String,
    /// Direct .dmg download URL.
    pub dmg_url: String,
    /// Human-readable release notes (the release body).
    pub notes: String,
}

/// Query GitHub for the latest release; return it only if it's strictly newer than this build.
pub fn check() -> Result<Option<LatestUpdate>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body: serde_json::Value = ureq::get(&url)
        .set("User-Agent", "gmacFTP-updater")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GitHub request failed: {e}"))?
        .into_json()
        .map_err(|e| format!("invalid response: {e}"))?;

    let tag = body.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
    let version = tag.trim_start_matches('v').to_string();
    if version.is_empty() {
        return Err("no tag_name in latest release".into());
    }
    if !is_newer(&version, CURRENT) {
        return Ok(None);
    }
    let dmg_url = body
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|a| {
                let name = a.get("name")?.as_str()?;
                let url = a.get("browser_download_url")?.as_str()?;
                name.ends_with(".dmg").then(|| url.to_string())
            })
        })
        .ok_or_else(|| "no .dmg asset in latest release".to_string())?;
    let notes = body
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(Some(LatestUpdate { version, dmg_url, notes }))
}

/// True iff `latest` (e.g. "0.0.3") is strictly newer than `current` (e.g. "0.0.2").
/// Compares the first three numeric dot-segments; non-numeric segments count as 0.
pub fn is_newer(latest: &str, current: &str) -> bool {
    parse_semver(latest) > parse_semver(current)
}
fn parse_semver(v: &str) -> (u32, u32, u32) {
    // Each dot-segment contributes its leading run of digits ("3-beta" -> 3, "0" -> 0).
    let nums: Vec<u32> = v
        .split('.')
        .map(|seg| {
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u32>().unwrap_or(0)
        })
        .collect();
    (*nums.first().unwrap_or(&0), *nums.get(1).unwrap_or(&0), *nums.get(2).unwrap_or(&0))
}

/// Download `dmg_url` into ~/Downloads/gmacFTP-<version>.dmg. Returns the local path.
pub fn download(url: &str, version: &str) -> Result<PathBuf, String> {
    let dir = directories::UserDirs::new()
        .and_then(|d| d.download_dir()?.canonicalize().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let path = dir.join(format!("gmacFTP-{version}.dmg"));
    let resp = ureq::get(url)
        .set("User-Agent", "gmacFTP-updater")
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    let mut reader = resp.into_reader();
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read failed: {e}"))?;
    std::fs::write(&path, &bytes).map_err(|e| format!("write failed: {e}"))?;
    Ok(path)
}

/// Open `path` with the default handler (Finder mounts a .dmg → shows the install window).
pub fn open_in_finder(path: &Path) {
    let _ = std::process::Command::new("open").arg(path).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_detection() {
        assert!(is_newer("0.0.3", "0.0.2"));
        assert!(is_newer("0.1.0", "0.0.99"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.0.2", "0.0.2"));
        assert!(!is_newer("0.0.1", "0.0.2"));
    }

    #[test]
    fn non_numeric_segments_are_zero() {
        assert!(is_newer("0.0.3-beta", "0.0.2"));
        assert!(!is_newer("x.y.z", "0.0.0"));
    }
}
