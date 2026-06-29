//! A queued file transfer (download or upload) and its progress.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TransferId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Download, // remote -> local
    Upload,   // local -> remote
}

#[derive(Debug, Clone)]
pub struct TransferJob {
    pub id: TransferId,
    pub direction: TransferDirection,
    pub local_path: String,
    pub remote_path: String,
    /// Total size in bytes, if known before the transfer starts.
    pub bytes_total: Option<u64>,
}
