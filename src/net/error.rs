//! Network errors unified across FTP (suppaftp) and SFTP (russh).

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("FTP error: {0}")]
    Ftp(String),
    #[error("SFTP/SSH error: {0}")]
    Ssh(String),
    #[error("host key verification failed: {0}")]
    HostKey(String),
    #[error("authentication failed for {0}")]
    AuthFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("background task failed: {0}")]
    Join(String),
    #[error("missing credential")]
    MissingCredential,
    #[error("unsafe path: {0}")]
    InvalidPath(String),
    #[error("transfer cancelled")]
    Cancelled,
}

impl NetError {
    pub(crate) fn from_ftp(e: suppaftp::FtpError) -> Self {
        NetError::Ftp(e.to_string())
    }
}
