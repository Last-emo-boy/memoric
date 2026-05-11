//! Error types for memoric

use thiserror::Error;

/// Main error type for memoric
#[derive(Error, Debug)]
pub enum MemoricError {
    #[error("Windows API error: {0}")]
    WindowsApi(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    #[error("Memory access error: {0}")]
    MemoryAccess(String),

    #[error("Injection failed: {0}")]
    InjectionFailed(String),

    #[error("Hook failed: {0}")]
    HookFailed(String),

    #[error("IPC error: {0}")]
    IpcError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MemoricError>;

impl From<&str> for MemoricError {
    fn from(s: &str) -> Self {
        MemoricError::WindowsApi(s.to_string())
    }
}

impl From<String> for MemoricError {
    fn from(s: String) -> Self {
        MemoricError::WindowsApi(s)
    }
}
