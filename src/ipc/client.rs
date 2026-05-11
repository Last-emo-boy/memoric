//! Named Pipe Client for Worker mode (High IL)
//! This connects to the Proxy's Named Pipe Server

use crate::error::{MemoricError, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_SHARE_MODE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::SetNamedPipeHandleState;

pub use super::server::PIPE_NAME;

// ERROR_MORE_DATA = 234 (Win32), HRESULT = 0x800700EA = -2147024662 (i32)
const ERROR_MORE_DATA_HRESULT: i32 = -2147024662;

/// Named Pipe Client for Worker mode
pub struct PipeClient {
    handle: HANDLE,
}

impl PipeClient {
    /// Connect to the Named Pipe server (Proxy side)
    pub fn connect() -> Result<Self> {
        unsafe {
            let pipe_name: Vec<u16> = format!("{}\0", PIPE_NAME).encode_utf16().collect();

            let desired_access = FILE_READ_DATA.0
                | FILE_WRITE_DATA.0
                | FILE_READ_ATTRIBUTES.0
                | FILE_WRITE_ATTRIBUTES.0
                | 0x00100000; // SYNCHRONIZE

            tracing::info!("Connecting to Named Pipe: {}", PIPE_NAME);

            let handle = CreateFileW(
                windows::core::PCWSTR(pipe_name.as_ptr()),
                desired_access,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
            .map_err(|e| MemoricError::IpcError(format!("Failed to connect to pipe: {}", e)))?;

            if handle == INVALID_HANDLE_VALUE {
                return Err(MemoricError::IpcError("Invalid pipe handle".to_string()));
            }

            // Set pipe to message-read mode so message boundaries are preserved
            let mut mode = windows::Win32::System::Pipes::PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(handle, Some(&mut mode), None, None).map_err(|e| {
                let _ = CloseHandle(handle);
                MemoricError::IpcError(format!("Failed to set pipe to message mode: {}", e))
            })?;

            tracing::info!("Connected to Named Pipe successfully (message mode)");

            Ok(Self { handle })
        }
    }

    /// Read a complete message from the pipe.
    pub fn read_message(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(65536);
        let mut chunk = [0u8; 65536];

        loop {
            unsafe {
                let mut bytes_read = 0u32;
                match ReadFile(self.handle, Some(&mut chunk), Some(&mut bytes_read), None) {
                    Ok(_) => {
                        buffer.extend_from_slice(&chunk[..bytes_read as usize]);
                        tracing::debug!(
                            "read_message: Ok, bytes_read={}, total={}",
                            bytes_read,
                            buffer.len()
                        );
                        // In message mode, Ok means full message was read in this chunk
                        break;
                    }
                    Err(e) => {
                        let code = e.code().0;
                        tracing::debug!(
                            "read_message: Err hr=0x{:08X} ({}), bytes_read={}",
                            code as u32,
                            code,
                            bytes_read
                        );
                        if code == ERROR_MORE_DATA_HRESULT {
                            // Message is larger than chunk buffer — accumulate and keep reading
                            buffer.extend_from_slice(&chunk[..bytes_read as usize]);
                            tracing::debug!(
                                "read_message: ERROR_MORE_DATA, accumulated={}",
                                buffer.len()
                            );
                            continue;
                        }
                        return Err(MemoricError::IpcError(format!(
                            "Read error (hr=0x{:08X}): {}",
                            code as u32, e
                        )));
                    }
                }
            }
        }

        tracing::debug!("Received {} bytes from pipe", buffer.len());
        Ok(buffer)
    }

    /// Write a message to the pipe
    pub fn write_message(&self, data: &[u8]) -> Result<()> {
        unsafe {
            let mut total_written = 0usize;
            while total_written < data.len() {
                let mut bytes_written = 0u32;
                WriteFile(
                    self.handle,
                    Some(&data[total_written..]),
                    Some(&mut bytes_written),
                    None,
                )
                .map_err(|e| MemoricError::IpcError(format!("Write error: {}", e)))?;
                total_written += bytes_written as usize;
            }
            tracing::debug!("Wrote {} bytes to pipe", total_written);
        }
        Ok(())
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
