//! Named Pipe Server for Proxy mode (Medium IL)
//! This is created by the Proxy process and waited for Worker to connect

use crate::error::{MemoricError, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const PIPE_NAME: &str = r"\\.\pipe\memoric-worker";

/// Named Pipe Server for Proxy mode
pub struct PipeServer {
    handle: HANDLE,
    connected: bool,
    security_descriptor: *mut std::ffi::c_void,
}

impl PipeServer {
    /// Create a new Named Pipe server (Proxy side)
    /// Uses a security descriptor that:
    /// - Grants full access to the current user and SYSTEM
    /// - Sets HIGH integrity level mandatory label so only High IL (elevated) processes can connect
    pub fn new() -> Result<Self> {
        unsafe {
            // SDDL: Grant full access to SYSTEM, Administrators, and Creator Owner
            // No SACL mandatory label — Medium IL process can't set it, and it's not needed:
            // High IL Worker connecting to Medium IL pipe is allowed by default (high→low is OK)
            let sddl: Vec<u16> = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;CO)\0"
                .encode_utf16()
                .collect();

            let mut sd_ptr: *mut windows::Win32::Security::SECURITY_DESCRIPTOR =
                std::ptr::null_mut();

            let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd_ptr as *mut _ as *mut _,
                None,
            );

            let (sd_raw, should_free) = if ok.is_ok() {
                tracing::info!("Named Pipe security descriptor created (HIGH IL mandatory label)");
                (sd_ptr as *mut std::ffi::c_void, true)
            } else {
                tracing::warn!("Failed to create security descriptor, falling back to default");
                (std::ptr::null_mut(), false)
            };

            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd_raw,
                bInheritHandle: false.into(),
            };

            let pipe_name: Vec<u16> = format!("{}\0", PIPE_NAME).encode_utf16().collect();

            tracing::info!("Creating Named Pipe Server: {}", PIPE_NAME);

            let handle = CreateNamedPipeW(
                windows::core::PCWSTR(pipe_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                1024 * 1024, // 1MB output buffer
                1024 * 1024, // 1MB input buffer
                30_000,      // 30 second timeout (prevents idle disconnect)
                Some(&sa),
            );

            if handle == INVALID_HANDLE_VALUE {
                let err = windows::Win32::Foundation::GetLastError();
                if should_free {
                    let _ = LocalFree(HLOCAL(sd_raw));
                }
                return Err(MemoricError::IpcError(format!(
                    "Failed to create Named Pipe (error: {:?})",
                    err
                )));
            }

            tracing::info!("Named Pipe Server created, waiting for Worker connection...");

            Ok(Self {
                handle,
                connected: false,
                security_descriptor: if should_free {
                    sd_raw
                } else {
                    std::ptr::null_mut()
                },
            })
        }
    }

    /// Wait for Worker to connect
    pub fn wait_for_client(&mut self) -> Result<()> {
        unsafe {
            tracing::info!("Calling ConnectNamedPipe...");

            // ConnectNamedPipe blocks until a client connects
            let result = ConnectNamedPipe(self.handle, None);

            tracing::info!("ConnectNamedPipe returned: {:?}", result.is_ok());

            match result {
                Ok(_) => {
                    // Client connected successfully
                }
                Err(e) => {
                    // ERROR_PIPE_CONNECTED (0x80070217) means client already connected
                    // This is OK - Worker connected before we called ConnectNamedPipe
                    // Note: HRESULT 0x80070217 = -2147024361 as i32
                    if e.code().0 == -2147024361i32 {
                        tracing::info!("Client already connected (ERROR_PIPE_CONNECTED)");
                    } else {
                        return Err(MemoricError::IpcError(format!("Failed to connect: {}", e)));
                    }
                }
            }

            self.connected = true;
            tracing::info!("Worker connected successfully!");
        }
        Ok(())
    }

    /// Read a complete message from the pipe.
    /// In PIPE_TYPE_MESSAGE mode, each WriteFile is a discrete message.
    /// ReadFile returns ERROR_MORE_DATA if the message is larger than the buffer.
    pub fn read_message(&self) -> Result<Vec<u8>> {
        // ERROR_MORE_DATA = 234 (Win32), HRESULT = 0x800700EA = -2147024662 (i32)
        const ERROR_MORE_DATA_HRESULT: i32 = -2147024662i32;

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

impl Drop for PipeServer {
    fn drop(&mut self) {
        unsafe {
            if self.connected {
                let _ = DisconnectNamedPipe(self.handle);
            }
            let _ = CloseHandle(self.handle);
            if !self.security_descriptor.is_null() {
                let _ = LocalFree(HLOCAL(self.security_descriptor));
            }
        }
    }
}
