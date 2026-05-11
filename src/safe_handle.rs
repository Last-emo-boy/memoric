//! RAII wrappers for Windows handles to prevent resource leaks
//!
//! SafeHandle wraps HANDLE and calls CloseHandle on drop.
//! SafeRegKey wraps HKEY and calls RegCloseKey on drop.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Registry::HKEY;

/// RAII wrapper for Windows HANDLE. Calls CloseHandle on drop.
pub struct SafeHandle(HANDLE);

impl SafeHandle {
    /// Create a new SafeHandle from a raw HANDLE.
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    /// Get the raw HANDLE value without consuming the wrapper.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

impl std::ops::Deref for SafeHandle {
    type Target = HANDLE;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<HANDLE> for SafeHandle {
    fn as_ref(&self) -> &HANDLE {
        &self.0
    }
}

impl From<HANDLE> for SafeHandle {
    fn from(handle: HANDLE) -> Self {
        Self(handle)
    }
}

/// RAII wrapper for Windows HKEY. Calls RegCloseKey on drop.
pub struct SafeRegKey(HKEY);

impl SafeRegKey {
    /// Create a new SafeRegKey from a raw HKEY.
    pub fn new(key: HKEY) -> Self {
        Self(key)
    }

    /// Get the raw HKEY value without consuming the wrapper.
    pub fn raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for SafeRegKey {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = windows::Win32::System::Registry::RegCloseKey(self.0);
            }
        }
    }
}

impl std::ops::Deref for SafeRegKey {
    type Target = HKEY;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<HKEY> for SafeRegKey {
    fn as_ref(&self) -> &HKEY {
        &self.0
    }
}

impl From<HKEY> for SafeRegKey {
    fn from(key: HKEY) -> Self {
        Self(key)
    }
}
