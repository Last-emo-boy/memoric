//! OPSEC cleanup module
//!
//! RAII guards for automatic token reversion, handle cleanup, and memory wipe.
//! Ensures no forensic artifacts linger after sensitive operations.

use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref GLOBAL_GUARD: Mutex<Option<OpsecGuard>> = Mutex::new(None);
}

/// RAII guard that auto-reverts tokens, closes handles, and wipes memory on Drop.
///
/// Usage:
/// ```ignore
/// let guard = OpsecGuard::new();
/// guard.register_handle(process_handle);
/// // ... sensitive operations ...
/// // guard drops here → RevertToSelf + CloseHandle on all registered handles
/// ```
pub struct OpsecGuard {
    handles: Vec<isize>,
    token_reverted: bool,
}

impl OpsecGuard {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            token_reverted: false,
        }
    }

    /// Register a raw handle (as isize) to be auto-closed on Drop
    pub fn register_handle(&mut self, handle: isize) {
        if handle != 0 && handle != -1 {
            self.handles.push(handle);
        }
    }

    /// Register a Windows HANDLE (as *mut c_void) to be auto-closed on Drop
    pub fn register_win_handle(&mut self, handle: *mut std::ffi::c_void) {
        self.register_handle(handle as isize);
    }

    /// Mark that token reversion is needed on Drop
    pub fn mark_token_revert(&mut self) {
        self.token_reverted = true;
    }

    /// Activate as the global guard (replaces any existing)
    pub fn activate(self) {
        if let Ok(mut guard) = GLOBAL_GUARD.lock() {
            *guard = Some(self);
        }
    }

    /// Deactivate and run cleanup immediately
    pub fn deactivate() {
        if let Ok(mut guard) = GLOBAL_GUARD.lock() {
            *guard = None;
        }
    }

    /// Register a handle into the global guard
    pub fn global_register(handle: isize) {
        if let Ok(mut guard) = GLOBAL_GUARD.lock() {
            if let Some(ref mut g) = *guard {
                g.register_handle(handle);
            }
        }
    }
}

impl Default for OpsecGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OpsecGuard {
    fn drop(&mut self) {
        // Revert token first if needed
        if !self.token_reverted {
            unsafe {
                let _ = windows::Win32::Security::RevertToSelf();
            }
        }

        // Close all registered handles
        for &h in &self.handles {
            if h != 0 && h != -1 {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(
                        windows::Win32::Foundation::HANDLE(h as *mut std::ffi::c_void),
                    );
                }
            }
        }

        if !self.handles.is_empty() {
            tracing::debug!("[OPSEC] Cleaned up {} handles", self.handles.len());
        }
    }
}

/// Wipe a memory buffer with DoD 5220.22-M pattern before freeing
pub fn wipe_buffer(buffer: &mut [u8]) {
    // Pass 1: 0x00
    buffer.fill(0x00);
    // Pass 2: 0xFF
    buffer.fill(0xFF);
    // Pass 3: random
    for byte in buffer.iter_mut() {
        *byte = fastrand::u8(..);
    }
    // Pass 4: 0x00 final
    buffer.fill(0x00);
}

/// Wipe and drop a Vec's contents
pub fn wipe_vec<T: Default>(v: &mut Vec<T>) {
    let ptr = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    let size_bytes = cap * std::mem::size_of::<T>();
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, size_bytes);
        slice.fill(0x00);
        for byte in slice.iter_mut() {
            *byte = fastrand::u8(..);
        }
        slice.fill(0x00);
    }
    v.clear();
    // Force deallocation
    let _ = std::mem::take(v);
    // len was already consumed
    let _ = len;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opsec_guard_no_panic_on_drop() {
        let _guard = OpsecGuard::new();
        // Should not panic when dropped
    }

    #[test]
    fn test_register_handle_ignores_null() {
        let mut guard = OpsecGuard::new();
        guard.register_handle(0);
        guard.register_handle(-1);
        assert!(guard.handles.is_empty());
    }

    #[test]
    fn test_wipe_buffer() {
        let mut buf = vec![0x41u8; 64];
        let original = buf.clone();
        wipe_buffer(&mut buf);
        // After wipe, at minimum the final pass is all zeros
        assert!(buf.iter().all(|&b| b == 0), "Buffer not zeroed after wipe");
    }

    #[test]
    fn test_wipe_vec() {
        let mut v: Vec<u8> = vec![0x41; 128];
        wipe_vec(&mut v);
        assert!(v.is_empty());
    }
}
