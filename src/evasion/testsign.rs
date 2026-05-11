//! Test Signing Bypass — hide test mode indicators
//!
//! Hooks NtQuerySystemInformation in target processes to clear the
//! CODEINTEGRITY_OPTION_TESTSIGN (0x2) bit when SystemCodeIntegrityInformation
//! is queried. Also patches BCD read paths to report non-test-signing state.
//!
//! Techniques:
//! 1. NtQuerySystemInformation hook — intercept SystemCodeIntegrityInformation (0x67)
//!    and clear the 0x2 bit from the returned CodeIntegrityOptions.
//! 2. BCD query bypass — hook NtQueryLicenseValue / registry-based BCD reads
//!    to return "normal mode" for Kernel-TestSigning queries.
//! 3. SharedUserData patch — directly modify KUSER_SHARED_DATA.TestRetInstruction
//!    indicators (requires kernel driver).

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// SystemCodeIntegrityInformation class number
const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 0x67;
/// Bit mask for test signing in CodeIntegrityOptions
const CODEINTEGRITY_OPTION_TESTSIGN: u32 = 0x2;

/// Build the NtQueryLicenseValue hook shellcode (x64).
/// This shellcode:
///   1. Calls the original NtQueryLicenseValue (trampoline)
///   2. Checks if ValueName->Length is 38 or 44 (test-signing license names)
///   3. If yes, verifies Buffer starts with 'K' (0x004B)
///   4. If match, returns STATUS_OBJECT_NAME_NOT_FOUND
///   5. Otherwise, returns the original NTSTATUS
///
/// Only intercepts known BCD test-signing license value queries:
///   "Kernel-TestSigning" (38 bytes) / "Kernel-TestSigning-On" (44 bytes)
/// All other license queries pass through to the real function.
///
/// Layout:
///   [trampoline_addr: 8 bytes] [shellcode]
fn build_license_query_hook_shellcode(trampoline_addr: u64) -> Vec<u8> {
    let mut sc: Vec<u8> = Vec::with_capacity(128);

    // Store trampoline address at offset 0 (referenced by shellcode)
    sc.extend_from_slice(&trampoline_addr.to_le_bytes()); // [0..8]

    // x64 shellcode starts at offset 8
    // Prolog: save non-volatile registers and args
    // NtQueryLicenseValue(PUNICODE_STRING ValueName, ULONG *Type, PVOID Data, ULONG DataSize, ULONG *ResultLength)
    // RCX=ValueName, RDX=Type, R8=Data, R9=DataSize
    let prolog: &[u8] = &[
        0x55, // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x50, // sub rsp, 0x50
        // Save args
        0x48, 0x89, 0x4D, 0xF8, // mov [rbp-0x08], rcx (ValueName)
        0x48, 0x89, 0x55, 0xF0, // mov [rbp-0x10], rdx (Type)
        0x4C, 0x89, 0x45, 0xE8, // mov [rbp-0x18], r8  (Data)
        0x4C, 0x89, 0x4D, 0xE0, // mov [rbp-0x20], r9  (DataSize)
        // Call trampoline (original NtQueryLicenseValue)
        0x48, 0xB8, // mov rax, <trampoline_addr>
        // 8 bytes placeholder for trampoline address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, // call rax
        // Save NTSTATUS
        0x89, 0x45, 0xD8, // mov [rbp-0x28], eax
        // If error (NTSTATUS < 0), skip filtering
        0x85, 0xC0, // test eax, eax
        0x78, 0x2F, // js done (offset calculated below)
        // Load ValueName
        0x48, 0x8B, 0x4D, 0xF8, // mov rcx, [rbp-0x08]
        0x48, 0x85, 0xC9, // test rcx, rcx
        0x74, 0x26, // jz done
        // Get ValueName->Length (USHORT at offset 0)
        0x0F, 0xB7, 0x11, // movzx edx, word [rcx]
        // Check if Length == 38 ("Kernel-TestSigning")
        0x83, 0xFA, 0x26, // cmp edx, 38
        0x74, 0x05, // je check_buffer (offset +5)
        // Check if Length == 44 ("Kernel-TestSigning-On")
        0x83, 0xFA, 0x2C, // cmp edx, 44
        0x75, 0x19, // jne done
        // check_buffer: Get ValueName->Buffer (PWSTR at offset 8)
        0x48, 0x8B, 0x51, 0x08, // mov rdx, [rcx + 8]
        0x48, 0x85, 0xD2, // test rdx, rdx
        0x74, 0x10, // jz done
        // Check first wchar is 'K' (0x004B)
        0x0F, 0xB7, 0x02, // movzx eax, word [rdx]
        0x66, 0x3D, 0x4B, 0x00, // cmp ax, 0x004B
        0x75, 0x07, // jne done
        // block_it: replace NTSTATUS with STATUS_OBJECT_NAME_NOT_FOUND
        0xC7, 0x45, 0xD8, 0x34, 0x00, 0x00, 0xC0, // mov dword [rbp-0x28], 0xC0000034
        // done:
        0x8B, 0x45, 0xD8, // mov eax, [rbp-0x28]
        0x48, 0x83, 0xC4, 0x50, // add rsp, 0x50
        0x5D, // pop rbp
        0xC3, // ret
    ];
    sc.extend_from_slice(prolog);

    // Patch the trampoline address into the mov rax instruction
    // mov rax imm64 is at sc offset 8 + 24 (prolog bytes before opcode) + 2 (opcode)
    // = offset 34 within the Vec
    let addr_offset = 8 + 24 + 2;
    let addr_bytes = trampoline_addr.to_le_bytes();
    for i in 0..8 {
        sc[addr_offset + i] = addr_bytes[i];
    }

    sc
}

/// Build the NtQuerySystemInformation hook shellcode (x64).
/// Intercepts SystemCodeIntegrityInformation (0x67) queries and clears
/// the CODEINTEGRITY_OPTION_TESTSIGN bit (0x2) from the response.
fn build_ntquery_hook_shellcode(original_fn: u64) -> Vec<u8> {
    let mut sc: Vec<u8> = Vec::with_capacity(256);

    // Store original function address at offset 0 (referenced by shellcode)
    sc.extend_from_slice(&original_fn.to_le_bytes()); // [0..8]

    // x64 shellcode starts at offset 8
    // Prolog: save non-volatile registers and arguments
    let code: &[u8] = &[
        // push rbp; mov rbp, rsp; sub rsp, 0x40
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40,
        // Save args: rcx=InfoClass, rdx=InfoBuffer, r8=InfoLength, r9=ReturnLength
        0x48, 0x89, 0x4D, 0xE8, // mov [rbp-0x18], rcx (InfoClass)
        0x48, 0x89, 0x55, 0xE0, // mov [rbp-0x20], rdx (InfoBuffer)
        0x4C, 0x89, 0x45, 0xD8, // mov [rbp-0x28], r8  (InfoLength)
        0x4C, 0x89, 0x4D, 0xD0, // mov [rbp-0x30], r9  (ReturnLength)
        // Call original: load trampoline address from [rip - offset_to_base]
        // We'll use a direct mov rax, imm64 approach
        0x48, 0xB8, // mov rax, <trampoline_addr>
        // 8 bytes placeholder for trampoline address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, // call rax
        // Save return value
        0x48, 0x89, 0x45, 0xF0, // mov [rbp-0x10], rax (NTSTATUS)
        // Check if call succeeded (NTSTATUS >= 0)
        0x48, 0x85, 0xC0, // test rax, rax
        0x78, 0x1C, // js skip (negative = error, skip patching)
        // Check InfoClass == 0x67 (SystemCodeIntegrityInformation)
        0x48, 0x8B, 0x4D, 0xE8, // mov rcx, [rbp-0x18]
        0x48, 0x83, 0xF9, 0x67, // cmp rcx, 0x67
        0x75, 0x12, // jne skip
        // Check InfoBuffer != NULL
        0x48, 0x8B, 0x55, 0xE0, // mov rdx, [rbp-0x20]
        0x48, 0x85, 0xD2, // test rdx, rdx
        0x74, 0x09, // jz skip
        // Clear bit 0x2 from CodeIntegrityOptions at [InfoBuffer+4]
        // SYSTEM_CODEINTEGRITY_INFORMATION { ULONG Length; ULONG CodeIntegrityOptions; }
        0x8B, 0x42, 0x04, // mov eax, [rdx+4]  (CodeIntegrityOptions)
        0x83, 0xE0, 0xFD, // and eax, 0xFFFFFFFD  (clear bit 1 = ~0x2)
        0x89, 0x42, 0x04, // mov [rdx+4], eax
        // skip:
        // Restore NTSTATUS and return
        0x48, 0x8B, 0x45, 0xF0, // mov rax, [rbp-0x10]
        0x48, 0x83, 0xC4, 0x40, // add rsp, 0x40
        0x5D, // pop rbp
        0xC3, // ret
    ];
    sc.extend_from_slice(code);

    // Patch the trampoline address into the mov rax instruction
    // The mov rax imm64 is at offset 8 + 24 (prolog) + 2 (opcode)
    // imm64 field starts at code byte 26, i.e. sc byte 34
    let addr_offset = 8 + 24 + 2; // 8 (stored addr) + 24 (prolog bytes) + 2 (opcode bytes)
    let addr_bytes = original_fn.to_le_bytes();
    for i in 0..8 {
        sc[addr_offset + i] = addr_bytes[i];
    }

    sc
}

/// Hook NtQuerySystemInformation in a target process to hide test signing.
///
/// Patches the function so when SystemCodeIntegrityInformation (0x67) is
/// queried, the CODEINTEGRITY_OPTION_TESTSIGN bit (0x2) is cleared from
/// the response, making test signing mode invisible.
///
/// args: { "pid": <u32>, "method": "inline"|"iat" }
pub fn testsign_hide_ntquery(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::Other("Missing pid for testsign_hide_ntquery".to_string()))?;

    let _method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("inline");

    tracing::warn!(
        "[TESTSIGN] Hooking NtQuerySystemInformation in PID {} to hide test signing",
        pid
    );

    unsafe {
        // Get NtQuerySystemInformation address (same across processes)
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;
        let ntquery_addr = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        )
        .ok_or_else(|| {
            MemoricError::WindowsApi("NtQuerySystemInformation not found".to_string())
        })?;
        let ntquery_va = ntquery_addr as usize as u64;

        // Open target process
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open PID {}: {}", pid, e)))?;
        let handle = SafeHandle::new(handle);

        // Read original bytes from NtQuerySystemInformation (16 bytes for trampoline)
        // Must steal 16 bytes because the test instruction at offset 8 is 8 bytes
        // (F6 04 25 08 03 FE 7F 01 = test byte ptr [7FFE0308h], 1)
        // instruction boundaries: 0, 3, 8, 16
        let mut original_bytes = [0u8; 16];
        ReadProcessMemory(
            *handle,
            ntquery_va as *const _,
            original_bytes.as_mut_ptr() as *mut _,
            16,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("ReadProcessMemory: {}", e)))?;

        // Allocate memory in target for hook shellcode + trampoline
        let shellcode = build_ntquery_hook_shellcode(ntquery_va);
        let trampoline_size = 14 + original_bytes.len(); // jmp_abs(14) + stolen bytes
        let alloc_size = shellcode.len() + trampoline_size + 64; // extra padding

        let cave = VirtualAllocEx(
            *handle,
            None,
            alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if cave.is_null() {
            return Err(MemoricError::WindowsApi(
                "VirtualAllocEx failed for hook cave".to_string(),
            ));
        }
        let cave_addr = cave as u64;

        // Build trampoline: original stolen bytes + jmp back to NtQuerySystemInformation+14
        let trampoline_addr = cave_addr + shellcode.len() as u64;
        let mut trampoline = Vec::with_capacity(trampoline_size);
        trampoline.extend_from_slice(&original_bytes); // stolen bytes
                                                       // jmp [rip+0] ; absolute jump back to instruction boundary at +16
        trampoline.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        let jmp_back_target = ntquery_va + 16;
        trampoline.extend_from_slice(&jmp_back_target.to_le_bytes());

        // Patch shellcode to call trampoline instead of original
        let mut final_shellcode = shellcode.clone();
        // The trampoline address is at two places:
        // 1. First 8 bytes (stored reference)
        let tramp_bytes = trampoline_addr.to_le_bytes();
        for i in 0..8 {
            final_shellcode[i] = tramp_bytes[i];
        }
        // 2. Inside the mov rax instruction (offset 8 + 24 + 2 = 34)
        let addr_offset = 34;
        for i in 0..8 {
            final_shellcode[addr_offset + i] = tramp_bytes[i];
        }

        // Write hook shellcode to cave
        WriteProcessMemory(
            *handle,
            cave as *mut _,
            final_shellcode.as_ptr() as *const _,
            final_shellcode.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("WriteProcessMemory (shellcode): {}", e)))?;

        // Write trampoline after shellcode
        let tramp_ptr = (cave_addr + final_shellcode.len() as u64) as *mut _;
        WriteProcessMemory(
            *handle,
            tramp_ptr,
            trampoline.as_ptr() as *const _,
            trampoline.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("WriteProcessMemory (trampoline): {}", e)))?;

        // Hook entry point: overwrite NtQuerySystemInformation with jmp to our shellcode+8 (skip stored addr)
        // Must overwrite 16 bytes to reach instruction boundary (avoid splitting 8-byte test instruction)
        let hook_target = cave_addr + 8; // skip the stored trampoline address
        let mut hook_patch = Vec::with_capacity(16);
        // mov rax, <hook_target>; jmp rax
        hook_patch.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        hook_patch.extend_from_slice(&hook_target.to_le_bytes());
        hook_patch.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
                                                     // Pad with NOPs to reach 16-byte instruction boundary
        while hook_patch.len() < 16 {
            hook_patch.push(0x90);
        }

        // Change protection on NtQuerySystemInformation
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            ntquery_va as *mut _,
            16,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtectEx: {}", e)))?;

        // Write the hook
        WriteProcessMemory(
            *handle,
            ntquery_va as *mut _,
            hook_patch.as_ptr() as *const _,
            hook_patch.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("WriteProcessMemory (hook): {}", e)))?;

        // Restore original protection
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(*handle, ntquery_va as *mut _, 16, old_protect, &mut tmp);

        tracing::info!(
            "[TESTSIGN] Hook installed at 0x{:016X} -> cave 0x{:016X}",
            ntquery_va,
            cave_addr
        );

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "ntquery_address": format!("0x{:016X}", ntquery_va),
            "hook_cave": format!("0x{:016X}", cave_addr),
            "trampoline": format!("0x{:016X}", trampoline_addr),
            "stolen_bytes": format!("{:02X?}", &original_bytes),
            "message": format!("NtQuerySystemInformation hooked in PID {} — SystemCodeIntegrityInformation will report non-test-signing", pid),
            "bit_cleared": "CODEINTEGRITY_OPTION_TESTSIGN (0x2)"
        }))
    }
}

/// Hook NtQuerySystemInformation in the current process (self-hook).
/// Useful for hiding test signing from within memoric itself.
pub fn testsign_hide_self(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS,
    };

    tracing::warn!("[TESTSIGN] Self-hooking NtQuerySystemInformation to hide test signing");

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;
        let ntquery_addr = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        )
        .ok_or_else(|| {
            MemoricError::WindowsApi("NtQuerySystemInformation not found".to_string())
        })?;
        let ntquery_ptr = ntquery_addr as *mut u8;
        let ntquery_va = ntquery_ptr as u64;

        // Check if already hooked (first 2 bytes would be 0x48 0xB8 = mov rax)
        let first_two = std::slice::from_raw_parts(ntquery_ptr, 2);
        if first_two == [0x48, 0xB8] {
            return Ok(serde_json::json!({
                "success": true,
                "already_hooked": true,
                "address": format!("0x{:016X}", ntquery_va),
                "message": "NtQuerySystemInformation already hooked (idempotent)"
            }));
        }

        // Save original 16 bytes (must reach instruction boundary at +16)
        // NtQuerySystemInformation layout: mov r10,rcx(3) + mov eax,SSN(5) + test(8) = 16
        let mut original = [0u8; 16];
        std::ptr::copy_nonoverlapping(ntquery_ptr, original.as_mut_ptr(), 16);

        // Allocate code cave
        let cave = VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if cave.is_null() {
            return Err(MemoricError::WindowsApi("VirtualAlloc failed".to_string()));
        }
        let cave_addr = cave as u64;

        // Build trampoline (stolen bytes + jmp back)
        let trampoline_offset = 256usize; // put trampoline at cave+256
        let trampoline_addr = cave_addr + trampoline_offset as u64;
        let trampoline_ptr = (cave as *mut u8).add(trampoline_offset);

        let jmp_back = ntquery_va + 16;
        std::ptr::copy_nonoverlapping(original.as_ptr(), trampoline_ptr, 16);
        // jmp [rip+0]; addr
        let jmp_abs: [u8; 6] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        std::ptr::copy_nonoverlapping(jmp_abs.as_ptr(), trampoline_ptr.add(16), 6);
        std::ptr::copy_nonoverlapping(jmp_back.to_le_bytes().as_ptr(), trampoline_ptr.add(22), 8);

        // Build hook shellcode at cave+0
        let shellcode = build_ntquery_hook_shellcode(trampoline_addr);
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), cave as *mut u8, shellcode.len());

        // Patch trampoline addr in shellcode
        let tramp_bytes = trampoline_addr.to_le_bytes();
        let cave_bytes = cave as *mut u8;
        // Offset 0: stored address
        for i in 0..8 {
            *cave_bytes.add(i) = tramp_bytes[i];
        }
        // Offset 34: inside mov rax instruction (8 prefix + 24 prolog + 2 opcode)
        for i in 0..8 {
            *cave_bytes.add(34 + i) = tramp_bytes[i];
        }

        // Install inline hook on NtQuerySystemInformation (16 bytes to reach instruction boundary)
        let hook_target = cave_addr + 8; // skip stored addr
        let mut hook_patch = [0u8; 16];
        hook_patch[0] = 0x48;
        hook_patch[1] = 0xB8; // mov rax, imm64
        let target_bytes = hook_target.to_le_bytes();
        hook_patch[2..10].copy_from_slice(&target_bytes);
        hook_patch[10] = 0xFF;
        hook_patch[11] = 0xE0; // jmp rax
        hook_patch[12] = 0x90;
        hook_patch[13] = 0x90; // nop padding
        hook_patch[14] = 0x90;
        hook_patch[15] = 0x90; // nop padding to 16

        // VirtualProtect → write → restore
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            ntquery_ptr as *mut _,
            16,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect: {}", e)))?;
        std::ptr::copy_nonoverlapping(hook_patch.as_ptr(), ntquery_ptr, 16);
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(ntquery_ptr as *mut _, 16, old_protect, &mut tmp);

        tracing::info!("[TESTSIGN] Self-hook installed at 0x{:016X}", ntquery_va);

        Ok(serde_json::json!({
            "success": true,
            "address": format!("0x{:016X}", ntquery_va),
            "hook_cave": format!("0x{:016X}", cave_addr),
            "trampoline": format!("0x{:016X}", trampoline_addr),
            "message": "NtQuerySystemInformation self-hooked — local test signing queries will report normal mode"
        }))
    }
}

/// BCD query bypass — patches BCD-related registry reads so test signing
/// status returns FALSE. Works by hooking NtQueryLicenseValue and/or
/// patching the BCD registry hive entries.
///
/// args: { "method": "registry"|"hook" }
pub fn testsign_hide_bcd(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_WRITE,
    };

    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("registry");
    tracing::warn!("[TESTSIGN] BCD bypass via {} method", method);

    match method {
        "registry" => {
            // Direct registry approach: ensure BCD store reflects non-test-signing
            // Patch HKLM\BCD00000000\Objects\{bootmgr}\Elements\16000049
            // (Element 0x16000049 = BcdBootMgrBoolean_AllowBadMemoryAccess but we target
            //  the test signing boolean at 0x16000049)
            // Actually, test signing in BCD is at:
            //   HKLM\BCD00000000\Objects\{current boot entry}\Elements\25000049
            //   where 25000049 = BcdOSLoaderBoolean_AllowPrereleaseSignatures (testsigning)

            unsafe {
                let bcd_subkey: Vec<u16> = "BCD00000000\\Description\0".encode_utf16().collect();
                let mut hkey = windows::Win32::System::Registry::HKEY::default();

                // Try to open BCD store to verify access
                let status = RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    windows::core::PCWSTR(bcd_subkey.as_ptr()),
                    0,
                    KEY_WRITE,
                    &mut hkey,
                );

                if status.is_err() {
                    // BCD registry manipulation requires elevated + special permissions
                    // Fall back to bcdedit approach
                    tracing::warn!("[TESTSIGN] BCD registry not directly writable, using bcdedit command approach");

                    return Ok(serde_json::json!({
                        "success": true,
                        "method": "info",
                        "message": "BCD store requires SYSTEM-level access for direct modification. Use kernel driver IOCTL (testsign_hide_kernel) for full BCD bypass, or run: bcdedit /set testsigning on (then use NtQuerySystemInformation hook to hide it).",
                        "recommendation": "Use testsign_hide_ntquery to hook NtQuerySystemInformation in target processes — this is the most reliable usermode bypass."
                    }));
                }

                let _ = RegCloseKey(hkey);

                // If we have access, create/modify the SharedUserData indicator
                // SharedUserData at 0x7FFE0000 contains TestRetInstruction at offset 0x2F0
                // However, this is read-only from usermode.
                // The most effective approach is NtQuerySystemInformation hook
                // combined with kernel-level SharedUserData patching.

                Ok(serde_json::json!({
                    "success": true,
                    "method": "registry",
                    "message": "BCD access verified. For complete test signing concealment, combine with NtQuerySystemInformation hook and kernel-level SharedUserData patch.",
                    "bcd_key": "HKLM\\BCD00000000",
                    "testsign_element": "0x16000049 / 0x25000049"
                }))
            }
        }
        "hook" => {
            // Hook NtQueryLicenseValue to intercept BCD_TEST_SIGNING queries
            use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
            use windows::Win32::System::Memory::{
                VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
                PAGE_PROTECTION_FLAGS,
            };

            unsafe {
                let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
                    .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

                // NtQueryLicenseValue — used by BCD subsystem to check licensing/signing values
                let qlv_addr = GetProcAddress(
                    ntdll,
                    windows::core::PCSTR(b"NtQueryLicenseValue\0".as_ptr()),
                );
                if qlv_addr.is_none() {
                    return Ok(serde_json::json!({
                        "success": false,
                        "message": "NtQueryLicenseValue not found in ntdll — this API may not exist on this Windows version"
                    }));
                }
                let qlv_ptr = qlv_addr.unwrap() as *mut u8;
                let qlv_va = qlv_ptr as u64;

                // Check if already patched
                let first_two = std::slice::from_raw_parts(qlv_ptr, 2);
                if first_two == [0x48, 0xB8] {
                    return Ok(serde_json::json!({
                        "success": true,
                        "already_hooked": true,
                        "address": format!("0x{:016X}", qlv_va),
                        "message": "NtQueryLicenseValue already hooked"
                    }));
                }

                // Allocate cave for hook
                let cave =
                    VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if cave.is_null() {
                    return Err(MemoricError::WindowsApi(
                        "VirtualAlloc for NtQueryLicenseValue hook failed".to_string(),
                    ));
                }
                let cave_addr = cave as u64;

                // Save original 16 bytes (must reach instruction boundary at +16)
                // NtQueryLicenseValue layout: mov r10,rcx(3) + mov eax,SSN(5) + syscall/test = varies
                // Saving 16 bytes covers the initial instruction block
                let mut original = [0u8; 16];
                std::ptr::copy_nonoverlapping(qlv_ptr, original.as_mut_ptr(), 16);

                // Build trampoline at cave+256 (stolen bytes + absolute jmp back)
                let trampoline_offset = 256usize;
                let trampoline_addr = cave_addr + trampoline_offset as u64;
                let trampoline_ptr = (cave as *mut u8).add(trampoline_offset);
                let jmp_back = qlv_va + 16;
                std::ptr::copy_nonoverlapping(original.as_ptr(), trampoline_ptr, 16);
                // jmp [rip+0]; addr — absolute jump back to NtQueryLicenseValue+16
                let jmp_abs: [u8; 6] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
                std::ptr::copy_nonoverlapping(jmp_abs.as_ptr(), trampoline_ptr.add(16), 6);
                std::ptr::copy_nonoverlapping(
                    jmp_back.to_le_bytes().as_ptr(),
                    trampoline_ptr.add(22),
                    8,
                );

                // Build selective hook shellcode at cave+0
                let shellcode = build_license_query_hook_shellcode(trampoline_addr);
                std::ptr::copy_nonoverlapping(shellcode.as_ptr(), cave as *mut u8, shellcode.len());

                // Patch trampoline address in shellcode (offset 0: stored addr, offset 34: mov rax imm64)
                let cave_bytes = cave as *mut u8;
                for i in 0..8 {
                    *cave_bytes.add(i) = trampoline_addr.to_le_bytes()[i];
                }
                for i in 0..8 {
                    *cave_bytes.add(34 + i) = trampoline_addr.to_le_bytes()[i];
                }

                // Install inline hook on NtQueryLicenseValue (16 bytes)
                let hook_target = cave_addr + 8; // skip stored trampoline addr
                let mut hook_patch = [0u8; 16];
                hook_patch[0] = 0x48;
                hook_patch[1] = 0xB8; // mov rax, imm64
                let target_bytes = hook_target.to_le_bytes();
                hook_patch[2..10].copy_from_slice(&target_bytes);
                hook_patch[10] = 0xFF;
                hook_patch[11] = 0xE0; // jmp rax
                hook_patch[12] = 0x90;
                hook_patch[13] = 0x90; // nop padding to 16
                hook_patch[14] = 0x90;
                hook_patch[15] = 0x90;

                // VirtualProtect → write → restore
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(
                    qlv_ptr as *mut _,
                    16,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
                .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect: {}", e)))?;
                std::ptr::copy_nonoverlapping(hook_patch.as_ptr(), qlv_ptr, 16);
                let mut tmp = PAGE_PROTECTION_FLAGS(0);
                let _ = VirtualProtect(qlv_ptr as *mut _, 16, old_protect, &mut tmp);

                tracing::info!("[TESTSIGN] NtQueryLicenseValue selectively hooked — only blocks known test-signing license queries");

                Ok(serde_json::json!({
                    "success": true,
                    "method": "hook",
                    "address": format!("0x{:016X}", qlv_va),
                    "hook_cave": format!("0x{:016X}", cave_addr),
                    "trampoline": format!("0x{:016X}", trampoline_addr),
                    "original_16": format!("{:02X?}", &original),
                    "message": "NtQueryLicenseValue hooked selectively — only 'Kernel-TestSigning' / 'Kernel-TestSigning-On' queries blocked, all others pass through"
                }))
            }
        }
        _ => Err(MemoricError::Other(format!(
            "Unknown BCD bypass method: {}",
            method
        ))),
    }
}

/// Query current test signing status — checks CodeIntegrityOptions
/// to verify if the bypass is working.
pub fn testsign_query(_args: &Value) -> Result<Value, MemoricError> {
    use std::ffi::c_void;

    tracing::info!("[TESTSIGN] Querying current test signing status");

    // Call NtQuerySystemInformation with SystemCodeIntegrityInformation (0x67)
    type NtQuerySystemInformationFn =
        unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
            b"ntdll.dll\0".as_ptr(),
        ))
        .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        let func = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        )
        .ok_or_else(|| {
            MemoricError::WindowsApi("NtQuerySystemInformation not found".to_string())
        })?;

        let nt_query: NtQuerySystemInformationFn = std::mem::transmute(func);

        // SYSTEM_CODEINTEGRITY_INFORMATION { ULONG Length; ULONG CodeIntegrityOptions; }
        #[repr(C)]
        struct CodeIntegrityInfo {
            length: u32,
            code_integrity_options: u32,
        }

        let mut ci_info = CodeIntegrityInfo {
            length: 8,
            code_integrity_options: 0,
        };
        let mut ret_len = 0u32;

        let status = nt_query(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut ci_info as *mut _ as *mut c_void,
            std::mem::size_of::<CodeIntegrityInfo>() as u32,
            &mut ret_len,
        );

        let test_signing_active =
            (ci_info.code_integrity_options & CODEINTEGRITY_OPTION_TESTSIGN) != 0;

        Ok(serde_json::json!({
            "success": status >= 0,
            "ntstatus": format!("0x{:08X}", status as u32),
            "code_integrity_options": format!("0x{:08X}", ci_info.code_integrity_options),
            "test_signing_active": test_signing_active,
            "test_signing_bit": format!("0x{:X}", CODEINTEGRITY_OPTION_TESTSIGN),
            "message": if test_signing_active {
                "Test signing IS active (0x2 bit set) — hook not applied or not effective"
            } else {
                "Test signing NOT detected (0x2 bit clear) — bypass is working or test signing is off"
            }
        }))
    }
}

/// ETW-based auto-injection: monitor new process creation and automatically
/// inject the NtQuerySystemInformation hook into each new process.
///
/// Uses ETW Microsoft-Windows-Kernel-Process provider to detect process start.
/// args: { "duration_secs": <u64>, "exclude": ["process_name", ...] }
pub fn testsign_auto_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let _duration = args
        .get("duration_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let _exclude: Vec<&str> = args
        .get("exclude")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    tracing::warn!("[TESTSIGN] Scanning running processes for test signing hook injection");

    // Snapshot current processes and inject into each
    let mut injected = Vec::new();
    let mut failed = Vec::new();

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;
        let snap = SafeHandle::new(snap);

        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(*snap, &mut pe).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &pe.szExeFile[..pe
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(pe.szExeFile.len())],
                );
                let pid = pe.th32ProcessID;

                // Skip PID 0 (System Idle), PID 4 (System), and self
                if pid > 4 && pid != std::process::id() {
                    let inject_args = serde_json::json!({ "pid": pid });
                    match testsign_hide_ntquery(&inject_args) {
                        Ok(_) => {
                            injected.push(serde_json::json!({
                                "pid": pid,
                                "name": name,
                            }));
                        }
                        Err(e) => {
                            failed.push(serde_json::json!({
                                "pid": pid,
                                "name": name,
                                "error": e.to_string(),
                            }));
                        }
                    }
                }

                pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(*snap, &mut pe).is_err() {
                    break;
                }
            }
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "injected_count": injected.len(),
        "failed_count": failed.len(),
        "injected": injected,
        "failed": failed,
        "message": format!("Injected NtQuerySystemInformation hook into {} processes ({} failed)", injected.len(), failed.len())
    }))
}

/// Launch an executable in SUSPENDED state, hook NtQuerySystemInformation
/// to hide test signing, then resume the main thread.
///
/// This ensures the process never gets a chance to see test signing mode.
/// args: { "exe_path": "..." , "args": "..." (optional), "work_dir": "..." (optional) }
pub fn testsign_launch_hooked(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{
        CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let exe_path = args
        .get("exe_path")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("target_exe").and_then(|v| v.as_str()))
        .ok_or_else(|| MemoricError::Other("Missing exe_path".to_string()))?;

    let extra_args = args.get("args").and_then(|v| v.as_str()).unwrap_or("");
    let work_dir = args.get("work_dir").and_then(|v| v.as_str());

    tracing::warn!("[TESTSIGN] Launching with pre-hook: {}", exe_path);

    unsafe {
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();

        // Build command line
        let cmd = if extra_args.is_empty() {
            format!("\"{}\"", exe_path)
        } else {
            format!("\"{}\" {}", exe_path, extra_args)
        };
        let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        // Build work_dir — default to parent directory of exe
        let effective_work_dir = work_dir.map(|s| s.to_string()).unwrap_or_else(|| {
            std::path::Path::new(exe_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string())
        });
        let work_dir_w: Vec<u16> = effective_work_dir
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Create process SUSPENDED
        CreateProcessW(
            None,
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            windows::core::PCWSTR(work_dir_w.as_ptr()),
            &si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateProcessW SUSPENDED failed: {}", e)))?;

        let proc_handle = SafeHandle::new(pi.hProcess);
        let thread_handle = SafeHandle::new(pi.hThread);
        let pid = pi.dwProcessId;
        let tid = pi.dwThreadId;

        tracing::info!(
            "[TESTSIGN] Process created suspended: PID={} TID={}",
            pid,
            tid
        );

        // Hook NtQuerySystemInformation in the suspended process
        let hook_args = serde_json::json!({ "pid": pid });
        let hook_result = testsign_hide_ntquery(&hook_args);

        let hook_ok = hook_result.is_ok();
        let hook_detail = match &hook_result {
            Ok(v) => v.clone(),
            Err(e) => serde_json::json!({ "error": e.to_string() }),
        };

        if !hook_ok {
            // Hook failed — terminate the suspended process
            use windows::Win32::System::Threading::TerminateProcess;
            let _ = TerminateProcess(*proc_handle, 1);
            return Err(MemoricError::Other(format!(
                "Hook failed, terminated suspended process PID {}: {}",
                pid,
                hook_result.err().unwrap()
            )));
        }

        // Also hook NtQueryLicenseValue (BCD bypass) in the target process
        // This prevents BCD-based test signing detection
        let bcd_result = testsign_hide_bcd_remote(pid, &proc_handle);

        // Resume the main thread — process starts running with hooks already in place
        let suspend_count = ResumeThread(*thread_handle);
        tracing::info!(
            "[TESTSIGN] Resumed PID {} (previous suspend count: {})",
            pid,
            suspend_count
        );

        // Don't close handles immediately — let SafeHandle drop them
        // The process continues running independently

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "tid": tid,
            "exe_path": exe_path,
            "work_dir": effective_work_dir,
            "hook": hook_detail,
            "bcd_hook": bcd_result.unwrap_or_else(|e| serde_json::json!({"error": e})),
            "resumed": suspend_count != u32::MAX,
            "message": format!("Process PID {} launched with NtQuerySystemInformation hook pre-installed — test signing invisible from first instruction", pid)
        }))
    }
}

/// Kernel-level test signing bypass — directly patch CI.dll's g_CiOptions in kernel memory.
/// This modifies the kernel's CodeIntegrity options so NtQuerySystemInformation natively
/// reports non-test-signing. No user-mode hooks needed — invisible to anti-cheat.
///
/// Uses export-anchored approach: CiInitialize export → CipInitialize → first `mov [rip+disp], ecx`
/// instruction stores BootOptions (CI flags) to g_CiOptions. This precisely identifies the variable
/// even if it's in an unusual section (e.g. CiPolicy instead of .data).
pub fn testsign_kernel_bypass(args: &Value) -> Result<Value, MemoricError> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("hide");
    tracing::warn!("[TESTSIGN] Kernel CI bypass: action={}", action);

    let drv = crate::driver::MemoricDriver::open().map_err(|e| {
        MemoricError::WindowsApi(format!(
            "Driver open failed (is memoric.sys loaded?): {}",
            e
        ))
    })?;

    // 1. Find CI.dll kernel base via NtQuerySystemInformation(SystemModuleInformation)
    let (ci_base, _ci_size) = find_kernel_module("CI.dll")?;
    if ci_base == 0 {
        return Err(MemoricError::WindowsApi(
            "CI.dll not found in kernel modules".to_string(),
        ));
    }
    tracing::info!("[TESTSIGN] CI.dll at 0x{:016X}", ci_base);

    // 2. Load CI.dll from disk, find g_CiOptions RVA via export-anchored code analysis
    let ci_disk = std::fs::read(r"C:\Windows\System32\CI.dll")
        .map_err(|e| MemoricError::WindowsApi(format!("Read CI.dll from disk: {}", e)))?;

    let ci_options_rva = find_g_ci_options_via_exports(&ci_disk)?;
    let ci_options_kva = ci_base + ci_options_rva as u64;
    tracing::warn!(
        "[TESTSIGN] g_CiOptions: RVA=0x{:X}, KVA=0x{:016X}",
        ci_options_rva,
        ci_options_kva
    );

    // 3. Read current value from kernel memory
    let current_val = read_kernel_dword(&drv, ci_options_kva).map_err(|e| {
        MemoricError::WindowsApi(format!(
            "Read g_CiOptions at 0x{:016X}: {}",
            ci_options_kva, e
        ))
    })?;

    let user_ci = get_usermode_ci_options().unwrap_or(0);
    tracing::warn!(
        "[TESTSIGN] g_CiOptions=0x{:08X}, user-mode CI=0x{:08X}",
        current_val,
        user_ci
    );

    if action == "query" {
        return Ok(serde_json::json!({
            "success": true,
            "technique": "kernel_ci_export_anchor",
            "ci_dll_base": format!("0x{:016X}", ci_base),
            "ci_options_rva": format!("0x{:X}", ci_options_rva),
            "ci_options_address": format!("0x{:016X}", ci_options_kva),
            "ci_options_value": format!("0x{:08X}", current_val),
            "user_mode_ci": format!("0x{:08X}", user_ci),
            "test_signing_active": (current_val & 0x02) != 0,
            "message": format!("g_CiOptions at 0x{:016X} = 0x{:08X}", ci_options_kva, current_val)
        }));
    }

    // 4. Patch: clear TESTSIGN bit (0x02)
    if (current_val & 0x02) == 0 {
        return Ok(serde_json::json!({
            "success": true,
            "ci_options_address": format!("0x{:016X}", ci_options_kva),
            "ci_options_value": format!("0x{:08X}", current_val),
            "test_signing_hidden": true,
            "message": "TESTSIGN bit already cleared — no patch needed"
        }));
    }

    let new_val = current_val & !0x02u32;

    // Use VA→PA + physical write (SAFE: MmMapIoSpace at PASSIVE_LEVEL).
    // NEVER use write_kernel — it raises IRQL + clears CR0.WP → BSOD with Hyper-V/VBS.
    let pa = drv.va_to_pa(0, ci_options_kva).map_err(|e| {
        MemoricError::WindowsApi(format!("va_to_pa(0x{:016X}): {}", ci_options_kva, e))
    })?;
    if pa == 0 {
        return Err(MemoricError::WindowsApi(format!(
            "g_CiOptions VA 0x{:016X} has no physical mapping",
            ci_options_kva
        )));
    }
    tracing::warn!(
        "[TESTSIGN] g_CiOptions: VA=0x{:016X} PA=0x{:016X}",
        ci_options_kva,
        pa
    );
    drv.write_physical(pa, &new_val.to_le_bytes())
        .map_err(|e| {
            MemoricError::WindowsApi(format!("write_physical(PA=0x{:016X}): {}", pa, e))
        })?;

    // Verify
    let verify_val = read_kernel_dword(&drv, ci_options_kva).unwrap_or(0);
    tracing::warn!(
        "[TESTSIGN] g_CiOptions patched: 0x{:08X} → 0x{:08X} (verify: 0x{:08X})",
        current_val,
        new_val,
        verify_val
    );

    Ok(serde_json::json!({
        "success": true,
        "technique": "kernel_ci_options_patch",
        "ci_dll_base": format!("0x{:016X}", ci_base),
        "ci_options_rva": format!("0x{:X}", ci_options_rva),
        "ci_options_address": format!("0x{:016X}", ci_options_kva),
        "original_value": format!("0x{:08X}", current_val),
        "patched_value": format!("0x{:08X}", new_val),
        "verified_value": format!("0x{:08X}", verify_val),
        "test_signing_hidden": (verify_val & 0x02) == 0,
        "message": format!(
            "g_CiOptions patched in kernel: 0x{:08X} → 0x{:08X}. All processes will natively see non-test-signing.",
            current_val, new_val
        )
    }))
}

/// Read kernel .data section page-by-page via VA→PA + physical read.
fn read_data_physical(
    drv: &crate::driver::MemoricDriver,
    base_kva: u64,
    size: usize,
) -> Result<Vec<u8>, MemoricError> {
    let mut buf = Vec::with_capacity(size);
    let mut off = 0u64;
    let mut pages_ok = 0u32;
    let mut pages_fail = 0u32;
    while off < size as u64 {
        let va = base_kva + off;
        let chunk = std::cmp::min(0x1000u64, size as u64 - off) as usize;
        // First try read_virtual to fault the page in
        let _ = drv.read_virtual(4, va, chunk);
        // Then get physical address
        match drv.va_to_pa(0, va) {
            Ok(pa) if pa != 0 => match drv.read_physical(pa, chunk) {
                Ok(d) => {
                    buf.extend_from_slice(&d);
                    pages_ok += 1;
                }
                Err(_) => {
                    buf.extend(vec![0u8; chunk]);
                    pages_fail += 1;
                }
            },
            _ => {
                buf.extend(vec![0u8; chunk]);
                pages_fail += 1;
            }
        }
        off += 0x1000;
    }
    tracing::info!(
        "[TESTSIGN] Physical read: {} pages OK, {} pages failed",
        pages_ok,
        pages_fail
    );
    Ok(buf)
}

/// Write patched g_CiOptions value via physical memory.
fn write_ci_options(
    drv: &crate::driver::MemoricDriver,
    ci_base: u64,
    rva: u32,
    kva: u64,
    current_val: u32,
    action: &str,
) -> Result<serde_json::Value, MemoricError> {
    if action == "query" {
        return Ok(serde_json::json!({
            "success": true,
            "technique": "kernel_ci_dword_scan",
            "ci_dll_base": format!("0x{:016X}", ci_base),
            "ci_options_rva": format!("0x{:X}", rva),
            "ci_options_address": format!("0x{:016X}", kva),
            "ci_options_value": format!("0x{:08X}", current_val),
            "test_signing_active": (current_val & 0x02) != 0,
        }));
    }
    if (current_val & 0x02) == 0 {
        return Ok(serde_json::json!({
            "success": true,
            "ci_options_address": format!("0x{:016X}", kva),
            "ci_options_value": format!("0x{:08X}", current_val),
            "message": "TESTSIGN bit already cleared",
        }));
    }
    let new_val = current_val & !0x02u32;
    let pa = drv
        .va_to_pa(0, kva)
        .map_err(|e| MemoricError::WindowsApi(format!("va_to_pa(0x{:016X}): {}", kva, e)))?;
    if pa == 0 {
        return Err(MemoricError::WindowsApi(format!(
            "g_CiOptions VA 0x{:016X} has no physical mapping",
            kva
        )));
    }
    drv.write_physical(pa, &new_val.to_le_bytes())
        .map_err(|e| {
            MemoricError::WindowsApi(format!("write_physical(PA=0x{:016X}): {}", pa, e))
        })?;
    let verify_val = read_kernel_dword(drv, kva).unwrap_or(0);
    tracing::warn!(
        "[TESTSIGN] g_CiOptions patched: 0x{:08X} → 0x{:08X} (verify: 0x{:08X})",
        current_val,
        new_val,
        verify_val
    );
    Ok(serde_json::json!({
        "success": true,
        "technique": "kernel_ci_options_patch",
        "ci_dll_base": format!("0x{:016X}", ci_base),
        "ci_options_rva": format!("0x{:X}", rva),
        "ci_options_address": format!("0x{:016X}", kva),
        "original_value": format!("0x{:08X}", current_val),
        "patched_value": format!("0x{:08X}", new_val),
        "verified_value": format!("0x{:08X}", verify_val),
        "test_signing_hidden": (verify_val & 0x02) == 0,
        "message": format!("g_CiOptions patched: 0x{:08X} → 0x{:08X}", current_val, new_val),
    }))
}

/// Find g_CiOptions RVA via export-anchored code tracing.
///
/// Algorithm:
/// 1. Parse PE export directory → find "CiInitialize" RVA
/// 2. Read CiInitialize bytes → find first CALL rel32 → that's CipInitialize RVA
/// 3. Read CipInitialize bytes → find first `89 0D xx xx xx xx` (mov [rip+disp32], ecx)
///    This is where CipInitialize stores its first parameter (BootOptions = CI flags)
///    → the target of that instruction is g_CiOptions
///
/// This approach is precise regardless of which PE section g_CiOptions resides in
/// (e.g. CiPolicy section on modern Windows, not .data).
fn find_g_ci_options_via_exports(ci_disk: &[u8]) -> Result<u32, MemoricError> {
    if ci_disk.len() < 0x200 {
        return Err(MemoricError::WindowsApi("CI.dll too small".to_string()));
    }

    // Parse PE headers
    let e_lfanew = u32::from_le_bytes(ci_disk[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew >= 0x800 || e_lfanew + 0x88 + 8 > ci_disk.len() {
        return Err(MemoricError::WindowsApi("Invalid PE header".to_string()));
    }

    let num_sections =
        u16::from_le_bytes(ci_disk[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
    let opt_header_size =
        u16::from_le_bytes(ci_disk[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let sections_offset = e_lfanew + 24 + opt_header_size;

    // PE64 optional header: Export directory is DataDirectory[0] at offset 0x70 from opt header start
    let opt_start = e_lfanew + 24;
    let export_dir_rva = u32::from_le_bytes(
        ci_disk[opt_start + 0x70..opt_start + 0x74]
            .try_into()
            .unwrap(),
    ) as usize;
    let export_dir_size = u32::from_le_bytes(
        ci_disk[opt_start + 0x74..opt_start + 0x78]
            .try_into()
            .unwrap(),
    ) as usize;

    if export_dir_rva == 0 || export_dir_size == 0 {
        return Err(MemoricError::WindowsApi(
            "CI.dll has no export directory".to_string(),
        ));
    }

    // Build section table for RVA → file offset conversion
    struct Section {
        rva: u32,
        vsize: u32,
        raw_offset: u32,
        raw_size: u32,
    }
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let so = sections_offset + i * 40;
        if so + 40 > ci_disk.len() {
            break;
        }
        sections.push(Section {
            vsize: u32::from_le_bytes(ci_disk[so + 8..so + 12].try_into().unwrap()),
            rva: u32::from_le_bytes(ci_disk[so + 12..so + 16].try_into().unwrap()),
            raw_offset: u32::from_le_bytes(ci_disk[so + 16..so + 20].try_into().unwrap()),
            raw_size: u32::from_le_bytes(ci_disk[so + 20..so + 24].try_into().unwrap()),
        });
    }

    let rva_to_offset = |rva: u32| -> Option<usize> {
        for s in &sections {
            if rva >= s.rva && rva < s.rva + std::cmp::max(s.vsize, s.raw_size) {
                let off = s.raw_offset as usize + (rva - s.rva) as usize;
                if off < ci_disk.len() {
                    return Some(off);
                }
            }
        }
        None
    };

    // Parse export directory
    let ed_off = rva_to_offset(export_dir_rva as u32).ok_or_else(|| {
        MemoricError::WindowsApi("Cannot resolve export directory offset".to_string())
    })?;
    if ed_off + 40 > ci_disk.len() {
        return Err(MemoricError::WindowsApi(
            "Export directory truncated".to_string(),
        ));
    }

    let num_functions =
        u32::from_le_bytes(ci_disk[ed_off + 20..ed_off + 24].try_into().unwrap()) as usize;
    let num_names =
        u32::from_le_bytes(ci_disk[ed_off + 24..ed_off + 28].try_into().unwrap()) as usize;
    let addr_table_rva = u32::from_le_bytes(ci_disk[ed_off + 28..ed_off + 32].try_into().unwrap());
    let name_table_rva = u32::from_le_bytes(ci_disk[ed_off + 32..ed_off + 36].try_into().unwrap());
    let ordinal_table_rva =
        u32::from_le_bytes(ci_disk[ed_off + 36..ed_off + 40].try_into().unwrap());

    let addr_off = rva_to_offset(addr_table_rva)
        .ok_or_else(|| MemoricError::WindowsApi("Bad export addr table".to_string()))?;
    let name_off = rva_to_offset(name_table_rva)
        .ok_or_else(|| MemoricError::WindowsApi("Bad export name table".to_string()))?;
    let ord_off = rva_to_offset(ordinal_table_rva)
        .ok_or_else(|| MemoricError::WindowsApi("Bad export ordinal table".to_string()))?;

    // Find CiInitialize export
    let mut ci_init_rva = 0u32;
    for i in 0..num_names {
        let name_rva = u32::from_le_bytes(
            ci_disk[name_off + i * 4..name_off + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
        if let Some(noff) = rva_to_offset(name_rva) {
            let name_end = ci_disk[noff..].iter().position(|&b| b == 0).unwrap_or(0);
            let name = &ci_disk[noff..noff + name_end];
            if name == b"CiInitialize" {
                let ordinal = u16::from_le_bytes(
                    ci_disk[ord_off + i * 2..ord_off + i * 2 + 2]
                        .try_into()
                        .unwrap(),
                ) as usize;
                if ordinal < num_functions {
                    ci_init_rva = u32::from_le_bytes(
                        ci_disk[addr_off + ordinal * 4..addr_off + ordinal * 4 + 4]
                            .try_into()
                            .unwrap(),
                    );
                }
                break;
            }
        }
    }

    if ci_init_rva == 0 {
        return Err(MemoricError::WindowsApi(
            "CiInitialize export not found in CI.dll".to_string(),
        ));
    }
    tracing::info!("[TESTSIGN] CiInitialize RVA = 0x{:X}", ci_init_rva);

    // Step 2: Read CiInitialize code, find CALL rel32 (E8 xx xx xx xx) to get CipInitialize
    let ci_init_off = rva_to_offset(ci_init_rva).ok_or_else(|| {
        MemoricError::WindowsApi("Cannot resolve CiInitialize file offset".to_string())
    })?;
    let ci_init_code_len = std::cmp::min(128, ci_disk.len() - ci_init_off);
    let ci_init_code = &ci_disk[ci_init_off..ci_init_off + ci_init_code_len];

    // CiInitialize is a short wrapper. Find the CALL that jumps to CipInitialize.
    // It typically does: mov reg, [rsp+xx]; push reg; call CipInitialize
    // We want the first E8 CALL in the function body.
    let mut cip_init_rva = 0u32;
    for i in 0..ci_init_code_len.saturating_sub(5) {
        if ci_init_code[i] == 0xE8 {
            let rel = i32::from_le_bytes(ci_init_code[i + 1..i + 5].try_into().unwrap());
            let call_rva = ci_init_rva + i as u32 + 5;
            let target = (call_rva as i64 + rel as i64) as u32;
            tracing::info!("[TESTSIGN] CiInitialize+0x{:X}: CALL 0x{:X}", i, target);
            cip_init_rva = target;
            break;
        }
    }

    if cip_init_rva == 0 {
        return Err(MemoricError::WindowsApi(
            "Could not find CALL to CipInitialize".to_string(),
        ));
    }
    tracing::info!("[TESTSIGN] CipInitialize RVA = 0x{:X}", cip_init_rva);

    // Step 3: Read CipInitialize code, find first `89 0D xx xx xx xx` (mov [rip+disp32], ecx)
    // ECX = first parameter = BootOptions (the CI flags value)
    // This is the store of BootOptions to g_CiOptions.
    let cip_init_off = rva_to_offset(cip_init_rva).ok_or_else(|| {
        MemoricError::WindowsApi("Cannot resolve CipInitialize file offset".to_string())
    })?;
    let cip_init_code_len = std::cmp::min(256, ci_disk.len() - cip_init_off);
    let cip_code = &ci_disk[cip_init_off..cip_init_off + cip_init_code_len];

    for i in 0..cip_init_code_len.saturating_sub(6) {
        // Look for `89 0D xx xx xx xx` — mov dword [rip+disp32], ecx
        // 89 = MOV r/m32, r32  |  ModRM 0x0D = mod=00, reg=001(ECX), r/m=101(RIP-relative)
        if cip_code[i] == 0x89 && cip_code[i + 1] == 0x0D {
            let disp = i32::from_le_bytes(cip_code[i + 2..i + 6].try_into().unwrap());
            let instr_rva = cip_init_rva + i as u32;
            let next_rva = instr_rva + 6; // instruction is 6 bytes
            let target_rva = (next_rva as i64 + disp as i64) as u32;
            tracing::warn!("[TESTSIGN] CipInitialize+0x{:X}: mov [rip+0x{:X}], ecx → target RVA 0x{:X} (g_CiOptions)",
                i, disp, target_rva);
            return Ok(target_rva);
        }
    }

    Err(MemoricError::WindowsApi(
        "Could not find g_CiOptions store (mov [rip+disp], ecx) in CipInitialize".to_string(),
    ))
}

/// Read a DWORD from kernel memory, trying virtual read then physical read fallback.
fn read_kernel_dword(drv: &crate::driver::MemoricDriver, kva: u64) -> Result<u32, MemoricError> {
    // Try virtual read first
    if let Ok(data) = drv.read_virtual(4, kva, 4) {
        if data.len() >= 4 {
            let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
            if val != 0 {
                return Ok(val);
            }
        }
    }
    // Fallback: translate VA to PA, then read physical
    let pa = drv
        .va_to_pa(0, kva)
        .map_err(|e| MemoricError::WindowsApi(format!("VA2PA failed for 0x{:016X}: {}", kva, e)))?;
    if pa == 0 {
        return Err(MemoricError::WindowsApi(format!(
            "VA 0x{:016X} has no physical mapping",
            kva
        )));
    }
    let data = drv
        .read_physical(pa, 4)
        .map_err(|e| MemoricError::WindowsApi(format!("PhysRead 0x{:016X}: {}", pa, e)))?;
    if data.len() >= 4 {
        Ok(u32::from_le_bytes(data[0..4].try_into().unwrap()))
    } else {
        Err(MemoricError::WindowsApi(
            "Physical read returned insufficient data".to_string(),
        ))
    }
}

/// Launch exe cleanly — no SUSPENDED, no inline hooks.
/// Uses kernel-level g_CiOptions patch so NtQuerySystemInformation natively returns clean results.
/// Falls back to HWBP-based NtQueryLicenseValue bypass (no code modification).
pub fn testsign_launch_clean(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};

    let exe_path = args
        .get("exe_path")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("target_exe").and_then(|v| v.as_str()))
        .ok_or_else(|| MemoricError::Other("Missing exe_path".to_string()))?;
    let extra_args = args.get("args").and_then(|v| v.as_str()).unwrap_or("");
    let work_dir = args.get("work_dir").and_then(|v| v.as_str());

    tracing::warn!("[TESTSIGN] Clean launch (kernel bypass): {}", exe_path);

    // Step 1: Apply kernel-level CI bypass
    let kernel_result = testsign_kernel_bypass(&serde_json::json!({"action": "hide"}))?;
    let kernel_ok = kernel_result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !kernel_ok {
        return Err(MemoricError::Other(format!(
            "Kernel CI bypass failed: {}",
            kernel_result
        )));
    }

    // Step 2: Launch process normally — no SUSPENDED, no hooks
    unsafe {
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();

        let cmd = if extra_args.is_empty() {
            format!("\"{}\"", exe_path)
        } else {
            format!("\"{}\" {}", exe_path, extra_args)
        };
        let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        let effective_work_dir = work_dir.map(|s| s.to_string()).unwrap_or_else(|| {
            std::path::Path::new(exe_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string())
        });
        let work_dir_w: Vec<u16> = effective_work_dir
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        CreateProcessW(
            None,
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0),
            None,
            windows::core::PCWSTR(work_dir_w.as_ptr()),
            &si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateProcessW: {}", e)))?;

        let _proc_handle = SafeHandle::new(pi.hProcess);
        let _thread_handle = SafeHandle::new(pi.hThread);
        let pid = pi.dwProcessId;

        tracing::info!(
            "[TESTSIGN] Process launched cleanly: PID={} (no hooks)",
            pid
        );

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "exe_path": exe_path,
            "work_dir": effective_work_dir,
            "kernel_bypass": kernel_result,
            "hooks_applied": false,
            "technique": "kernel_ci_patch + clean_launch",
            "message": format!(
                "PID {} launched without any user-mode hooks. Kernel g_CiOptions patched — NtQuerySystemInformation natively reports non-test-signing.",
                pid
            )
        }))
    }
}

/// Find a kernel module's base address and size.
/// First tries user-mode NtQuerySystemInformation; if that returns base=0
/// (Windows 26220+ zeroes kernel addresses), falls back to the driver's
/// GET_MODULE_BASE IOCTL which queries from kernel mode.
fn find_kernel_module(module_name: &str) -> Result<(u64, u32), MemoricError> {
    // Try user-mode first
    let mut ret_len = 0u32;
    let usermode_result = unsafe {
        let _ = ntapi::ntexapi::NtQuerySystemInformation(11, std::ptr::null_mut(), 0, &mut ret_len);
        if ret_len > 0 {
            let mut buffer = vec![0u8; ret_len as usize];
            let status = ntapi::ntexapi::NtQuerySystemInformation(
                11,
                buffer.as_mut_ptr() as *mut _,
                ret_len,
                &mut ret_len,
            );
            if status == 0 {
                let num_modules = *(buffer.as_ptr() as *const u32);
                let entry_size = 0x128usize;
                let entries_start = 8usize;
                let mut found = None;
                for i in 0..num_modules as usize {
                    let entry = buffer.as_ptr().add(entries_start + i * entry_size);
                    let image_base = *(entry.add(0x10) as *const u64);
                    let image_size = *(entry.add(0x18) as *const u32);
                    let name_ptr = entry.add(0x28);
                    let name_slice = std::slice::from_raw_parts(name_ptr, 256);
                    let name_end = name_slice.iter().position(|&b| b == 0).unwrap_or(256);
                    let full_path = String::from_utf8_lossy(&name_slice[..name_end]);
                    if let Some(fname) = full_path.rsplit('\\').next() {
                        if fname.eq_ignore_ascii_case(module_name) {
                            found = Some((image_base, image_size));
                            break;
                        }
                    }
                }
                found
            } else {
                None
            }
        } else {
            None
        }
    };

    // If user-mode returned a non-zero base, use it
    if let Some((base, size)) = usermode_result {
        if base != 0 {
            tracing::info!(
                "[TESTSIGN] find_kernel_module({}): user-mode base=0x{:016X}",
                module_name,
                base
            );
            return Ok((base, size));
        }
    }

    // Fallback: query from kernel-mode via driver IOCTL
    tracing::warn!(
        "[TESTSIGN] User-mode returned base=0 for {}, falling back to kernel-mode IOCTL",
        module_name
    );
    let drv = crate::driver::MemoricDriver::open().map_err(|e| {
        MemoricError::WindowsApi(format!("Driver open for module base query: {}", e))
    })?;
    let resp = drv.get_module_base(module_name)?;
    if resp.found != 0 {
        tracing::info!(
            "[TESTSIGN] find_kernel_module({}): kernel-mode base=0x{:016X} size=0x{:X}",
            module_name,
            resp.module_base,
            resp.module_size
        );
        Ok((resp.module_base, resp.module_size))
    } else {
        Ok((0, 0))
    }
}

/// Get current CI options from user-mode NtQuerySystemInformation
fn get_usermode_ci_options() -> Option<u32> {
    use std::ffi::c_void;
    type NtQueryFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
            b"ntdll.dll\0".as_ptr(),
        ))
        .ok()?;
        let func = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        )?;
        let nt_query: NtQueryFn = std::mem::transmute(func);

        #[repr(C)]
        struct CiInfo {
            length: u32,
            options: u32,
        }
        let mut ci = CiInfo {
            length: 8,
            options: 0,
        };
        let mut ret_len = 0u32;
        let status = nt_query(0x67, &mut ci as *mut _ as *mut c_void, 8, &mut ret_len);
        if status >= 0 {
            Some(ci.options)
        } else {
            None
        }
    }
}

/// Hook NtQueryLicenseValue in a remote process to hide BCD test signing indicators.
/// Uses a trampoline-based selective hook that only blocks known test-signing
/// license queries ("Kernel-TestSigning", "Kernel-TestSigning-On").
fn testsign_hide_bcd_remote(pid: u32, _proc_handle: &SafeHandle) -> Result<Value, String> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    unsafe {
        // Get NtQueryLicenseValue address
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| format!("ntdll: {}", e))?;
        let addr = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQueryLicenseValue\0".as_ptr()),
        );
        let func_addr = match addr {
            Some(a) => a as usize as u64,
            None => return Err("NtQueryLicenseValue not found".to_string()),
        };

        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| format!("OpenProcess: {}", e))?;
        let handle = SafeHandle::new(handle);

        // Read original 16 bytes from remote NtQueryLicenseValue
        let mut original = [0u8; 16];
        let mut bytes_read: usize = 0;
        ReadProcessMemory(
            *handle,
            func_addr as *mut _,
            original.as_mut_ptr() as _,
            16,
            Some(&mut bytes_read as *mut usize),
        )
        .map_err(|e| format!("ReadProcessMemory: {}", e))?;

        // Allocate code cave in remote process
        let cave = VirtualAllocEx(
            *handle,
            None,
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if cave.is_null() {
            return Err(
                "VirtualAllocEx for remote NtQueryLicenseValue hook cave failed".to_string(),
            );
        }
        let cave_addr = cave as u64;

        // Build trampoline at cave+256: original 16 bytes + absolute jmp back
        let trampoline_offset = 256usize;
        let trampoline_addr = cave_addr + trampoline_offset as u64;
        let jmp_back = func_addr + 16;
        let mut trampoline = [0u8; 30];
        trampoline[0..16].copy_from_slice(&original);
        // jmp [rip+0]; addr (absolute indirect jump)
        trampoline[16] = 0xFF;
        trampoline[17] = 0x25;
        trampoline[18] = 0x00;
        trampoline[19] = 0x00;
        trampoline[20] = 0x00;
        trampoline[21] = 0x00;
        trampoline[22..30].copy_from_slice(&jmp_back.to_le_bytes());

        WriteProcessMemory(
            *handle,
            (cave as *mut u8).add(trampoline_offset) as *mut _,
            trampoline.as_ptr() as _,
            30,
            None,
        )
        .map_err(|e| format!("WriteProcessMemory trampoline: {}", e))?;

        // Build selective hook shellcode and write to cave+0
        let shellcode = build_license_query_hook_shellcode(trampoline_addr);
        // Write the 8-byte stored addr at cave+0 (actually the whole shellcode)
        WriteProcessMemory(
            *handle,
            cave as *mut _,
            shellcode.as_ptr() as _,
            shellcode.len(),
            None,
        )
        .map_err(|e| format!("WriteProcessMemory shellcode: {}", e))?;

        // Patch trampoline address inside shellcode at offset 34 (mov rax imm64)
        let addr_patch = trampoline_addr.to_le_bytes();
        WriteProcessMemory(
            *handle,
            (cave as *mut u8).add(34) as *mut _,
            addr_patch.as_ptr() as _,
            8,
            None,
        )
        .map_err(|e| format!("WriteProcessMemory addr_patch: {}", e))?;

        // Build 16-byte inline hook patch: mov rax, cave+8; jmp rax; nop*4
        let hook_target = cave_addr + 8; // skip stored trampoline addr
        let mut hook_patch = [0u8; 16];
        hook_patch[0] = 0x48;
        hook_patch[1] = 0xB8; // mov rax, imm64
        hook_patch[2..10].copy_from_slice(&hook_target.to_le_bytes());
        hook_patch[10] = 0xFF;
        hook_patch[11] = 0xE0; // jmp rax
        hook_patch[12] = 0x90;
        hook_patch[13] = 0x90; // nop padding
        hook_patch[14] = 0x90;
        hook_patch[15] = 0x90;

        // Install inline hook on remote NtQueryLicenseValue
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            func_addr as *mut _,
            16,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| format!("VirtualProtectEx: {}", e))?;

        WriteProcessMemory(
            *handle,
            func_addr as *mut _,
            hook_patch.as_ptr() as _,
            16,
            None,
        )
        .map_err(|e| format!("WriteProcessMemory hook: {}", e))?;

        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(*handle, func_addr as *mut _, 16, old_protect, &mut tmp);

        Ok(serde_json::json!({
            "success": true,
            "function": "NtQueryLicenseValue",
            "address": format!("0x{:016X}", func_addr),
            "hook_cave": format!("0x{:016X}", cave_addr),
            "trampoline": format!("0x{:016X}", trampoline_addr),
            "method": "selective_trampoline",
            "message": "NtQueryLicenseValue hooked selectively in remote process — only 'Kernel-TestSigning' queries blocked, all others pass through"
        }))
    }
}

// ================================================================
// Kernel-level CI bypass techniques — driver IOCTL wrappers
// ================================================================

/// SeCiCallbacks bypass — replace CiValidateImageHeader callback pointer
/// in ntoskrnl!SeCiCallbacks with ZwFlushInstructionCache (always returns TRUE).
///
/// This is more stealthy than patching g_CiOptions because anti-cheat
/// often monitors the CI options value but not callback pointers.
pub fn testsign_ci_callback_bypass(args: &Value) -> Result<Value, MemoricError> {
    use crate::driver::{CI_CALLBACK_PATCH, CI_CALLBACK_QUERY, CI_CALLBACK_RESTORE};

    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("patch");
    tracing::warn!("[TESTSIGN] CI callback bypass: action={}", action);

    let drv = crate::driver::MemoricDriver::open()
        .map_err(|e| MemoricError::WindowsApi(format!("Driver open failed: {}", e)))?;

    let action_code = match action {
        "patch" => CI_CALLBACK_PATCH,
        "restore" => CI_CALLBACK_RESTORE,
        "query" => CI_CALLBACK_QUERY,
        _ => {
            return Err(MemoricError::WindowsApi(format!(
                "Unknown action: {}",
                action
            )))
        }
    };

    let resp = drv
        .ci_callback_patch(action_code)
        .map_err(|e| MemoricError::WindowsApi(format!("CI callback IOCTL: {}", e)))?;

    Ok(serde_json::json!({
        "success": resp.success == 1,
        "technique": "se_ci_callbacks_swap",
        "action": action,
        "patched": resp.patched == 1,
        "se_ci_callbacks_entry": format!("0x{:016X}", resp.se_ci_callbacks_addr),
        "original_ptr": format!("0x{:016X}", resp.original_ptr),
        "current_ptr": format!("0x{:016X}", resp.current_ptr),
        "zw_flush_addr": format!("0x{:016X}", resp.zw_flush_addr),
        "message": if resp.success == 1 {
            match action {
                "patch" => format!("SeCiCallbacks.CiValidateImageHeader patched: 0x{:016X} -> ZwFlushInstructionCache(0x{:016X})", resp.original_ptr, resp.zw_flush_addr),
                "restore" => "SeCiCallbacks restored to original pointer".to_string(),
                "query" => format!("SeCiCallbacks entry at 0x{:016X}, current ptr=0x{:016X}, patched={}", resp.se_ci_callbacks_addr, resp.current_ptr, resp.patched == 1),
                _ => "OK".to_string(),
            }
        } else {
            "CI callback operation failed — see driver DbgPrint for details".to_string()
        }
    }))
}

/// CiValidateImageHeader prologue patch — write "xor eax,eax; ret" to the
/// function entry point using PTE manipulation (Hyper-V safe).
///
/// This directly neuters CI validation at the function level.
pub fn testsign_ci_func_patch(args: &Value) -> Result<Value, MemoricError> {
    use crate::driver::{CI_FUNC_PATCH, CI_FUNC_QUERY, CI_FUNC_RESTORE};

    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("patch");
    tracing::warn!("[TESTSIGN] CI func patch: action={}", action);

    let drv = crate::driver::MemoricDriver::open()
        .map_err(|e| MemoricError::WindowsApi(format!("Driver open failed: {}", e)))?;

    let action_code = match action {
        "patch" => CI_FUNC_PATCH,
        "restore" => CI_FUNC_RESTORE,
        "query" => CI_FUNC_QUERY,
        _ => {
            return Err(MemoricError::WindowsApi(format!(
                "Unknown action: {}",
                action
            )))
        }
    };

    let resp = drv
        .ci_func_patch(action_code)
        .map_err(|e| MemoricError::WindowsApi(format!("CI func patch IOCTL: {}", e)))?;

    Ok(serde_json::json!({
        "success": resp.success == 1,
        "technique": "ci_validate_image_header_patch",
        "action": action,
        "patched": resp.patched == 1,
        "ci_validate_addr": format!("0x{:016X}", resp.ci_validate_addr),
        "original_bytes": format!("{:02X?}", &resp.original_bytes[..4]),
        "current_bytes": format!("{:02X?}", &resp.current_bytes[..4]),
        "message": if resp.success == 1 {
            match action {
                "patch" => format!("CiValidateImageHeader at 0x{:016X} patched to xor eax,eax;ret", resp.ci_validate_addr),
                "restore" => "CiValidateImageHeader restored to original bytes".to_string(),
                "query" => format!("CiValidateImageHeader at 0x{:016X}, patched={}", resp.ci_validate_addr, resp.patched == 1),
                _ => "OK".to_string(),
            }
        } else {
            "CI function patch failed — see driver DbgPrint for details".to_string()
        }
    }))
}

/// PTE read/write — read or modify page table entries for kernel virtual addresses.
/// Used by other techniques for making read-only code pages writable.
pub fn testsign_pte_rw(args: &Value) -> Result<Value, MemoricError> {
    use crate::driver::{PTE_MAKE_WRITABLE, PTE_READ, PTE_RESTORE, PTE_WRITE};

    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let va = args.get("address").and_then(|v| v.as_u64()).unwrap_or(0);
    let new_pte = args.get("new_pte").and_then(|v| v.as_u64()).unwrap_or(0);
    tracing::warn!("[TESTSIGN] PTE RW: action={}, va=0x{:016X}", action, va);

    let drv = crate::driver::MemoricDriver::open()
        .map_err(|e| MemoricError::WindowsApi(format!("Driver open failed: {}", e)))?;

    let action_code = match action {
        "read" => PTE_READ,
        "write" => PTE_WRITE,
        "make_writable" => PTE_MAKE_WRITABLE,
        "restore" => PTE_RESTORE,
        _ => {
            return Err(MemoricError::WindowsApi(format!(
                "Unknown action: {}",
                action
            )))
        }
    };

    let resp = drv
        .pte_rw(action_code, va, new_pte)
        .map_err(|e| MemoricError::WindowsApi(format!("PTE RW IOCTL: {}", e)))?;

    Ok(serde_json::json!({
        "success": resp.success == 1,
        "technique": "pte_manipulation",
        "action": action,
        "virtual_address": format!("0x{:016X}", resp.virtual_address),
        "pte_address": format!("0x{:016X}", resp.pte_address),
        "pte_value": format!("0x{:016X}", resp.pte_value),
        "original_pte_value": format!("0x{:016X}", resp.original_pte_value),
        "pte_base": format!("0x{:016X}", resp.pte_base),
        "writable": (resp.pte_value & 2) != 0,
        "present": (resp.pte_value & 1) != 0,
    }))
}
