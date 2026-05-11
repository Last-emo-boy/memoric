//! Comprehensive smoke test for memoric.sys kernel driver
//! Run as Administrator:
//!   cargo build --example driver_test --release
//!   target\release\examples\driver_test.exe > driver_test_output.txt 2>&1
//! Requires: memoric.sys loaded (sc start memoric)

use std::process;

fn hex_dump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  {:04X}: {:<48} {}", i * 16, hex.join(" "), ascii);
    }
}

fn main() {
    println!("=== memoric.sys driver smoke test (v2) ===");
    println!("[*] PID: {}", process::id());
    println!("[*] Running as admin: check if Token/ImageName fields are populated\n");

    // Open device
    let path: Vec<u16> = "\\\\.\\Memoric\0".encode_utf16().collect();
    let handle = unsafe {
        windows::Win32::Storage::FileSystem::CreateFileW(
            windows::core::PCWSTR(path.as_ptr()),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            windows::Win32::Storage::FileSystem::OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    let handle = match handle {
        Ok(h) => {
            println!("[+] Opened \\\\.\\Memoric successfully");
            h
        }
        Err(e) => {
            println!("[-] Failed to open device: {} (run as Administrator!)", e);
            process::exit(1);
        }
    };

    // Helper closure for DeviceIoControl
    let ioctl = |code: u32, input: &[u8], out_size: usize| -> Result<Vec<u8>, String> {
        let mut output = vec![0u8; out_size];
        let mut returned = 0u32;
        unsafe {
            windows::Win32::System::IO::DeviceIoControl(
                handle,
                code,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                if out_size > 0 {
                    Some(output.as_mut_ptr() as *mut _)
                } else {
                    None
                },
                out_size as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| format!("IOCTL 0x{:08X} failed: {}", code, e))?;
        }
        output.truncate(returned as usize);
        Ok(output)
    };

    // IOCTL constants
    const IOCTL_GET_CR3: u32 = 0x80002010;
    const IOCTL_GET_EPROCESS: u32 = 0x80002014;
    const IOCTL_PHYS_READ: u32 = 0x80002000;
    const IOCTL_VIRT_READ: u32 = 0x80002008;
    const IOCTL_VA_TO_PA: u32 = 0x80002028;

    // ---- Test 1: CR3 for current process ----
    println!("\n[Test 1] GET_CR3 (current process, pid=0)");
    {
        let req: [u8; 8] = [0; 8]; // pid=0
        match ioctl(IOCTL_GET_CR3, &req, 16) {
            Ok(data) if data.len() >= 16 => {
                let cr3 = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let eproc = u64::from_le_bytes(data[8..16].try_into().unwrap());
                println!("  [+] CR3 = 0x{:016X}", cr3);
                println!("  [+] EPROCESS = 0x{:016X}", eproc);
            }
            Ok(data) => println!("  [-] Short response: {} bytes", data.len()),
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 2: CR3 for System (pid=4) ----
    println!("\n[Test 2] GET_CR3 (System, pid=4)");
    let mut system_eproc: u64 = 0;
    {
        let mut req = [0u8; 8];
        req[0] = 4; // pid=4
        match ioctl(IOCTL_GET_CR3, &req, 16) {
            Ok(data) if data.len() >= 16 => {
                let cr3 = u64::from_le_bytes(data[0..8].try_into().unwrap());
                system_eproc = u64::from_le_bytes(data[8..16].try_into().unwrap());
                println!("  [+] System CR3 = 0x{:016X}", cr3);
                println!("  [+] System EPROCESS = 0x{:016X}", system_eproc);
            }
            Ok(data) => println!("  [-] Short response: {} bytes", data.len()),
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 3: EPROCESS info for System (pid=4) ----
    println!("\n[Test 3] GET_EPROCESS (System, pid=4)");
    let mut token_off: u32 = 0;
    let mut img_off: u32 = 0;
    {
        let mut req = [0u8; 8];
        req[0] = 4; // pid=4
        match ioctl(IOCTL_GET_EPROCESS, &req, 72) {
            Ok(data) if data.len() >= 72 => {
                // Raw hex dump for debugging
                println!("  --- Raw response (72 bytes) ---");
                hex_dump(&data);

                let eproc_addr = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let token = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let dtb = u64::from_le_bytes(data[16..24].try_into().unwrap());
                let pid = u64::from_le_bytes(data[24..32].try_into().unwrap());
                let pid_off = u32::from_le_bytes(data[32..36].try_into().unwrap());
                let apl_off = u32::from_le_bytes(data[36..40].try_into().unwrap());
                token_off = u32::from_le_bytes(data[40..44].try_into().unwrap());
                let prot_off = u32::from_le_bytes(data[44..48].try_into().unwrap());
                img_off = u32::from_le_bytes(data[48..52].try_into().unwrap());
                let vad_off = u32::from_le_bytes(data[52..56].try_into().unwrap());
                let name_bytes = &data[56..72];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]);

                println!("  --- Parsed fields ---");
                println!("  [+] EPROCESS    = 0x{:016X}", eproc_addr);
                println!(
                    "  [+] Token       = 0x{:016X} {}",
                    token,
                    if token == 0 { "(ZERO - BUG!)" } else { "(OK)" }
                );
                println!("  [+] DTB (CR3)   = 0x{:016X}", dtb);
                println!("  [+] PID         = {}", pid);
                println!(
                    "  [+] ImageName   = \"{}\" {}",
                    name,
                    if name.is_empty() {
                        "(EMPTY - BUG!)"
                    } else {
                        "(OK)"
                    }
                );
                println!("  --- Resolved offsets ---");
                println!("  [+] UniqueProcessId      = 0x{:03X}", pid_off);
                println!("  [+] ActiveProcessLinks   = 0x{:03X}", apl_off);
                println!("  [+] Token                = 0x{:03X}", token_off);
                println!("  [+] Protection           = 0x{:03X}", prot_off);
                println!("  [+] ImageFileName        = 0x{:03X}", img_off);
                println!("  [+] VadRoot              = 0x{:03X}", vad_off);
            }
            Ok(data) => println!("  [-] Short response: {} bytes (expected 72)", data.len()),
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 3b: EPROCESS info for current process ----
    println!("\n[Test 3b] GET_EPROCESS (current process, pid=0)");
    {
        let req = [0u8; 8]; // pid=0
        match ioctl(IOCTL_GET_EPROCESS, &req, 72) {
            Ok(data) if data.len() >= 72 => {
                println!("  --- Raw response (72 bytes) ---");
                hex_dump(&data);

                let eproc_addr = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let token = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let dtb = u64::from_le_bytes(data[16..24].try_into().unwrap());
                let pid = u64::from_le_bytes(data[24..32].try_into().unwrap());
                let name_bytes = &data[56..72];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]);

                println!("  --- Parsed fields ---");
                println!("  [+] EPROCESS    = 0x{:016X}", eproc_addr);
                println!(
                    "  [+] Token       = 0x{:016X} {}",
                    token,
                    if token == 0 { "(ZERO - BUG!)" } else { "(OK)" }
                );
                println!("  [+] DTB (CR3)   = 0x{:016X}", dtb);
                println!("  [+] PID         = {}", pid);
                println!(
                    "  [+] ImageName   = \"{}\" {}",
                    name,
                    if name.is_empty() {
                        "(EMPTY - BUG!)"
                    } else {
                        "(OK)"
                    }
                );
            }
            Ok(data) => println!("  [-] Short response: {} bytes", data.len()),
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 4: Cross-validate Token via VIRT_READ ----
    if system_eproc != 0 && token_off != 0 {
        println!(
            "\n[Test 4] VIRT_READ cross-check: read EPROCESS+0x{:03X} (Token) directly",
            token_off
        );
        #[repr(C)]
        struct VirtReq {
            pid: u32,
            size: u32,
            addr: u64,
        }
        // pid=0 for kernel address space (System EPROCESS is kernel memory)
        let req = VirtReq {
            pid: 0,
            size: 8,
            addr: system_eproc + token_off as u64,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<VirtReq>(),
            )
        };
        match ioctl(IOCTL_VIRT_READ, input, 8) {
            Ok(data) if data.len() >= 8 => {
                let raw_token = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let token_ptr = raw_token & !0xF; // strip EX_FAST_REF low bits
                println!(
                    "  [+] Raw Token value at EPROCESS+0x{:03X} = 0x{:016X}",
                    token_off, raw_token
                );
                println!(
                    "  [+] Token pointer (masked)              = 0x{:016X}",
                    token_ptr
                );
            }
            Ok(data) => println!("  [-] Short response: {} bytes", data.len()),
            Err(e) => println!("  [-] {}", e),
        }

        // Also read ImageFileName
        if img_off != 0 {
            println!("\n[Test 4b] VIRT_READ cross-check: read EPROCESS+0x{:03X} (ImageFileName) directly", img_off);
            let req = VirtReq {
                pid: 0,
                size: 16,
                addr: system_eproc + img_off as u64,
            };
            let input = unsafe {
                std::slice::from_raw_parts(
                    &req as *const _ as *const u8,
                    std::mem::size_of::<VirtReq>(),
                )
            };
            match ioctl(IOCTL_VIRT_READ, input, 16) {
                Ok(data) => {
                    println!("  [+] Raw bytes at EPROCESS+0x{:03X}:", img_off);
                    hex_dump(&data);
                    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                    let name = String::from_utf8_lossy(&data[..end]);
                    println!("  [+] ImageFileName = \"{}\"", name);
                }
                Err(e) => println!("  [-] {}", e),
            }
        }
    }

    // ---- Test 5: Physical memory read ----
    println!("\n[Test 5] PHYS_READ (0x1000, 64 bytes)");
    {
        #[repr(C)]
        struct PhysReq {
            addr: u64,
            size: u32,
            reserved: u32,
        }
        let req = PhysReq {
            addr: 0x1000,
            size: 64,
            reserved: 0,
        };
        let input = unsafe { std::slice::from_raw_parts(&req as *const _ as *const u8, 16) };
        match ioctl(IOCTL_PHYS_READ, input, 64) {
            Ok(data) => {
                println!("  [+] Read {} bytes from physical 0x1000", data.len());
                hex_dump(&data);
            }
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 6: VA-to-PA ----
    println!("\n[Test 6] VA_TO_PA (KUSER_SHARED_DATA 0x7FFE0000)");
    {
        #[repr(C)]
        struct VaReq {
            pid: u32,
            reserved: u32,
            va: u64,
        }
        let req = VaReq {
            pid: 0,
            reserved: 0,
            va: 0x7FFE0000,
        };
        let input = unsafe { std::slice::from_raw_parts(&req as *const _ as *const u8, 16) };
        match ioctl(IOCTL_VA_TO_PA, input, 8) {
            Ok(data) if data.len() >= 8 => {
                let pa = u64::from_le_bytes(data[0..8].try_into().unwrap());
                println!("  [+] VA 0x7FFE0000 -> PA 0x{:016X}", pa);
            }
            Ok(data) => println!("  [-] Short response: {} bytes", data.len()),
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 7: Read KUSER_SHARED_DATA via virtual read (kernel addr 0xFFFFF78000000000) ----
    println!("\n[Test 7] VIRT_READ (KUSER_SHARED_DATA kernel VA 0xFFFFF78000000000, 32 bytes)");
    {
        #[repr(C)]
        struct VirtReq {
            pid: u32,
            size: u32,
            addr: u64,
        }
        let req = VirtReq {
            pid: 0,
            size: 32,
            addr: 0xFFFFF78000000000u64,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<VirtReq>(),
            )
        };
        match ioctl(IOCTL_VIRT_READ, input, 32) {
            Ok(data) => {
                println!(
                    "  [+] Read {} bytes from kernel KUSER_SHARED_DATA",
                    data.len()
                );
                if data.len() >= 8 {
                    let tick = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    let tick_mult = u32::from_le_bytes(data[4..8].try_into().unwrap());
                    println!("  [+] TickCountLowDeprecated = {}", tick);
                    println!("  [+] TickCountMultiplier    = {}", tick_mult);
                }
                hex_dump(&data);
            }
            Err(e) => println!("  [-] {}", e),
        }
    }

    // ---- Test 8-11: Full EPROCESS scan to find real offsets ----
    if system_eproc != 0 {
        #[repr(C)]
        struct VaReq {
            pid: u32,
            reserved: u32,
            va: u64,
        }
        #[repr(C)]
        struct PhysReq {
            addr: u64,
            size: u32,
            reserved: u32,
        }

        let va_to_pa = |va: u64| -> Option<u64> {
            let req = VaReq {
                pid: 0,
                reserved: 0,
                va,
            };
            let input = unsafe { std::slice::from_raw_parts(&req as *const _ as *const u8, 16) };
            match ioctl(IOCTL_VA_TO_PA, input, 8) {
                Ok(data) if data.len() >= 8 => {
                    Some(u64::from_le_bytes(data[0..8].try_into().unwrap()))
                }
                _ => None,
            }
        };

        let phys_read = |pa: u64, size: u32| -> Option<Vec<u8>> {
            let req = PhysReq {
                addr: pa,
                size,
                reserved: 0,
            };
            let input = unsafe { std::slice::from_raw_parts(&req as *const _ as *const u8, 16) };
            ioctl(IOCTL_PHYS_READ, input, size as usize).ok()
        };

        // Read full EPROCESS: offsets 0x000 to 0xA00 (2560 bytes)
        println!("\n[Test 8] Full EPROCESS dump (0x000-0xA00) for System (PID=4)");
        println!("  System EPROCESS = 0x{:016X}", system_eproc);

        let mut eprocess_buf = vec![0u8; 0xA00];
        let mut read_ok = true;

        for page_off in (0..0xA00).step_by(256) {
            let va = system_eproc + page_off as u64;
            if let Some(pa) = va_to_pa(va) {
                let chunk_size = std::cmp::min(256, 0xA00 - page_off);
                if let Some(data) = phys_read(pa, chunk_size as u32) {
                    let copy_len = std::cmp::min(data.len(), chunk_size);
                    eprocess_buf[page_off..page_off + copy_len].copy_from_slice(&data[..copy_len]);
                } else {
                    println!("  [-] PHYS_READ failed at offset 0x{:03X}", page_off);
                    read_ok = false;
                }
            } else {
                println!("  [-] VA_TO_PA failed at offset 0x{:03X}", page_off);
                read_ok = false;
            }
        }

        if read_ok {
            // --- Scan for PID=4 ---
            println!("\n[Test 9] Scan for PID=4 (0x0000000000000004) in EPROCESS:");
            let pid_bytes = 4u64.to_le_bytes();
            for off in (0..0xA00 - 8).step_by(8) {
                if eprocess_buf[off..off + 8] == pid_bytes {
                    // Check if offset+8 looks like ActiveProcessLinks (LIST_ENTRY with kernel ptrs)
                    let mut is_list = false;
                    if off + 24 <= 0xA00 {
                        let flink =
                            u64::from_le_bytes(eprocess_buf[off + 8..off + 16].try_into().unwrap());
                        let blink = u64::from_le_bytes(
                            eprocess_buf[off + 16..off + 24].try_into().unwrap(),
                        );
                        is_list = flink > 0xFFFF000000000000 && blink > 0xFFFF000000000000;
                    }
                    println!(
                        "  [!] PID=4 found at offset 0x{:03X} (LIST_ENTRY follows: {})",
                        off,
                        if is_list {
                            "YES - likely UniqueProcessId!"
                        } else {
                            "no"
                        }
                    );
                    if is_list && off + 24 <= 0xA00 {
                        let flink =
                            u64::from_le_bytes(eprocess_buf[off + 8..off + 16].try_into().unwrap());
                        let blink = u64::from_le_bytes(
                            eprocess_buf[off + 16..off + 24].try_into().unwrap(),
                        );
                        println!("      Flink = 0x{:016X}", flink);
                        println!("      Blink = 0x{:016X}", blink);
                        println!(
                            "      => UniqueProcessId=0x{:03X}, ActiveProcessLinks=0x{:03X}",
                            off,
                            off + 8
                        );
                    }
                }
            }

            // --- Scan for Token (EX_FAST_REF: kernel pointer with low nibble) ---
            println!("\n[Test 10] Scan for Token candidates (EX_FAST_REF kernel pointers):");
            for off in (0..0xA00 - 8).step_by(8) {
                let val = u64::from_le_bytes(eprocess_buf[off..off + 8].try_into().unwrap());
                let masked = val & !0xF;
                // Token: kernel pointer (0xFFFF...) with low bits set (refcount)
                if masked > 0xFFFF000000000000 && (val & 0xF) != 0 && masked != val {
                    // Additional check: not obviously a LIST_ENTRY or EPROCESS pointer
                    // Token EX_FAST_REF typically has refcount in low 4 bits
                    let refcount = val & 0xF;
                    if refcount > 0 && refcount <= 0xF {
                        println!(
                            "  [?] Offset 0x{:03X}: val=0x{:016X} masked=0x{:016X} ref={}",
                            off, val, masked, refcount
                        );
                    }
                }
            }

            // --- Scan for "System" string ---
            println!("\n[Test 11] Scan for 'System' string in EPROCESS:");
            let system_bytes = b"System";
            for off in 0..0xA00 - 6 {
                if &eprocess_buf[off..off + 6] == system_bytes {
                    println!("  [!] 'System' found at offset 0x{:03X}", off);
                    let end = eprocess_buf[off..std::cmp::min(off + 16, 0xA00)]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(16);
                    println!(
                        "      Full string: \"{}\"",
                        String::from_utf8_lossy(&eprocess_buf[off..off + end])
                    );
                    println!("      => ImageFileName=0x{:03X}", off);
                }
            }

            // --- Full hex dump of key regions ---
            println!("\n[Test 12] OS Build info:");
            // Print the build from KUSER_SHARED_DATA+0x26C (NtBuildNumber)
            {
                let ksd_va = 0x7FFE0000u64 + 0x260;
                if let Some(pa) = va_to_pa(ksd_va) {
                    if let Some(data) = phys_read(pa, 16) {
                        let build = u32::from_le_bytes(data[0xC..0x10].try_into().unwrap());
                        println!("  NtBuildNumber = {} (0x{:X})", build & 0x0FFFFFFF, build);
                    }
                }
            }
        }
    }

    // Clean up
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
    println!("\n=== All tests complete ===");
}
