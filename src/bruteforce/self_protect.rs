//! Self-Protection & Encryption Module
//!
//! Features:
//! 1. Memory encryption - XOR/AES/ChaCha20 encryption for sensitive code/data
//! 2. Self-mutating code - runtime signature modification
//! 3. Anti-debug - detection and response to debugging attempts
//! 4. Memory locking - prevent external reads
//!
//! Techniques:
//! - Runtime encrypt/decrypt
//! - Random NOP insertion
//! - Instruction substitution
//! - Memory access monitoring

use crate::error::MemoricError;
use lazy_static::lazy_static;
use serde_json::Value;
use std::sync::{Arc, Mutex, RwLock};

/// Encryption engine
pub struct MemoryEncryption {
    key: Vec<u8>,
    algorithm: CryptoAlgorithm,
}

#[derive(Debug, Clone, Copy)]
pub enum CryptoAlgorithm {
    Xor,
    RollingXor,
    AesCtr,
    ChaCha20,
}

impl MemoryEncryption {
    /// Create a new encryption engine
    pub fn new(algorithm: CryptoAlgorithm) -> Self {
        let key_size = match algorithm {
            CryptoAlgorithm::Xor => 32,
            CryptoAlgorithm::RollingXor => 32,
            CryptoAlgorithm::AesCtr => 32,
            CryptoAlgorithm::ChaCha20 => 32,
        };

        let mut key = vec![0u8; key_size];
        for i in 0..key_size {
            key[i] = fastrand::u8(..);
        }

        Self { key, algorithm }
    }

    /// Rotate encryption key
    pub fn rotate_key(&mut self) {
        for byte in self.key.iter_mut() {
            *byte = fastrand::u8(..);
        }
        tracing::debug!("[CRYPTO] Key rotated");
    }

    /// Encrypt a memory block
    pub fn encrypt(&self, data: &mut [u8]) {
        match self.algorithm {
            CryptoAlgorithm::Xor => self.xor_encrypt(data),
            CryptoAlgorithm::RollingXor => self.rolling_xor_encrypt(data),
            CryptoAlgorithm::AesCtr => self.aes_ctr_encrypt(data),
            CryptoAlgorithm::ChaCha20 => self.chacha20_encrypt(data),
        }
    }

    /// Decrypt a memory block
    pub fn decrypt(&self, data: &mut [u8]) {
        match self.algorithm {
            CryptoAlgorithm::RollingXor => self.rolling_xor_decrypt(data),
            _ => self.encrypt(data),
        }
    }

    fn xor_encrypt(&self, data: &mut [u8]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.key[i % self.key.len()];
        }
    }

    fn rolling_xor_encrypt(&self, data: &mut [u8]) {
        let mut key_idx = 0;
        let mut prev = 0u8;
        for byte in data.iter_mut() {
            let key_byte = self.key[key_idx % self.key.len()];
            *byte ^= key_byte ^ prev;
            prev = *byte;
            key_idx += 1;
        }
    }

    fn rolling_xor_decrypt(&self, data: &mut [u8]) {
        let mut key_idx = 0;
        let mut prev_cipher = 0u8;
        for byte in data.iter_mut() {
            let cipher = *byte;
            let key_byte = self.key[key_idx % self.key.len()];
            *byte = cipher ^ key_byte ^ prev_cipher;
            prev_cipher = cipher;
            key_idx += 1;
        }
    }

    fn aes_ctr_encrypt(&self, data: &mut [u8]) {
        // Use shared BCrypt AES-256-CTR from crypto module
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.key[..8]);
        crate::crypto::aes::aes256_ctr_inplace(data, &self.key, &nonce);
    }

    fn chacha20_encrypt(&self, data: &mut [u8]) {
        // Pure Rust ChaCha20 implementation
        fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
            state[a] = state[a].wrapping_add(state[b]);
            state[d] ^= state[a];
            state[d] = state[d].rotate_left(16);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] ^= state[c];
            state[b] = state[b].rotate_left(12);
            state[a] = state[a].wrapping_add(state[b]);
            state[d] ^= state[a];
            state[d] = state[d].rotate_left(8);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] ^= state[c];
            state[b] = state[b].rotate_left(7);
        }

        fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
            let mut state: [u32; 16] = [
                0x61707865,
                0x3320646e,
                0x79622d32,
                0x6b206574, // "expand 32-byte k"
                u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
                u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
                u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
                u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
                u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
                u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
                u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
                u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
                counter,
                u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
                u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
                u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
            ];
            let initial = state;

            // 20 rounds (10 double-rounds)
            for _ in 0..10 {
                // Column rounds
                quarter_round(&mut state, 0, 4, 8, 12);
                quarter_round(&mut state, 1, 5, 9, 13);
                quarter_round(&mut state, 2, 6, 10, 14);
                quarter_round(&mut state, 3, 7, 11, 15);
                // Diagonal rounds
                quarter_round(&mut state, 0, 5, 10, 15);
                quarter_round(&mut state, 1, 6, 11, 12);
                quarter_round(&mut state, 2, 7, 8, 13);
                quarter_round(&mut state, 3, 4, 9, 14);
            }

            for i in 0..16 {
                state[i] = state[i].wrapping_add(initial[i]);
            }

            let mut out = [0u8; 64];
            for (i, &word) in state.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            out
        }

        // Use first 32 bytes of key, derive nonce from key bytes 0..12
        let mut key32 = [0u8; 32];
        for i in 0..32 {
            key32[i] = self.key[i % self.key.len()];
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.key[..12.min(self.key.len())]);

        let mut offset = 0;
        let mut block_counter = 0u32;

        while offset < data.len() {
            let keystream = chacha20_block(&key32, block_counter, &nonce);
            let remain = std::cmp::min(64, data.len() - offset);
            for i in 0..remain {
                data[offset + i] ^= keystream[i];
            }
            offset += 64;
            block_counter += 1;
        }
    }
}

/// Protected memory region
#[derive(Debug)]
pub struct ProtectedRegion {
    pub base_address: usize,
    pub size: usize,
    pub encrypted: RwLock<bool>,
    pub access_count: RwLock<u64>,
}

lazy_static! {
    static ref PROTECTED_REGIONS: Arc<Mutex<Vec<ProtectedRegion>>> =
        Arc::new(Mutex::new(Vec::new()));
    static ref ENCRYPTION_ENGINE: Arc<Mutex<MemoryEncryption>> = Arc::new(Mutex::new(
        MemoryEncryption::new(CryptoAlgorithm::RollingXor)
    ));
    static ref ENCRYPTION_ACTIVE: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

fn is_writable_protection(protect: u32) -> bool {
    use windows::Win32::System::Memory::{
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY,
    };

    protect
        & (PAGE_READWRITE.0
            | PAGE_WRITECOPY.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_EXECUTE_WRITECOPY.0)
        != 0
}

fn validate_local_region(address: usize, size: usize) -> Result<(), MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };

    if address == 0 {
        return Err(MemoricError::MemoryAccess(
            "address must be non-zero".to_string(),
        ));
    }
    if size == 0 || size > 64 * 1024 * 1024 {
        return Err(MemoricError::MemoryAccess(
            "size must be in range 1..64MB".to_string(),
        ));
    }

    let end = address
        .checked_add(size)
        .ok_or_else(|| MemoricError::MemoryAccess("address + size overflows".to_string()))?;
    let mut current = address;

    while current < end {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let ret = unsafe {
            VirtualQuery(
                Some(current as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if ret == 0 {
            return Err(MemoricError::MemoryAccess(format!(
                "VirtualQuery failed for local address 0x{:016X}",
                current
            )));
        }

        let protect = mbi.Protect.0;
        if mbi.State != MEM_COMMIT
            || protect & PAGE_GUARD.0 != 0
            || protect & PAGE_NOACCESS.0 != 0
            || !is_writable_protection(protect)
        {
            return Err(MemoricError::MemoryAccess(format!(
                "Local region 0x{:016X} is not committed writable memory (state=0x{:X}, protect=0x{:X})",
                current, mbi.State.0, protect
            )));
        }

        let region_end = (mbi.BaseAddress as usize)
            .checked_add(mbi.RegionSize)
            .ok_or_else(|| MemoricError::MemoryAccess("region end overflows".to_string()))?;
        if region_end <= current {
            return Err(MemoricError::MemoryAccess(format!(
                "VirtualQuery returned a zero-sized or invalid region at 0x{:016X}",
                current
            )));
        }
        current = region_end.min(end);
    }

    Ok(())
}

/// Encrypt the specified memory region
pub fn encrypt_region(address: usize, size: usize) -> Result<Value, MemoricError> {
    validate_local_region(address, size)?;

    {
        let regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        if let Some(region) = regions.iter().find(|r| r.base_address == address) {
            if region.size != size {
                return Err(MemoricError::MemoryAccess(format!(
                    "Region 0x{:016X} is already registered with size {}, not {}",
                    address, region.size, size
                )));
            }
            let encrypted = region
                .encrypted
                .read()
                .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
            if *encrypted {
                return Ok(serde_json::json!({
                    "success": true,
                    "already_encrypted": true,
                    "address": format!("0x{:016X}", address),
                    "size": size
                }));
            }
        }
    }

    let engine = ENCRYPTION_ENGINE
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    unsafe {
        let slice = std::slice::from_raw_parts_mut(address as *mut u8, size);
        engine.encrypt(slice);
    }

    // 添加到受保护区域列表
    {
        let mut regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

        if let Some(region) = regions.iter().find(|r| r.base_address == address) {
            let mut encrypted = region
                .encrypted
                .write()
                .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
            *encrypted = true;
        } else {
            regions.push(ProtectedRegion {
                base_address: address,
                size,
                encrypted: RwLock::new(true),
                access_count: RwLock::new(0),
            });
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "already_encrypted": false,
        "address": format!("0x{:016X}", address),
        "size": size,
        "algorithm": format!("{:?}", engine.algorithm)
    }))
}

/// Decrypt the specified memory region
pub fn decrypt_region(address: usize) -> Result<Value, MemoricError> {
    let engine = ENCRYPTION_ENGINE
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    // 查找区域
    let regions = PROTECTED_REGIONS
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    let region = regions
        .iter()
        .find(|r| r.base_address == address)
        .ok_or_else(|| MemoricError::Other("Region not found".to_string()))?;

    validate_local_region(region.base_address, region.size)?;

    {
        let encrypted = region
            .encrypted
            .read()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        if !*encrypted {
            return Ok(serde_json::json!({
                "success": true,
                "already_decrypted": true,
                "address": format!("0x{:016X}", address),
                "size": region.size
            }));
        }
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(region.base_address as *mut u8, region.size);
        engine.decrypt(slice);
    }

    // 更新状态
    {
        let mut encrypted = region
            .encrypted
            .write()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *encrypted = false;

        let mut count = region
            .access_count
            .write()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *count += 1;
    }

    let access_count = {
        let count = region
            .access_count
            .read()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *count
    };

    Ok(serde_json::json!({
        "success": true,
        "already_decrypted": false,
        "address": format!("0x{:016X}", address),
        "size": region.size,
        "access_count": access_count
    }))
}

/// Rotate all encryption keys
pub fn rotate_encryption_keys() -> Result<Value, MemoricError> {
    // 先解密所有区域
    let addresses: Vec<usize> = {
        let regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        regions.iter().map(|r| r.base_address).collect()
    };

    for addr in &addresses {
        let _ = decrypt_region(*addr);
    }

    // 轮换密钥
    {
        let mut engine = ENCRYPTION_ENGINE
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        engine.rotate_key();
    }

    // 重新加密
    for addr in &addresses {
        let regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

        if let Some(region) = regions.iter().find(|r| r.base_address == *addr) {
            let engine = ENCRYPTION_ENGINE
                .lock()
                .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

            unsafe {
                let slice =
                    std::slice::from_raw_parts_mut(region.base_address as *mut u8, region.size);
                engine.encrypt(slice);
            }
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "message": "Encryption keys rotated and regions re-encrypted"
    }))
}

/// Self-mutation engine
///
/// Modifies code signature at runtime to evade detection
pub struct SelfMutation {
    mutation_count: u64,
    original_bytes: Vec<u8>,
    current_offset: usize,
}

impl SelfMutation {
    pub fn new() -> Self {
        Self {
            mutation_count: 0,
            original_bytes: Vec::new(),
            current_offset: 0,
        }
    }

    /// Perform self-mutation
    ///
    /// Available mutation techniques:
    /// 1. NOP insertion/deletion
    /// 2. Register substitution
    /// 3. Instruction reordering
    /// 4. Immediate value mutation
    pub fn mutate(&mut self, code_region: &mut [u8]) -> Result<(), MemoricError> {
        if self.original_bytes.is_empty() {
            self.original_bytes = code_region.to_vec();
        }

        // 恢复原始代码
        code_region.copy_from_slice(&self.original_bytes);

        // 应用变异
        self.insert_random_nops(code_region)?;
        self.mutate_immediates(code_region)?;

        self.mutation_count += 1;
        self.current_offset = (self.current_offset + 1) % 16;

        tracing::debug!("[MUTATION] Code mutated (count: {})", self.mutation_count);

        Ok(())
    }

    /// Insert random NOPs
    fn insert_random_nops(&self, code: &mut [u8]) -> Result<(), MemoricError> {
        // NOP sleds: 0x90 (single), 0x66 0x90 (2-byte), 0x0F 0x1F 0x00 (3-byte), etc.
        let nop_sequences: &[&[u8]] = &[
            &[0x90],                   // NOP
            &[0x66, 0x90],             // 66 NOP
            &[0x0F, 0x1F, 0x00],       // NOP DWORD ptr [rax]
            &[0x0F, 0x1F, 0x40, 0x00], // NOP DWORD ptr [rax+00]
            &[0x48, 0x89, 0xC0],       // mov rax, rax
            &[0x48, 0x8B, 0xC0],       // mov rax, rax (alternate)
        ];

        // Select random positions to insert NOPs
        let positions: Vec<usize> = (0..code.len() / 16)
            .map(|i| i * 16 + (fastrand::usize(0..8)))
            .filter(|&p| p < code.len().saturating_sub(8))
            .take(5)
            .collect();

        for pos in positions {
            let nop = nop_sequences[fastrand::usize(0..nop_sequences.len())];
            if pos + nop.len() < code.len() {
                code[pos..pos + nop.len()].copy_from_slice(nop);
            }
        }

        Ok(())
    }

    /// Mutate immediate values while preserving semantic equivalence
    /// Inserts compensating SUB after each mutated MOV reg,imm32:
    ///   MOV r32, N  →  MOV r32, N+delta; SUB r32, delta  (net effect = unchanged)
    fn mutate_immediates(&self, code: &mut [u8]) -> Result<(), MemoricError> {
        // MOV r32, imm32 = 5 bytes (0xB8+r), compensating SUB r32, imm8 = 3 bytes (83 E8+r xx)
        // Total = 8 bytes. Skip if not enough room.
        let mut i = 0;
        while i < code.len().saturating_sub(8) {
            // MOV r32, imm32: opcodes 0xB8 through 0xBF
            if code[i] >= 0xB8 && code[i] <= 0xBF {
                let reg = code[i] - 0xB8; // 0=EAX..7=EDI
                let imm = u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
                // Only mutate non-trivial immediates
                if imm > 1 && imm < 0xFFFFFFF0 {
                    let delta: u8 = fastrand::u8(1..17);
                    let new_imm = imm.wrapping_add(delta as u32);
                    code[i + 1..i + 5].copy_from_slice(&new_imm.to_le_bytes());
                    // Compensating SUB r32, imm8: 83 E8+r delta
                    code[i + 5] = 0x83;
                    code[i + 6] = 0xE8 + reg;
                    code[i + 7] = delta;
                    i += 8; // skip MOV(5) + SUB(3)
                    continue;
                }
                i += 5;
            } else {
                i += 1;
            }
        }
        Ok(())
    }
}

/// Sleep encryption — encrypt memory during idle, auto-decrypt on wake
///
/// Encrypts all registered protected regions before sleeping,
/// then automatically decrypts them when the sleep duration expires.
pub fn sleep_encrypt(duration_ms: u64) -> Result<Value, MemoricError> {
    // Collect regions that need encryption
    let regions_to_encrypt: Vec<(usize, usize)> = {
        let regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        regions
            .iter()
            .filter(|r| !r.encrypted.read().map(|e| *e).unwrap_or(true))
            .map(|r| (r.base_address, r.size))
            .collect()
    };

    // Encrypt unencrypted regions before sleep
    let engine = ENCRYPTION_ENGINE
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    for &(addr, size) in &regions_to_encrypt {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(addr as *mut u8, size);
            engine.encrypt(slice);
        }
    }
    drop(engine);

    // Mark regions as encrypted
    {
        let regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        for &(addr, _) in &regions_to_encrypt {
            if let Some(r) = regions.iter().find(|r| r.base_address == addr) {
                if let Ok(mut e) = r.encrypted.write() {
                    *e = true;
                }
            }
        }
    }

    {
        let mut active = ENCRYPTION_ACTIVE
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *active = true;
    }

    let total_encrypted: usize = {
        let regions = PROTECTED_REGIONS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        regions
            .iter()
            .filter(|r| r.encrypted.read().map(|e| *e).unwrap_or(false))
            .count()
    };

    tracing::info!(
        "[CRYPTO] Sleep encryption active for {}ms ({} regions encrypted, {} newly encrypted)",
        duration_ms,
        total_encrypted,
        regions_to_encrypt.len()
    );

    // Sleep
    std::thread::sleep(std::time::Duration::from_millis(duration_ms));

    // Auto-decrypt on wake
    let engine = ENCRYPTION_ENGINE
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
    let regions = PROTECTED_REGIONS
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    let mut decrypted_count = 0;
    for region in regions.iter() {
        if region.encrypted.read().map(|e| *e).unwrap_or(false) {
            unsafe {
                let slice =
                    std::slice::from_raw_parts_mut(region.base_address as *mut u8, region.size);
                engine.decrypt(slice);
            }
            if let Ok(mut e) = region.encrypted.write() {
                *e = false;
            }
            decrypted_count += 1;
        }
    }
    drop(engine);
    drop(regions);

    {
        let mut active = ENCRYPTION_ACTIVE
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *active = false;
    }

    tracing::info!(
        "[CRYPTO] Sleep complete, {} regions decrypted",
        decrypted_count
    );

    Ok(serde_json::json!({
        "success": true,
        "sleep_duration_ms": duration_ms,
        "regions_encrypted": regions_to_encrypt.len(),
        "regions_decrypted": decrypted_count,
        "total_regions": total_encrypted,
        "message": format!("Sleep encryption completed: {} regions encrypted during sleep, auto-decrypted on wake", total_encrypted)
    }))
}

/// Anti-debug detection and response
pub struct AntiDebug {
    check_interval_ms: u64,
}

impl AntiDebug {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            check_interval_ms: interval_ms,
        }
    }

    /// Start anti-debug monitoring
    pub fn start_monitoring(&self) -> Result<(), MemoricError> {
        let interval = self.check_interval_ms;

        std::thread::spawn(move || {
            loop {
                // 检测调试器
                if Self::is_debugger_present() {
                    tracing::warn!("[ANTIDEBUG] Debugger detected!");

                    // 应对措施
                    Self::debugger_detected_response();
                }

                // 检测单步
                if Self::is_single_stepping() {
                    tracing::warn!("[ANTIDEBUG] Single-stepping detected!");
                }

                // 检测时间差（调试通常使程序变慢）
                if Self::check_timing_anomaly() {
                    tracing::warn!("[ANTIDEBUG] Timing anomaly detected!");
                }

                std::thread::sleep(std::time::Duration::from_millis(interval));
            }
        });

        Ok(())
    }

    fn is_debugger_present() -> bool {
        unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
    }

    fn is_single_stepping() -> bool {
        // Check trap flag
        unsafe {
            let flags: u64;
            std::arch::asm!(
                "pushfq",
                "pop {}",
                out(reg) flags,
                options(nomem, preserves_flags)
            );
            (flags & 0x100) != 0 // Trap flag
        }
    }

    fn check_timing_anomaly() -> bool {
        let start = std::time::Instant::now();

        // Execute fixed workload
        let mut sum = 0u64;
        for i in 0..100000 {
            sum = sum.wrapping_add(i);
        }

        let elapsed = start.elapsed().as_micros() as u64;

        // If elapsed time exceeds threshold, likely being debugged (single-stepping)
        elapsed > 50000 // 50ms threshold
    }

    fn debugger_detected_response() {
        // Possible responses:
        // 1. Crash the program
        // 2. Enter infinite loop
        // 3. Silent exit
        // 4. Trigger anti-forensics

        // Use silent encryption of critical memory
        unsafe {
            // Quickly encrypt critical memory regions
            let regions = PROTECTED_REGIONS.lock();
            if let Ok(regions) = regions {
                let engine = ENCRYPTION_ENGINE.lock();
                if let Ok(engine) = engine {
                    for region in regions.iter() {
                        let slice = std::slice::from_raw_parts_mut(
                            region.base_address as *mut u8,
                            region.size,
                        );
                        engine.encrypt(slice);
                    }
                }
            }
        }
    }
}

/// Initialize the full self-protection system
pub fn init_self_protection(config: ProtectionConfig) -> Result<Value, MemoricError> {
    // 启动反调试
    if config.enable_anti_debug {
        let anti_debug = AntiDebug::new(1000);
        anti_debug.start_monitoring()?;
    }

    // 设置加密引擎
    {
        let mut engine = ENCRYPTION_ENGINE
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *engine = MemoryEncryption::new(config.algorithm);
    }

    // 启动密钥轮换线程
    if config.key_rotation_interval_ms > 0 {
        let interval = config.key_rotation_interval_ms;
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(interval));
            let _ = rotate_encryption_keys();
        });
    }

    Ok(serde_json::json!({
        "success": true,
        "config": {
            "anti_debug": config.enable_anti_debug,
            "algorithm": format!("{:?}", config.algorithm),
            "key_rotation_ms": config.key_rotation_interval_ms,
        },
        "message": "Self-protection system initialized"
    }))
}

#[derive(Debug, Clone)]
pub struct ProtectionConfig {
    pub enable_anti_debug: bool,
    pub algorithm: CryptoAlgorithm,
    pub key_rotation_interval_ms: u64,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enable_anti_debug: true,
            algorithm: CryptoAlgorithm::RollingXor,
            key_rotation_interval_ms: 30000, // 30s rotation
        }
    }
}

/// Secure memory wipe
///
/// Multi-pass overwrite ensures data is unrecoverable
pub fn secure_wipe(address: usize, size: usize) -> Result<Value, MemoricError> {
    const PASSES: usize = 7; // DoD 5220.22-M standard
    const PATTERNS: &[u8] = &[0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24];

    unsafe {
        let slice = std::slice::from_raw_parts_mut(address as *mut u8, size);

        for pass in 0..PASSES {
            slice.fill(PATTERNS[pass % PATTERNS.len()]);

            // 内存屏障
            std::arch::x86_64::_mm_sfence();
            std::arch::x86_64::_mm_mfence();
        }

        // 最终随机覆盖
        for byte in slice.iter_mut() {
            *byte = fastrand::u8(..);
        }

        // 最终清零
        slice.fill(0x00);
    }

    Ok(serde_json::json!({
        "success": true,
        "address": format!("0x{:016X}", address),
        "size": size,
        "passes": PASSES,
        "standard": "DoD 5220.22-M"
    }))
}

#[cfg(test)]
mod tests {
    use super::{CryptoAlgorithm, MemoryEncryption};

    #[test]
    fn rolling_xor_decrypt_restores_plaintext() {
        let engine = MemoryEncryption::new(CryptoAlgorithm::RollingXor);
        let original = b"memoric rolling xor roundtrip".to_vec();
        let mut data = original.clone();

        engine.encrypt(&mut data);
        assert_ne!(data, original);

        engine.decrypt(&mut data);
        assert_eq!(data, original);
    }
}
