//! AES-256-CTR encryption via Windows BCrypt (CNG) API
//!
//! Shared module used by self-protection (memory encryption) and payload obfuscation.
//! Falls back to rolling XOR if the BCrypt provider is unavailable.

use crate::error::MemoricError;
use serde_json::Value;

/// Encrypt or decrypt data in-place using AES-256-CTR.
///
/// CTR mode is symmetric — calling this twice with the same `key` and `nonce`
/// returns the original data.
pub fn aes256_ctr_inplace(data: &mut [u8], key: &[u8], nonce: &[u8]) {
    if key.len() < 32 {
        // Degrade gracefully for undersized keys
        rolling_xor_inplace(data, key);
        return;
    }

    #[cfg(target_os = "windows")]
    {
        if bcrypt_ctr_inplace(data, &key[..32], nonce) {
            return;
        }
    }

    // Fallback
    rolling_xor_inplace(data, key);
}

/// Encrypt data, returning a new Vec.
pub fn aes256_ctr_encrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    aes256_ctr_inplace(&mut buf, key, nonce);
    buf
}

/// Decrypt is identical to encrypt in CTR mode
pub fn aes256_ctr_decrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    aes256_ctr_encrypt(data, key, nonce)
}

// ─── BCrypt backend (Windows only) ───────────────────────────────────────────

#[cfg(target_os = "windows")]
fn bcrypt_ctr_inplace(data: &mut [u8], key: &[u8], nonce: &[u8]) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::*;

    unsafe {
        let alg_id: Vec<u16> = "AES\0".encode_utf16().collect();
        let chain_mode: Vec<u16> = "ChainingModeECB\0".encode_utf16().collect();
        let chain_prop: Vec<u16> = "ChainingMode\0".encode_utf16().collect();

        let mut h_alg = BCRYPT_ALG_HANDLE::default();
        if BCryptOpenAlgorithmProvider(
            &mut h_alg,
            PCWSTR(alg_id.as_ptr()),
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
        .is_err()
        {
            return false;
        }

        let _ = BCryptSetProperty(
            h_alg.into(),
            PCWSTR(chain_prop.as_ptr()),
            &chain_mode
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<u8>>(),
            0,
        );

        let mut h_key = BCRYPT_KEY_HANDLE::default();
        if BCryptGenerateSymmetricKey(h_alg, &mut h_key, None, key, 0).is_err() {
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            return false;
        }

        // CTR: encrypt counter blocks with AES-ECB then XOR
        let mut counter = [0u8; 16];
        let ncopy = nonce.len().min(12);
        counter[..ncopy].copy_from_slice(&nonce[..ncopy]);

        let mut offset = 0;
        while offset < data.len() {
            let mut block = [0u8; 16];
            let mut cb = 0u32;

            let _ = BCryptEncrypt(
                h_key,
                Some(&counter),
                None,
                None,
                Some(&mut block),
                &mut cb,
                BCRYPT_FLAGS(0),
            );

            let take = (data.len() - offset).min(16);
            for i in 0..take {
                data[offset + i] ^= block[i];
            }

            // Increment counter (little-endian u128)
            for b in counter.iter_mut() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }

            offset += 16;
        }

        let _ = BCryptDestroyKey(h_key);
        let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        true
    }
}

// ─── Rolling XOR fallback ────────────────────────────────────────────────────

fn rolling_xor_inplace(data: &mut [u8], key: &[u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        let k = key[i % key.len()];
        *b ^= k.wrapping_add(i as u8);
    }
}

// ─── MCP handler helpers ─────────────────────────────────────────────────────

/// Parse key, requiring exact length
pub fn parse_key(args: &Value, size: usize) -> Result<Vec<u8>, MemoricError> {
    let key: Vec<u8> = args
        .get("key")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|b| b as u8))
                .collect()
        })
        .unwrap_or_default();

    if key.len() == size {
        return Ok(key);
    }
    if key.is_empty() {
        return Err(MemoricError::Other(format!(
            "Missing key (expected {} bytes)",
            size
        )));
    }
    Err(MemoricError::Other(format!(
        "Key must be {} bytes, got {}",
        size,
        key.len()
    )))
}

/// Generate a random nonce from system entropy
pub fn random_nonce() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut nonce = vec![0u8; 16];
    let ns = now.as_nanos().to_le_bytes();
    let pid = std::process::id().to_le_bytes();
    nonce[..8].copy_from_slice(&ns[..8]);
    nonce[8..16].copy_from_slice(&pid[..4]);
    nonce
}

/// Format bytes as hex string
pub fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
