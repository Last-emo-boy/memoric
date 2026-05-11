//! Structured memory read/write and pointer chain resolution

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Read memory as a named struct layout.
/// Fields define {name, offset, type} where type is u8/u16/u32/u64/i32/f32/f64/ptr/string:N/bytes:N
pub fn read_struct(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing or invalid address".to_string()))?;
    let fields = args
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing fields array".to_string()))?;

    if fields.is_empty() {
        return Err(MemoricError::MemoryAccess(
            "Fields array is empty".to_string(),
        ));
    }

    // Compute total read size from field definitions
    let mut max_end = 0usize;
    let mut field_specs: Vec<(String, usize, String)> = Vec::new();

    for field in fields {
        let name = field
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let offset = field.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let ftype = field
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("u32")
            .to_string();

        let size = field_type_size(&ftype);
        let end = offset + size;
        if end > max_end {
            max_end = end;
        }
        field_specs.push((name, offset, ftype));
    }

    tracing::info!(
        "[MEMORY] read_struct pid={} addr=0x{:X} total_size={} fields={}",
        pid,
        address,
        max_end,
        field_specs.len()
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut buffer = vec![0u8; max_end];
        let mut bytes_read = 0usize;

        ReadProcessMemory(
            *handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            max_end,
            Some(&mut bytes_read as *mut _),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("ReadProcessMemory failed: {}", e)))?;

        // Parse each field from the buffer
        let mut result_fields = serde_json::Map::new();

        for (name, offset, ftype) in &field_specs {
            let val = parse_field_value(&buffer, *offset, ftype);
            result_fields.insert(name.clone(), val);
        }

        let raw_hex: String = buffer[..bytes_read]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "fields": result_fields,
            "bytes_read": bytes_read,
            "raw_hex": raw_hex
        }))
    }
}

/// Write structured data to memory
pub fn write_struct(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing or invalid address".to_string()))?;
    let fields = args
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing fields array".to_string()))?;

    // Compute total buffer size and build field writes
    let mut max_end = 0usize;
    let mut writes: Vec<(usize, Vec<u8>)> = Vec::new();

    for field in fields {
        let offset = field.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let ftype = field.get("type").and_then(|v| v.as_str()).unwrap_or("u32");
        let value = field
            .get("value")
            .ok_or_else(|| MemoricError::MemoryAccess("Field missing value".to_string()))?;

        let bytes = serialize_field_value(value, ftype)?;
        let end = offset + bytes.len();
        if end > max_end {
            max_end = end;
        }
        writes.push((offset, bytes));
    }

    tracing::info!(
        "[MEMORY] write_struct pid={} addr=0x{:X} total_size={} fields={}",
        pid,
        address,
        max_end,
        writes.len()
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Write each field individually to avoid overwriting gaps
        let mut total_written = 0usize;
        for (offset, bytes) in &writes {
            let write_addr = address + *offset as u64;
            let mut bytes_written = 0usize;
            WriteProcessMemory(
                *handle,
                write_addr as *const _,
                bytes.as_ptr() as *const _,
                bytes.len(),
                Some(&mut bytes_written as *mut _),
            )
            .map_err(|e| {
                MemoricError::MemoryAccess(format!(
                    "WriteProcessMemory failed at offset {}: {}",
                    offset, e
                ))
            })?;
            total_written += bytes_written;
        }

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "fields_written": writes.len(),
            "bytes_written": total_written
        }))
    }
}

/// Follow a multi-level pointer chain: base -> [base] + off0 -> [[base]+off0] + off1 -> ...
pub fn pointer_chain_resolve(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let base = args
        .get("base")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing or invalid base address".to_string()))?;
    let offsets = args
        .get("offsets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing offsets array".to_string()))?;

    let offset_vals: Vec<i64> = offsets.iter().filter_map(|v| v.as_i64()).collect();

    tracing::info!(
        "[MEMORY] pointer_chain_resolve pid={} base=0x{:X} offsets={:?}",
        pid,
        base,
        offset_vals
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut current_addr = base;
        let mut intermediates: Vec<String> = vec![format!("0x{:016X}", current_addr)];

        for (i, offset) in offset_vals.iter().enumerate() {
            // Dereference: read pointer at current_addr
            let mut ptr_buf = [0u8; 8];
            let mut bytes_read = 0usize;

            ReadProcessMemory(
                *handle,
                current_addr as *const _,
                ptr_buf.as_mut_ptr() as *mut _,
                8,
                Some(&mut bytes_read as *mut _),
            )
            .map_err(|e| {
                MemoricError::MemoryAccess(format!(
                    "ReadProcessMemory failed at level {} addr=0x{:X}: {}",
                    i, current_addr, e
                ))
            })?;

            let deref_val = u64::from_ne_bytes(ptr_buf);
            // Apply offset
            current_addr = (deref_val as i64 + offset) as u64;
            intermediates.push(format!("0x{:016X}", current_addr));
        }

        // Read value at final address (8 bytes)
        let mut final_buf = [0u8; 8];
        let mut final_read = 0usize;
        let final_read_ok = ReadProcessMemory(
            *handle,
            current_addr as *const _,
            final_buf.as_mut_ptr() as *mut _,
            8,
            Some(&mut final_read as *mut _),
        )
        .is_ok();

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "base": format!("0x{:016X}", base),
            "offsets": offset_vals,
            "final_address": format!("0x{:016X}", current_addr),
            "intermediate_addresses": intermediates,
            "levels": offset_vals.len(),
            "value_at_final": if final_read_ok {
                serde_json::json!({
                    "u64": u64::from_ne_bytes(final_buf),
                    "i32": i32::from_ne_bytes([final_buf[0], final_buf[1], final_buf[2], final_buf[3]]),
                    "f32": f32::from_ne_bytes([final_buf[0], final_buf[1], final_buf[2], final_buf[3]]),
                    "hex": format!("{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                        final_buf[0], final_buf[1], final_buf[2], final_buf[3],
                        final_buf[4], final_buf[5], final_buf[6], final_buf[7])
                })
            } else {
                serde_json::json!(null)
            }
        }))
    }
}

// Helper: determine byte size for a field type string
fn field_type_size(ftype: &str) -> usize {
    match ftype {
        "u8" | "i8" | "bool" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" | "ptr" => 8,
        s if s.starts_with("string:") => s[7..].parse::<usize>().unwrap_or(64),
        s if s.starts_with("bytes:") => s[6..].parse::<usize>().unwrap_or(16),
        _ => 4,
    }
}

// Helper: parse a field value from a byte buffer
fn parse_field_value(buffer: &[u8], offset: usize, ftype: &str) -> Value {
    if offset >= buffer.len() {
        return Value::Null;
    }
    let remaining = &buffer[offset..];
    match ftype {
        "u8" if remaining.len() >= 1 => serde_json::json!(remaining[0]),
        "i8" if remaining.len() >= 1 => serde_json::json!(remaining[0] as i8),
        "bool" if remaining.len() >= 1 => serde_json::json!(remaining[0] != 0),
        "u16" if remaining.len() >= 2 => {
            serde_json::json!(u16::from_ne_bytes([remaining[0], remaining[1]]))
        }
        "i16" if remaining.len() >= 2 => {
            serde_json::json!(i16::from_ne_bytes([remaining[0], remaining[1]]))
        }
        "u32" if remaining.len() >= 4 => serde_json::json!(u32::from_ne_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3]
        ])),
        "i32" if remaining.len() >= 4 => serde_json::json!(i32::from_ne_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3]
        ])),
        "f32" if remaining.len() >= 4 => serde_json::json!(f32::from_ne_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3]
        ])),
        "u64" | "ptr" if remaining.len() >= 8 => {
            let val = u64::from_ne_bytes([
                remaining[0],
                remaining[1],
                remaining[2],
                remaining[3],
                remaining[4],
                remaining[5],
                remaining[6],
                remaining[7],
            ]);
            if ftype == "ptr" {
                serde_json::json!(format!("0x{:016X}", val))
            } else {
                serde_json::json!(val)
            }
        }
        "i64" if remaining.len() >= 8 => serde_json::json!(i64::from_ne_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
            remaining[4],
            remaining[5],
            remaining[6],
            remaining[7]
        ])),
        "f64" if remaining.len() >= 8 => serde_json::json!(f64::from_ne_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
            remaining[4],
            remaining[5],
            remaining[6],
            remaining[7]
        ])),
        s if s.starts_with("string:") => {
            let len = s[7..].parse::<usize>().unwrap_or(64).min(remaining.len());
            let data = &remaining[..len];
            // Find null terminator
            let end = data.iter().position(|&b| b == 0).unwrap_or(len);
            serde_json::json!(String::from_utf8_lossy(&data[..end]))
        }
        s if s.starts_with("bytes:") => {
            let len = s[6..].parse::<usize>().unwrap_or(16).min(remaining.len());
            let hex: String = remaining[..len]
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            serde_json::json!(hex)
        }
        _ => Value::Null,
    }
}

// Helper: serialize a JSON value into bytes for a given field type
fn serialize_field_value(value: &Value, ftype: &str) -> Result<Vec<u8>, MemoricError> {
    match ftype {
        "u8" | "i8" | "bool" => {
            let v = value
                .as_u64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected integer".to_string()))?
                as u8;
            Ok(vec![v])
        }
        "u16" | "i16" => {
            let v = value
                .as_u64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected integer".to_string()))?
                as u16;
            Ok(v.to_ne_bytes().to_vec())
        }
        "u32" => {
            let v = value
                .as_u64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected integer".to_string()))?
                as u32;
            Ok(v.to_ne_bytes().to_vec())
        }
        "i32" => {
            let v = value
                .as_i64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected integer".to_string()))?
                as i32;
            Ok(v.to_ne_bytes().to_vec())
        }
        "f32" => {
            let v = value
                .as_f64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected number".to_string()))?
                as f32;
            Ok(v.to_ne_bytes().to_vec())
        }
        "u64" | "ptr" => {
            let v = value
                .as_u64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected integer".to_string()))?;
            Ok(v.to_ne_bytes().to_vec())
        }
        "i64" => {
            let v = value
                .as_i64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected integer".to_string()))?;
            Ok(v.to_ne_bytes().to_vec())
        }
        "f64" => {
            let v = value
                .as_f64()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected number".to_string()))?;
            Ok(v.to_ne_bytes().to_vec())
        }
        s if s.starts_with("string:") => {
            let max_len = s[7..].parse::<usize>().unwrap_or(64);
            let s = value
                .as_str()
                .ok_or_else(|| MemoricError::MemoryAccess("Expected string".to_string()))?;
            let mut bytes = s.as_bytes().to_vec();
            bytes.resize(max_len, 0); // pad with nulls
            Ok(bytes)
        }
        s if s.starts_with("bytes:") => {
            if let Some(arr) = value.as_array() {
                Ok(arr
                    .iter()
                    .filter_map(|v| v.as_u64().map(|b| b as u8))
                    .collect())
            } else if let Some(hex) = value.as_str() {
                // Parse hex string
                Ok(hex
                    .split_whitespace()
                    .filter_map(|s| u8::from_str_radix(s, 16).ok())
                    .collect())
            } else {
                Err(MemoricError::MemoryAccess(
                    "Expected byte array or hex string".to_string(),
                ))
            }
        }
        _ => Err(MemoricError::MemoryAccess(format!(
            "Unknown field type: {}",
            ftype
        ))),
    }
}
