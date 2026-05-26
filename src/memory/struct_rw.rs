//! Structured memory read/write and pointer chain resolution

use crate::error::MemoricError;
use crate::util::parse_address;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrimitiveType {
    U8,
    U16,
    U32,
    U64,
    I32,
    F32,
    F64,
}

impl PrimitiveType {
    fn parse(value: &str) -> Result<Self, MemoricError> {
        match value {
            "u8" => Ok(Self::U8),
            "u16" => Ok(Self::U16),
            "u32" => Ok(Self::U32),
            "u64" => Ok(Self::U64),
            "i32" => Ok(Self::I32),
            "f32" => Ok(Self::F32),
            "f64" => Ok(Self::F64),
            _ => Err(MemoricError::MemoryAccess(format!(
                "Unsupported primitive type '{}'. Use u8/u16/u32/u64/i32/f32/f64.",
                value
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I32 => "i32",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }

    fn size(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::F64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endian {
    Native,
    Little,
    Big,
}

impl Endian {
    fn parse(value: Option<&str>) -> Result<Self, MemoricError> {
        match value.unwrap_or("native") {
            "native" => Ok(Self::Native),
            "little" => Ok(Self::Little),
            "big" => Ok(Self::Big),
            other => Err(MemoricError::MemoryAccess(format!(
                "Unsupported endian '{}'. Use native/little/big.",
                other
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Little => "little",
            Self::Big => "big",
        }
    }
}

fn requested_type(args: &Value) -> Result<PrimitiveType, MemoricError> {
    let type_name = args
        .get("type")
        .or_else(|| args.get("value_type"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing primitive type".to_string()))?;
    PrimitiveType::parse(type_name)
}

fn requested_endian(args: &Value) -> Result<Endian, MemoricError> {
    Endian::parse(args.get("endian").and_then(|value| value.as_str()))
}

fn alignment_json(address: u64, primitive: PrimitiveType, allow_unaligned: bool) -> Value {
    let alignment = primitive.size() as u64;
    let address_mod = if alignment <= 1 {
        0
    } else {
        address % alignment
    };
    json!({
        "required": alignment,
        "address_mod": address_mod,
        "aligned": address_mod == 0,
        "allow_unaligned": allow_unaligned,
    })
}

fn validate_alignment(
    address: u64,
    primitive: PrimitiveType,
    allow_unaligned: bool,
) -> Result<Value, MemoricError> {
    let metadata = alignment_json(address, primitive, allow_unaligned);
    if !allow_unaligned && !metadata["aligned"].as_bool().unwrap_or(false) {
        return Err(MemoricError::MemoryAccess(format!(
            "Address 0x{:016X} is not aligned to {} bytes for {}",
            address,
            primitive.size(),
            primitive.as_str()
        )));
    }
    Ok(metadata)
}

fn read_primitive_value(bytes: &[u8], primitive: PrimitiveType, endian: Endian) -> Value {
    match primitive {
        PrimitiveType::U8 => json!(bytes[0]),
        PrimitiveType::U16 => {
            let raw = [bytes[0], bytes[1]];
            json!(match endian {
                Endian::Native => u16::from_ne_bytes(raw),
                Endian::Little => u16::from_le_bytes(raw),
                Endian::Big => u16::from_be_bytes(raw),
            })
        }
        PrimitiveType::U32 => {
            let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
            json!(match endian {
                Endian::Native => u32::from_ne_bytes(raw),
                Endian::Little => u32::from_le_bytes(raw),
                Endian::Big => u32::from_be_bytes(raw),
            })
        }
        PrimitiveType::U64 => {
            let raw = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            json!(match endian {
                Endian::Native => u64::from_ne_bytes(raw),
                Endian::Little => u64::from_le_bytes(raw),
                Endian::Big => u64::from_be_bytes(raw),
            })
        }
        PrimitiveType::I32 => {
            let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
            json!(match endian {
                Endian::Native => i32::from_ne_bytes(raw),
                Endian::Little => i32::from_le_bytes(raw),
                Endian::Big => i32::from_be_bytes(raw),
            })
        }
        PrimitiveType::F32 => {
            let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
            let bits = match endian {
                Endian::Native => u32::from_ne_bytes(raw),
                Endian::Little => u32::from_le_bytes(raw),
                Endian::Big => u32::from_be_bytes(raw),
            };
            json!(f32::from_bits(bits))
        }
        PrimitiveType::F64 => {
            let raw = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            let bits = match endian {
                Endian::Native => u64::from_ne_bytes(raw),
                Endian::Little => u64::from_le_bytes(raw),
                Endian::Big => u64::from_be_bytes(raw),
            };
            json!(f64::from_bits(bits))
        }
    }
}

fn serialize_primitive_value(
    value: &Value,
    primitive: PrimitiveType,
    endian: Endian,
) -> Result<Vec<u8>, MemoricError> {
    match primitive {
        PrimitiveType::U8 => {
            let value = crate::args::parse_u64(value).ok_or_else(|| {
                MemoricError::MemoryAccess("Expected integer value for u8".to_string())
            })?;
            if value > u8::MAX as u64 {
                return Err(MemoricError::MemoryAccess(
                    "u8 value exceeds 255".to_string(),
                ));
            }
            Ok(vec![value as u8])
        }
        PrimitiveType::U16 => {
            let value = crate::args::parse_u64(value).ok_or_else(|| {
                MemoricError::MemoryAccess("Expected integer value for u16".to_string())
            })?;
            let value = u16::try_from(value)
                .map_err(|_| MemoricError::MemoryAccess("u16 value exceeds 65535".to_string()))?;
            Ok(match endian {
                Endian::Native => value.to_ne_bytes().to_vec(),
                Endian::Little => value.to_le_bytes().to_vec(),
                Endian::Big => value.to_be_bytes().to_vec(),
            })
        }
        PrimitiveType::U32 => {
            let value = crate::args::parse_u64(value).ok_or_else(|| {
                MemoricError::MemoryAccess("Expected integer value for u32".to_string())
            })?;
            let value = u32::try_from(value)
                .map_err(|_| MemoricError::MemoryAccess("u32 value exceeds maximum".to_string()))?;
            Ok(match endian {
                Endian::Native => value.to_ne_bytes().to_vec(),
                Endian::Little => value.to_le_bytes().to_vec(),
                Endian::Big => value.to_be_bytes().to_vec(),
            })
        }
        PrimitiveType::U64 => {
            let value = crate::args::parse_u64(value).ok_or_else(|| {
                MemoricError::MemoryAccess("Expected integer value for u64".to_string())
            })?;
            Ok(match endian {
                Endian::Native => value.to_ne_bytes().to_vec(),
                Endian::Little => value.to_le_bytes().to_vec(),
                Endian::Big => value.to_be_bytes().to_vec(),
            })
        }
        PrimitiveType::I32 => {
            let value = value.as_i64().ok_or_else(|| {
                MemoricError::MemoryAccess("Expected signed integer value for i32".to_string())
            })?;
            let value = i32::try_from(value)
                .map_err(|_| MemoricError::MemoryAccess("i32 value out of range".to_string()))?;
            Ok(match endian {
                Endian::Native => value.to_ne_bytes().to_vec(),
                Endian::Little => value.to_le_bytes().to_vec(),
                Endian::Big => value.to_be_bytes().to_vec(),
            })
        }
        PrimitiveType::F32 => {
            let value = value.as_f64().ok_or_else(|| {
                MemoricError::MemoryAccess("Expected numeric value for f32".to_string())
            })? as f32;
            let bits = value.to_bits();
            Ok(match endian {
                Endian::Native => bits.to_ne_bytes().to_vec(),
                Endian::Little => bits.to_le_bytes().to_vec(),
                Endian::Big => bits.to_be_bytes().to_vec(),
            })
        }
        PrimitiveType::F64 => {
            let value = value.as_f64().ok_or_else(|| {
                MemoricError::MemoryAccess("Expected numeric value for f64".to_string())
            })?;
            let bits = value.to_bits();
            Ok(match endian {
                Endian::Native => bits.to_ne_bytes().to_vec(),
                Endian::Little => bits.to_le_bytes().to_vec(),
                Endian::Big => bits.to_be_bytes().to_vec(),
            })
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    if bytes.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}

/// Read one primitive numeric value with explicit endian and alignment metadata.
pub fn typed_read(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = crate::args::require_pid(args, "pid").map_err(MemoricError::MemoryAccess)?;
    let address =
        crate::args::require_address(args, "address").map_err(MemoricError::MemoryAccess)?;
    let primitive = requested_type(args)?;
    let endian = requested_endian(args)?;
    let allow_unaligned = args
        .get("allow_unaligned")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let alignment = validate_alignment(address, primitive, allow_unaligned)?;
    let _handle_cache_guard = crate::handle_cache::ensure_request();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid,
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0,
        )
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

        let mut buffer = vec![0u8; primitive.size()];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            Some(&mut bytes_read as *mut _),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("ReadProcessMemory failed: {}", e)))?;

        if bytes_read != primitive.size() {
            return Err(MemoricError::MemoryAccess(format!(
                "Partial typed read: expected {} bytes, read {}",
                primitive.size(),
                bytes_read
            )));
        }

        Ok(json!({
            "success": true,
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "type": primitive.as_str(),
            "endian": endian.as_str(),
            "size": primitive.size(),
            "alignment": alignment,
            "value": read_primitive_value(&buffer, primitive, endian),
            "bytes": buffer,
            "hex": hex_bytes(&buffer),
        }))
    }
}

/// Write one primitive numeric value with explicit endian and alignment metadata.
pub fn typed_write(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Threading::{
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = crate::args::require_pid(args, "pid").map_err(MemoricError::MemoryAccess)?;
    let address =
        crate::args::require_address(args, "address").map_err(MemoricError::MemoryAccess)?;
    let primitive = requested_type(args)?;
    let endian = requested_endian(args)?;
    let value = args
        .get("value")
        .ok_or_else(|| MemoricError::MemoryAccess("Missing value".to_string()))?;
    let allow_unaligned = args
        .get("allow_unaligned")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let alignment = validate_alignment(address, primitive, allow_unaligned)?;
    let bytes = serialize_primitive_value(value, primitive, endian)?;
    let _handle_cache_guard = crate::handle_cache::ensure_request();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid,
            (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION).0,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

        let mut bytes_written = 0usize;
        WriteProcessMemory(
            handle,
            address as *const _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            Some(&mut bytes_written as *mut _),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("WriteProcessMemory failed: {}", e)))?;

        Ok(json!({
            "success": true,
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "type": primitive.as_str(),
            "endian": endian.as_str(),
            "size": primitive.size(),
            "alignment": alignment,
            "value": value.clone(),
            "bytes_written": bytes_written,
            "bytes": bytes,
            "hex": hex_bytes(&bytes),
        }))
    }
}

/// Read memory as a named struct layout.
/// Fields define {name, offset, type} where type is u8/u16/u32/u64/i32/f32/f64/ptr/string:N/bytes:N
pub fn read_struct(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
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
    let _handle_cache_guard = crate::handle_cache::ensure_request();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid as u32,
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

        let mut buffer = vec![0u8; max_end];
        let mut bytes_read = 0usize;

        ReadProcessMemory(
            handle,
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

        let raw_hex = hex_bytes(&buffer[..bytes_read]);

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
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
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
    let _handle_cache_guard = crate::handle_cache::ensure_request();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid as u32,
            (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION).0,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

        // Write each field individually to avoid overwriting gaps
        let mut total_written = 0usize;
        for (offset, bytes) in &writes {
            let write_addr = address + *offset as u64;
            let mut bytes_written = 0usize;
            WriteProcessMemory(
                handle,
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
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
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
    let _handle_cache_guard = crate::handle_cache::ensure_request();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid as u32,
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

        let mut current_addr = base;
        let mut intermediates: Vec<String> = vec![format!("0x{:016X}", current_addr)];

        for (i, offset) in offset_vals.iter().enumerate() {
            // Dereference: read pointer at current_addr
            let mut ptr_buf = [0u8; 8];
            let mut bytes_read = 0usize;

            ReadProcessMemory(
                handle,
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
            handle,
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
                    "hex": hex_bytes(&final_buf)
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
            serde_json::json!(hex_bytes(&remaining[..len]))
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
                Ok(parse_loose_hex_tokens(hex))
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

fn parse_loose_hex_tokens(value: &str) -> Vec<u8> {
    value
        .split_whitespace()
        .filter_map(parse_loose_hex_byte)
        .collect()
}

fn parse_loose_hex_byte(token: &str) -> Option<u8> {
    let mut value = 0u16;
    let mut saw_digit = false;
    for byte in token.bytes() {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        saw_digit = true;
        value = value.checked_mul(16)?.checked_add(nibble as u16)?;
        if value > u8::MAX as u16 {
            return None;
        }
    }
    saw_digit.then_some(value as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[repr(align(8))]
    struct AlignedBytes([u8; 64]);

    #[test]
    fn typed_read_write_cover_primitive_endian_and_alignment_metadata() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = AlignedBytes([0u8; 64]);
        let base = buffer.0.as_mut_ptr() as u64;
        let pid = std::process::id();
        assert_eq!(base % 8, 0, "test buffer should be 8-byte aligned");

        typed_write(&json!({
            "pid": pid,
            "address": base,
            "type": "u8",
            "value": 0xAB
        }))
        .expect("u8 write");
        assert_eq!(buffer.0[0], 0xAB);
        let read_u8 = typed_read(&json!({
            "pid": pid,
            "address": base,
            "type": "u8"
        }))
        .expect("u8 read");
        assert_eq!(read_u8["value"], json!(0xAB));
        assert_eq!(read_u8["alignment"]["aligned"], true);

        typed_write(&json!({
            "pid": pid,
            "address": base + 2,
            "type": "u16",
            "endian": "little",
            "value": 0x1234
        }))
        .expect("u16 little write");
        assert_eq!(&buffer.0[2..4], &[0x34, 0x12]);
        let read_u16 = typed_read(&json!({
            "pid": pid,
            "address": base + 2,
            "type": "u16",
            "endian": "little"
        }))
        .expect("u16 little read");
        assert_eq!(read_u16["value"], json!(0x1234));

        typed_write(&json!({
            "pid": pid,
            "address": base + 4,
            "type": "u32",
            "endian": "big",
            "value": 0x11223344u64
        }))
        .expect("u32 big write");
        assert_eq!(&buffer.0[4..8], &[0x11, 0x22, 0x33, 0x44]);
        let read_u32 = typed_read(&json!({
            "pid": pid,
            "address": base + 4,
            "type": "u32",
            "endian": "big"
        }))
        .expect("u32 big read");
        assert_eq!(read_u32["value"], json!(0x11223344u64));

        let u64_value = 0x0102_0304_0506_0708u64;
        typed_write(&json!({
            "pid": pid,
            "address": base + 8,
            "type": "u64",
            "endian": "little",
            "value": u64_value
        }))
        .expect("u64 little write");
        assert_eq!(
            &buffer.0[8..16],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        let read_u64 = typed_read(&json!({
            "pid": pid,
            "address": base + 8,
            "type": "u64",
            "endian": "little"
        }))
        .expect("u64 little read");
        assert_eq!(read_u64["value"], json!(u64_value));

        typed_write(&json!({
            "pid": pid,
            "address": base + 16,
            "type": "i32",
            "endian": "big",
            "value": -123456
        }))
        .expect("i32 big write");
        let read_i32 = typed_read(&json!({
            "pid": pid,
            "address": base + 16,
            "type": "i32",
            "endian": "big"
        }))
        .expect("i32 big read");
        assert_eq!(read_i32["value"], json!(-123456));

        typed_write(&json!({
            "pid": pid,
            "address": base + 20,
            "type": "f32",
            "endian": "little",
            "value": 3.5
        }))
        .expect("f32 little write");
        let read_f32 = typed_read(&json!({
            "pid": pid,
            "address": base + 20,
            "type": "f32",
            "endian": "little"
        }))
        .expect("f32 little read");
        assert!((read_f32["value"].as_f64().unwrap() - 3.5).abs() < f64::EPSILON);

        typed_write(&json!({
            "pid": pid,
            "address": base + 24,
            "type": "f64",
            "endian": "big",
            "value": -42.25
        }))
        .expect("f64 big write");
        let read_f64 = typed_read(&json!({
            "pid": pid,
            "address": base + 24,
            "type": "f64",
            "endian": "big"
        }))
        .expect("f64 big read");
        assert!((read_f64["value"].as_f64().unwrap() + 42.25).abs() < f64::EPSILON);

        let unaligned = typed_read(&json!({
            "pid": pid,
            "address": base + 1,
            "type": "u32",
            "allow_unaligned": true
        }))
        .expect("unaligned read is allowed by default");
        assert_eq!(unaligned["alignment"]["aligned"], false);
        assert_eq!(unaligned["alignment"]["address_mod"], json!(1));

        let err = typed_read(&json!({
            "pid": pid,
            "address": base + 1,
            "type": "u32",
            "allow_unaligned": false
        }))
        .expect_err("strict alignment should reject unaligned address");
        assert!(err.to_string().contains("not aligned"));
    }

    #[test]
    fn typed_write_validates_ranges_and_required_fields() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = AlignedBytes([0u8; 64]);
        let base = buffer.0.as_mut_ptr() as u64;

        let err = typed_write(&json!({
            "pid": std::process::id(),
            "address": base,
            "type": "u8",
            "value": 256
        }))
        .expect_err("u8 range should be enforced");
        assert!(err.to_string().contains("u8 value exceeds 255"));

        let err = typed_read(&json!({
            "pid": std::process::id(),
            "address": base,
            "type": "u128"
        }))
        .expect_err("unsupported type should fail");
        assert!(err.to_string().contains("Unsupported primitive type"));
    }

    #[test]
    fn loose_hex_token_parser_preserves_bytes_field_compatibility() {
        assert_eq!(
            parse_loose_hex_tokens("A 0f FF gg 100 0001"),
            vec![0x0A, 0x0F, 0xFF, 0x01]
        );
        assert_eq!(parse_loose_hex_tokens("DEADBEEF"), Vec::<u8>::new());
        assert_eq!(parse_loose_hex_tokens(""), Vec::<u8>::new());
    }
}
