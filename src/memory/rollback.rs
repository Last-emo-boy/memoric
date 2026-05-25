//! Rollback metadata helpers for live memory mutations.

use serde_json::{json, Value};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

pub(crate) struct OriginalBytesCapture {
    pub bytes: Option<Vec<u8>>,
    pub bytes_requested: usize,
    pub bytes_read: usize,
    pub error: Option<String>,
}

impl OriginalBytesCapture {
    pub(crate) fn unavailable(bytes_requested: usize, reason: impl Into<String>) -> Self {
        Self {
            bytes: None,
            bytes_requested,
            bytes_read: 0,
            error: Some(reason.into()),
        }
    }

    fn is_complete(&self) -> bool {
        self.bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() == self.bytes_requested)
    }

    fn status_json(&self) -> Value {
        match &self.error {
            Some(error) => json!({
                "status": "capture_failed",
                "bytes_requested": self.bytes_requested,
                "bytes_read": self.bytes_read,
                "error": error,
            }),
            None if self.is_complete() => json!({
                "status": "captured",
                "bytes_requested": self.bytes_requested,
                "bytes_read": self.bytes_read,
            }),
            None => json!({
                "status": "partial",
                "bytes_requested": self.bytes_requested,
                "bytes_read": self.bytes_read,
            }),
        }
    }
}

pub(crate) fn capture_original_bytes(
    handle: HANDLE,
    address: u64,
    size: usize,
) -> OriginalBytesCapture {
    if size == 0 {
        return OriginalBytesCapture {
            bytes: Some(Vec::new()),
            bytes_requested: 0,
            bytes_read: 0,
            error: None,
        };
    }

    let mut original = vec![0u8; size];
    let mut bytes_read = 0usize;
    let read_result = unsafe {
        ReadProcessMemory(
            handle,
            address as *const _,
            original.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read as *mut _),
        )
    };

    match read_result {
        Ok(()) => {
            original.truncate(bytes_read);
            OriginalBytesCapture {
                bytes: Some(original),
                bytes_requested: size,
                bytes_read,
                error: None,
            }
        }
        Err(error) => OriginalBytesCapture {
            bytes: None,
            bytes_requested: size,
            bytes_read,
            error: Some(error.to_string()),
        },
    }
}

pub(crate) fn format_address(address: u64) -> String {
    format!("0x{:016X}", address)
}

pub(crate) fn restore_original_bytes_rollback(
    pid: u64,
    address: u64,
    capture: &OriginalBytesCapture,
    old_protection: Option<u32>,
    bypass_protect: bool,
) -> Value {
    let mut captured_fields = vec!["pid", "address", "size"];
    if capture.bytes.is_some() {
        captured_fields.push("original_bytes");
    }
    if old_protection.is_some() {
        captured_fields.push("old_protection");
    }

    let available = if capture.is_complete() {
        json!(true)
    } else if capture.bytes.is_some() || old_protection.is_some() {
        json!("partial")
    } else {
        json!(false)
    };

    let mut rollback = json!({
        "available": available,
        "strategy": "restore_original_bytes",
        "captured_fields": captured_fields,
        "capture": capture.status_json(),
        "detail": "live handler attempted to capture original bytes before mutating memory",
    });

    if let Some(error) = &capture.error {
        rollback["reason"] = json!("original_bytes_capture_failed");
        rollback["capture_error"] = json!(error);
    }

    if let Some(old_protection) = old_protection {
        rollback["old_protection"] = json!(old_protection);
    }

    if let Some(original_bytes) = &capture.bytes {
        rollback["original_bytes"] = json!(original_bytes);
        if capture.is_complete() {
            let args = json!({
                "pid": pid,
                "address": format_address(address),
                "bytes": original_bytes,
                "bypass_protect": bypass_protect,
            });
            rollback["args"] = args.clone();
            rollback["action"] = json!({
                "tool": "memory",
                "action": "write",
                "args": args,
            });
        }
    }

    rollback
}

pub(crate) fn restore_original_string_bytes_rollback(
    pid: u64,
    address: u64,
    capture: &OriginalBytesCapture,
    bypass_protect: bool,
) -> Value {
    let mut rollback = restore_original_bytes_rollback(pid, address, capture, None, bypass_protect);

    rollback["strategy"] = json!("restore_original_string_bytes");
    rollback["detail"] = json!(
        "live handler attempted to capture the original null-terminated string bytes before mutation"
    );
    if let Some(action) = rollback.get_mut("action") {
        action["source_action"] = json!("target.string_write");
    }

    rollback
}

pub(crate) fn restore_previous_protection_rollback(
    pid: u64,
    address: u64,
    size: u64,
    old_protection: u32,
) -> Value {
    let args = json!({
        "pid": pid,
        "address": format_address(address),
        "size": size,
        "protect": old_protection,
    });
    json!({
        "available": true,
        "strategy": "restore_previous_protection",
        "captured_fields": ["pid", "address", "size", "old_protection"],
        "old_protection": old_protection,
        "args": args.clone(),
        "action": {
            "tool": "memory",
            "action": "protect",
            "args": args,
        },
        "detail": "previous page protection was captured by the live handler",
    })
}

pub(crate) fn free_allocated_region_rollback(pid: u64, address: u64, size: u64) -> Value {
    let args = json!({
        "pid": pid,
        "address": format_address(address),
    });
    json!({
        "available": true,
        "strategy": "free_allocated_region",
        "captured_fields": ["pid", "address", "size"],
        "args": args.clone(),
        "action": {
            "tool": "memory",
            "action": "free",
            "args": args,
        },
        "detail": "allocated region can be released with memory(action='free')",
        "allocated_size": size,
    })
}

pub(crate) fn irreversible_free_rollback(pid: u64, address: u64) -> Value {
    json!({
        "available": false,
        "strategy": "none",
        "captured_fields": ["pid", "address"],
        "reason": "irreversible_release",
        "detail": "released remote memory cannot be reconstructed without an external snapshot",
        "pid": pid,
        "address": format_address(address),
    })
}
