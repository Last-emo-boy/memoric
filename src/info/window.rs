//! Window enumeration for processes

use crate::error::MemoricError;
use serde_json::Value;

/// Enumerate windows owned by a process
pub fn enum_windows(args: &Value) -> Result<Value, MemoricError> {
    use std::sync::Mutex;
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let wait_ms = args.get("wait_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::info!("[INFO] enum_windows pid={} wait_ms={}", pid, wait_ms);

    struct EnumContext {
        target_pid: u32,
        windows: Vec<Value>,
    }

    static ENUM_CTX: once_cell::sync::Lazy<Mutex<Option<EnumContext>>> =
        once_cell::sync::Lazy::new(|| Mutex::new(None));

    unsafe extern "system" fn enum_callback(hwnd: HWND, _lparam: LPARAM) -> BOOL {
        let mut proc_id = 0u32;
        let tid = GetWindowThreadProcessId(hwnd, Some(&mut proc_id));

        if let Ok(mut ctx_guard) = ENUM_CTX.lock() {
            if let Some(ref mut ctx) = *ctx_guard {
                if proc_id == ctx.target_pid {
                    let mut title_buf = [0u16; 512];
                    let title_len = GetWindowTextW(hwnd, &mut title_buf);
                    let title = String::from_utf16_lossy(&title_buf[..title_len as usize]);

                    let mut class_buf = [0u16; 256];
                    let class_len = GetClassNameW(hwnd, &mut class_buf);
                    let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);

                    let visible = IsWindowVisible(hwnd).as_bool();

                    ctx.windows.push(serde_json::json!({
                        "hwnd": format!("0x{:X}", hwnd.0 as usize),
                        "title": title,
                        "class_name": class_name,
                        "visible": visible,
                        "thread_id": tid
                    }));
                }
            }
        }

        BOOL(1) // continue enumeration
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
    let mut attempts = 0u32;
    let windows = loop {
        attempts += 1;

        {
            let mut ctx = ENUM_CTX
                .lock()
                .map_err(|e| MemoricError::WindowsApi(format!("Lock: {}", e)))?;
            *ctx = Some(EnumContext {
                target_pid: pid as u32,
                windows: Vec::new(),
            });
        }

        unsafe {
            let _ = EnumWindows(Some(enum_callback), LPARAM(0));
        }

        let current_windows = {
            let mut ctx = ENUM_CTX
                .lock()
                .map_err(|e| MemoricError::WindowsApi(format!("Lock: {}", e)))?;
            ctx.take().map(|c| c.windows).unwrap_or_default()
        };

        if !current_windows.is_empty() || wait_ms == 0 || std::time::Instant::now() >= deadline {
            break current_windows;
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let initialized = !windows.is_empty();
    let total_count = windows.len();
    let paginated: Vec<_> = windows.into_iter().skip(offset).take(limit).collect();
    let window_count = paginated.len();

    Ok(serde_json::json!({
        "success": true,
        "pid": pid,
        "windows": paginated,
        "count": window_count,
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + window_count < total_count,
        "initialized": initialized,
        "attempts": attempts,
        "wait_ms": wait_ms,
        "hint": if initialized {
            "Window enumeration found one or more top-level windows"
        } else {
            "No windows found. GUI targets may need more startup time; retry with wait_ms or ensure the process owns a visible top-level window."
        }
    }))
}
