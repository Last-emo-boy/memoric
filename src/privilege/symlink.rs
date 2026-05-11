//! Symlink/Junction/Hardlink creation for TOCTOU exploitation

use crate::error::MemoricError;
use serde_json::Value;

/// Create filesystem links (junction, symlink, hardlink) for TOCTOU attacks
pub fn symlink_attack(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Storage::FileSystem::{
        CreateHardLinkW, CreateSymbolicLinkW, SYMBOLIC_LINK_FLAG_DIRECTORY,
    };

    let link_path = args
        .get("link_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing link_path".to_string()))?;
    let target_path = args
        .get("target_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing target_path".to_string()))?;
    let link_type = args
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("symlink");

    tracing::warn!(
        "[PRIVILEGE] symlink_attack: {} -> {} (type={})",
        link_path,
        target_path,
        link_type
    );

    match link_type {
        "symlink" => {
            let link_w: Vec<u16> = link_path.encode_utf16().chain(std::iter::once(0)).collect();
            let target_w: Vec<u16> = target_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let is_dir = std::path::Path::new(target_path).is_dir();
            let flags = if is_dir {
                SYMBOLIC_LINK_FLAG_DIRECTORY
            } else {
                Default::default()
            };

            unsafe {
                let result = CreateSymbolicLinkW(
                    windows::core::PCWSTR(link_w.as_ptr()),
                    windows::core::PCWSTR(target_w.as_ptr()),
                    flags,
                );
                if result.as_bool() {
                    Ok(serde_json::json!({
                        "success": true,
                        "technique": "symlink_attack",
                        "link_path": link_path,
                        "target_path": target_path,
                        "type": "symlink",
                        "message": format!("Symbolic link created: {} -> {}", link_path, target_path)
                    }))
                } else {
                    Err(MemoricError::WindowsApi(format!("CreateSymbolicLinkW failed. Requires developer mode or SeCreateSymbolicLinkPrivilege.")))
                }
            }
        }
        "hardlink" => {
            let link_w: Vec<u16> = link_path.encode_utf16().chain(std::iter::once(0)).collect();
            let target_w: Vec<u16> = target_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                CreateHardLinkW(
                    windows::core::PCWSTR(link_w.as_ptr()),
                    windows::core::PCWSTR(target_w.as_ptr()),
                    None,
                )
                .map_err(|e| MemoricError::WindowsApi(format!("CreateHardLinkW failed: {}", e)))?;
            }

            Ok(serde_json::json!({
                "success": true,
                "technique": "symlink_attack",
                "link_path": link_path,
                "target_path": target_path,
                "type": "hardlink",
                "message": format!("Hard link created: {} -> {}", link_path, target_path)
            }))
        }
        "junction" => {
            // Use mklink /J for junction (simplest reliable approach)
            let output = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J", link_path, target_path])
                .output()
                .map_err(|e| MemoricError::WindowsApi(format!("mklink failed: {}", e)))?;

            let success = output.status.success();
            let msg = String::from_utf8_lossy(&output.stdout).to_string();

            Ok(serde_json::json!({
                "success": success,
                "technique": "symlink_attack",
                "link_path": link_path,
                "target_path": target_path,
                "type": "junction",
                "output": msg,
                "message": if success { format!("Junction created: {} -> {}", link_path, target_path) } else { "Junction creation failed".to_string() }
            }))
        }
        _ => Err(MemoricError::WindowsApi(format!(
            "Unknown link type: {}. Use symlink, hardlink, or junction.",
            link_type
        ))),
    }
}
