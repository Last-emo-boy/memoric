//! Kerberos ticket extraction via LSA Authentication Package
//! Connects to LSA, looks up the Kerberos package, and dumps TGT/ST from session cache.

use crate::error::MemoricError;
use serde_json::Value;

/// KERB_PROTOCOL_MESSAGE_TYPE for querying ticket cache
const KERB_QUERY_TKT_CACHE_REQUEST: u32 = 8;

/// Kerberos ticket encryption type names
fn enc_type_name(etype: i32) -> &'static str {
    match etype {
        1 => "DES-CBC-CRC",
        3 => "DES-CBC-MD5",
        7 => "DES3-CBC-SHA1",
        16 => "DES3-CBC-SHA1-KD",
        17 => "AES128-CTS-HMAC-SHA1-96",
        18 => "AES256-CTS-HMAC-SHA1-96",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        65 => "RC4-MD4",
        _ => "UNKNOWN",
    }
}

/// Ticket flag names (RFC 4120)
fn ticket_flag_names(flags: u32) -> Vec<&'static str> {
    let mut result = Vec::new();
    let flag_map: &[(u32, &str)] = &[
        (0x00000001, "reserved"),
        (0x00000002, "forwardable"),
        (0x00000004, "forwarded"),
        (0x00000008, "proxiable"),
        (0x00000010, "proxy"),
        (0x00000020, "may-postdate"),
        (0x00000040, "postdated"),
        (0x00000080, "invalid"),
        (0x00000100, "renewable"),
        (0x00000200, "initial"),
        (0x00000400, "pre-authent"),
        (0x00000800, "hw-authent"),
        (0x00001000, "transited-policy-checked"),
        (0x00002000, "ok-as-delegate"),
        (0x00004000, "anonymous"),
    ];
    for (mask, name) in flag_map {
        if flags & mask != 0 {
            result.push(*name);
        }
    }
    result
}

/// Parse a Windows FILETIME interval into seconds since 1601 epoch
fn filetime_to_unix_since_epoch(low: u32, high: i32) -> Option<i64> {
    if high < 0 {
        return None;
    }
    let ft: i64 = ((high as u64 as i64) << 32) | (low as u64 as i64);
    // 116444736000000000 = number of 100ns intervals from 1601 to 1970
    let unix_ns = ft.saturating_sub(116444736000000000);
    if unix_ns <= 0 {
        return None;
    }
    Some(unix_ns / 10_000_000) // convert 100ns → seconds
}

/// Extract Kerberos tickets from the current logon session cache
pub fn extract_kerberos_tickets(args: &Value) -> Result<Value, MemoricError> {
    // Use extern "system" linkage to call LSA APIs from secur32.dll
    // We load them dynamically to avoid static linking requirements

    type LsaHandle = *mut std::ffi::c_void;

    #[repr(C)]
    struct LsaString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let all_sessions = args
        .get("all_sessions")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::warn!("[KERBEROS] Extracting Kerberos tickets from LSA cache");

    unsafe {
        // Load secur32.dll
        let secur32 = windows::Win32::System::LibraryLoader::LoadLibraryA(windows::core::PCSTR(
            b"secur32.dll\0".as_ptr(),
        ))
        .map_err(|e| MemoricError::WindowsApi(format!("LoadLibrary secur32.dll: {}", e)))?;

        // Resolve LSA functions
        macro_rules! get_proc {
            ($lib:expr, $name:literal) => {
                windows::Win32::System::LibraryLoader::GetProcAddress(
                    $lib,
                    windows::core::PCSTR(concat!($name, "\0").as_ptr()),
                )
                .ok_or_else(|| {
                    MemoricError::WindowsApi(format!("GetProcAddress({}) failed", $name))
                })?
            };
        }

        type LsaConnectUntrustedFn = unsafe extern "system" fn(*mut LsaHandle) -> i32;
        type LsaLookupAuthenticationPackageFn =
            unsafe extern "system" fn(LsaHandle, *const LsaString, *mut u32) -> i32;
        type LsaCallAuthenticationPackageFn = unsafe extern "system" fn(
            LsaHandle,
            u32,
            *mut u8,
            u32,
            *mut *mut u8,
            *mut u32,
            *mut i32,
        ) -> i32;
        type LsaFreeReturnBufferFn = unsafe extern "system" fn(*mut u8) -> i32;
        type LsaDeregisterLogonProcessFn = unsafe extern "system" fn(LsaHandle) -> i32;

        let lsa_connect: LsaConnectUntrustedFn =
            std::mem::transmute(get_proc!(secur32, "LsaConnectUntrusted"));
        let lsa_lookup: LsaLookupAuthenticationPackageFn =
            std::mem::transmute(get_proc!(secur32, "LsaLookupAuthenticationPackage"));
        let lsa_call: LsaCallAuthenticationPackageFn =
            std::mem::transmute(get_proc!(secur32, "LsaCallAuthenticationPackage"));
        let lsa_free: LsaFreeReturnBufferFn =
            std::mem::transmute(get_proc!(secur32, "LsaFreeReturnBuffer"));
        let lsa_deregister: LsaDeregisterLogonProcessFn =
            std::mem::transmute(get_proc!(secur32, "LsaDeregisterLogonProcess"));

        // Connect to LSA
        let mut lsa_handle: LsaHandle = std::ptr::null_mut();
        let status = lsa_connect(&mut lsa_handle);
        if status != 0 {
            let _ = windows::Win32::Foundation::FreeLibrary(secur32);
            return Err(MemoricError::WindowsApi(format!(
                "LsaConnectUntrusted failed: 0x{:08X}",
                status as u32
            )));
        }

        // Lookup Kerberos authentication package
        let kerberos_name = "kerberos\0";
        let kerb_wide: Vec<u16> = kerberos_name.encode_utf16().collect();
        let mut auth_package_id: u32 = 0;

        let kerb_lsa_str = LsaString {
            length: (kerb_wide.len() - 1) as u16 * 2,
            maximum_length: kerb_wide.len() as u16 * 2,
            buffer: kerb_wide.as_ptr(),
        };

        let status = lsa_lookup(lsa_handle, &kerb_lsa_str, &mut auth_package_id);
        if status != 0 {
            lsa_deregister(lsa_handle);
            let _ = windows::Win32::Foundation::FreeLibrary(secur32);
            return Err(MemoricError::WindowsApi(format!(
                "LsaLookupAuthenticationPackage(kerberos) failed: 0x{:08X}",
                status as u32
            )));
        }

        // Build KERB_QUERY_TKT_CACHE_REQUEST
        // MessageType (4 bytes) + LogonId (8 bytes)
        let mut request = vec![0u8; 12];
        request[0..4].copy_from_slice(&KERB_QUERY_TKT_CACHE_REQUEST.to_le_bytes());
        // LogonId = 0 queries all logon session tickets
        request[4..12].copy_from_slice(&[0u8; 8]);

        let mut response_ptr: *mut u8 = std::ptr::null_mut();
        let mut response_len: u32 = 0;
        let mut nt_status: i32 = 0;

        let status = lsa_call(
            lsa_handle,
            auth_package_id,
            request.as_mut_ptr(),
            request.len() as u32,
            &mut response_ptr,
            &mut response_len,
            &mut nt_status,
        );

        if status != 0 || nt_status < 0 {
            if !response_ptr.is_null() {
                lsa_free(response_ptr);
            }
            lsa_deregister(lsa_handle);
            let _ = windows::Win32::Foundation::FreeLibrary(secur32);
            return Err(MemoricError::WindowsApi(format!(
                "LsaCallAuthenticationPackage(KerbQueryTicketCache) failed: LSA=0x{:08X} NT=0x{:08X}",
                status as u32, nt_status as u32
            )));
        }

        if response_ptr.is_null() || response_len < 12 {
            lsa_deregister(lsa_handle);
            let _ = windows::Win32::Foundation::FreeLibrary(secur32);
            return Ok(serde_json::json!({
                "success": true,
                "ticket_count": 0,
                "tickets": [],
                "message": "No tickets found in Kerberos cache"
            }));
        }

        // Parse KERB_QUERY_TKT_CACHE_RESPONSE
        // MessageType (4) + CountOfTickets (4) + Tickets[] (CountOfTickets * 56 bytes each)
        let response = std::slice::from_raw_parts(response_ptr, response_len as usize);
        let count: u32 = u32::from_le_bytes([response[4], response[5], response[6], response[7]]);

        let mut tickets = Vec::new();

        if count > 0 && count <= 10000 {
            // Each KERB_TICKET_CACHE_INFO is 56 bytes:
            // UNICODE_STRING ServerName (8) + UNICODE_STRING RealmName (8) +
            // LARGE_INTEGER StartTime (8) + LARGE_INTEGER EndTime (8) +
            // LARGE_INTEGER RenewTime (8) + LONG EncryptionType (4) + ULONG TicketFlags (4)

            for i in 0..count as usize {
                let offset = 8 + i * 56;
                if offset + 56 > response.len() {
                    break;
                }

                let entry = &response[offset..];

                // ServerName: UNICODE_STRING at offset 0
                let sname_len = u16::from_le_bytes([entry[0], entry[1]]) as usize;
                let sname_ptr = u64::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                    entry[15],
                ]);

                // RealmName: UNICODE_STRING at offset 16 (8 + 8)
                let realm_len = u16::from_le_bytes([entry[16], entry[17]]) as usize;
                let realm_ptr = u64::from_le_bytes([
                    entry[24], entry[25], entry[26], entry[27], entry[28], entry[29], entry[30],
                    entry[31],
                ]);

                // StartTime at offset 32
                let start_low = u32::from_le_bytes([entry[32], entry[33], entry[34], entry[35]]);
                let start_high = i32::from_le_bytes([entry[36], entry[37], entry[38], entry[39]]);

                // EndTime at offset 40
                let end_low = u32::from_le_bytes([entry[40], entry[41], entry[42], entry[43]]);
                let end_high = i32::from_le_bytes([entry[44], entry[45], entry[46], entry[47]]);

                // RenewTime at offset 48
                let renew_low = u32::from_le_bytes([entry[48], entry[49], entry[50], entry[51]]);
                let renew_high = i32::from_le_bytes([entry[52], entry[53], entry[54], entry[55]]);

                // EncryptionType at offset 56 (but entry is only 56 bytes...)
                // Actually the struct layout is:
                // 0-7: ServerName (UNICODE_STRING)
                // 8-15: ServerName.Buffer pointer
                // 16-23: RealmName (UNICODE_STRING)
                // 24-31: RealmName.Buffer pointer
                // 32-39: StartTime (LARGE_INTEGER)
                // 40-47: EndTime (LARGE_INTEGER)
                // 48-55: RenewTime (LARGE_INTEGER)
                // 56-59: EncryptionType (LONG)
                // 60-63: TicketFlags (ULONG)
                // Total: 64 bytes (with alignment)

                // Read ServerName
                let server_name = if sname_len > 0 && sname_ptr != 0 && sname_len <= 512 {
                    let name_slice =
                        std::slice::from_raw_parts(sname_ptr as *const u16, sname_len / 2);
                    String::from_utf16_lossy(name_slice)
                } else {
                    String::new()
                };

                let realm_name = if realm_len > 0 && realm_ptr != 0 && realm_len <= 256 {
                    let realm_slice =
                        std::slice::from_raw_parts(realm_ptr as *const u16, realm_len / 2);
                    String::from_utf16_lossy(realm_slice)
                } else {
                    String::new()
                };

                // Encryption type and flags are at entry+56 (within the struct, not in the buffer we read)
                let enc_type = i32::from_le_bytes([entry[56], entry[57], entry[58], entry[59]]);
                let ticket_flags = u32::from_le_bytes([entry[60], entry[61], entry[62], entry[63]]);

                let start_ts = filetime_to_unix_since_epoch(start_low, start_high);
                let end_ts = filetime_to_unix_since_epoch(end_low, end_high);
                let renew_ts = filetime_to_unix_since_epoch(renew_low, renew_high);

                // Classify ticket type
                let ticket_type = if server_name.starts_with("krbtgt/") {
                    "TGT"
                } else if server_name.is_empty() {
                    "UNKNOWN"
                } else {
                    "ST"
                };

                if !verbose && !all_sessions && ticket_type != "TGT" && ticket_type != "ST" {
                    continue;
                }

                tickets.push(serde_json::json!({
                    "type": ticket_type,
                    "server": server_name,
                    "realm": realm_name,
                    "start_time": start_ts.map(|t| chrono_datetime_string(t)).unwrap_or_default(),
                    "end_time": end_ts.map(|t| chrono_datetime_string(t)).unwrap_or_default(),
                    "renew_time": renew_ts.map(|t| chrono_datetime_string(t)).unwrap_or_default(),
                    "start_unix": start_ts,
                    "end_unix": end_ts,
                    "encryption_type": enc_type_name(enc_type),
                    "enc_type_id": enc_type,
                    "ticket_flags": ticket_flag_names(ticket_flags),
                    "flags_raw": format!("0x{:08X}", ticket_flags),
                }));
            }
        }

        lsa_free(response_ptr);
        lsa_deregister(lsa_handle);
        let _ = windows::Win32::Foundation::FreeLibrary(secur32);

        let tgt_count = tickets.iter().filter(|t| t["type"] == "TGT").count();
        let st_count = tickets.iter().filter(|t| t["type"] == "ST").count();

        let artifact = export_kerberos_tickets_artifact(args, &tickets)?;
        let inline_tickets = artifact.is_none();

        let mut result = serde_json::json!({
            "success": true,
            "ticket_count": tickets.len(),
            "tgt_count": tgt_count,
            "st_count": st_count,
            "tickets": if inline_tickets { Value::Array(tickets.clone()) } else { Value::Array(Vec::new()) },
            "redaction_status": if inline_tickets { "inline" } else { "artifact" },
            "message": format!("Extracted {} tickets ({} TGTs, {} STs) from Kerberos cache", tickets.len(), tgt_count, st_count),
            "note": "Tickets are in the LSA cache — use Rubeus or Mimikatz to export them as .kirbi files for pass-the-ticket."
        });
        if let Some(artifact) = artifact {
            if let Some(obj) = result.as_object_mut() {
                obj.insert("artifact".to_string(), artifact.clone());
                obj.insert(
                    "output_path".to_string(),
                    serde_json::json!(artifact["path"].as_str().unwrap_or_default()),
                );
            }
        }
        Ok(result)
    }
}

fn export_kerberos_tickets_artifact(
    args: &Value,
    tickets: &[Value],
) -> Result<Option<Value>, MemoricError> {
    let Some(path) = args
        .get("output_path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Ok(None);
    };

    let payload = serde_json::json!({
        "kind": "kerberos-ticket-cache",
        "ticket_count": tickets.len(),
        "tickets": tickets,
        "redaction_status": "artifact"
    });
    let bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| MemoricError::Other(format!("serialize kerberos ticket artifact: {}", e)))?;
    let correlation_id = crate::observability::correlation_id_from_args(args);
    crate::artifact::write_artifact_bytes(
        path,
        &bytes,
        crate::artifact::retention_secs_from_args(args),
        correlation_id.as_deref(),
    )
    .map(Some)
    .map_err(|e| MemoricError::Other(format!("write kerberos ticket artifact: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::export_kerberos_tickets_artifact;
    use serde_json::json;

    #[test]
    fn kerberos_ticket_export_writes_artifact_json() {
        let output_path = std::env::temp_dir().join(format!(
            "memoric-kerberos-tickets-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&output_path);
        let tickets = vec![json!({
            "type": "TGT",
            "server": "krbtgt/example.test",
            "realm": "EXAMPLE.TEST"
        })];

        let artifact = export_kerberos_tickets_artifact(
            &json!({
                "output_path": output_path.display().to_string(),
                "artifact_retention_secs": 60,
                "request_id": "kerberos-artifact-test"
            }),
            &tickets,
        )
        .expect("export tickets")
        .expect("artifact");

        assert_eq!(artifact["size_bytes"].as_u64().unwrap() > 0, true);
        assert!(artifact["sha256"].as_str().is_some());
        let uri = artifact["uri"].as_str().expect("artifact uri");
        assert!(crate::artifact::is_artifact_uri(uri));

        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output_path).expect("ticket artifact"))
                .expect("ticket artifact json");
        assert_eq!(exported["kind"], "kerberos-ticket-cache");
        assert_eq!(exported["ticket_count"], 1);
        assert_eq!(exported["redaction_status"], "artifact");

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(output_path);
    }
}

fn chrono_datetime_string(unix_ts: i64) -> String {
    // Simple conversion without chrono dependency
    let days_since_epoch = unix_ts / 86400;
    let secs_of_day = unix_ts % 86400;
    let hours = secs_of_day / 3600;
    let minutes = (secs_of_day % 3600) / 60;
    let seconds = secs_of_day % 60;

    // Days since Unix epoch to year/month/day
    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}
