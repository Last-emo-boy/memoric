//! Process information implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct ProcessFingerprint {
    pub pid: u32,
    pub name: Option<String>,
    pub exe_path: Option<String>,
    pub parent_pid: Option<u32>,
    pub session_id: Option<u32>,
    pub signer: Option<String>,
    pub protection_level: Option<u32>,
    pub protection_name: Option<String>,
    pub query_limited_openable: bool,
    pub errors: Vec<String>,
}

impl ProcessFingerprint {
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.exe_path.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn is_protected(&self) -> bool {
        self.protection_level.is_some_and(|level| {
            level != windows::Win32::System::Threading::PROTECTION_LEVEL_NONE.0
        })
    }

    pub fn is_critical_name(&self) -> bool {
        self.name
            .as_deref()
            .map(is_critical_process_name)
            .unwrap_or(false)
    }

    pub fn is_high_risk_target(&self) -> bool {
        self.pid <= 4 || self.is_critical_name() || self.is_protected()
    }
}

/// List all processes
pub fn list_processes(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let include_system = args
        .get("include_system")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::debug!("Listing processes (include_system={})", include_system);

    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                let name = process_entry_name(&entry);
                let pid = entry.th32ProcessID;
                let ppid = entry.th32ParentProcessID;

                if !include_system && pid <= 4 {
                    // Skip system processes
                } else {
                    processes.push(serde_json::json!({
                        "pid": pid,
                        "ppid": ppid,
                        "name": name
                    }));
                }

                if Process32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!("Found {} processes", processes.len());

    let total_count = processes.len();
    let paginated: Vec<_> = processes.into_iter().skip(offset).take(limit).collect();

    Ok(serde_json::json!({
        "count": paginated.len(),
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + paginated.len() < total_count,
        "processes": paginated
    }))
}

/// Get detailed process information
pub fn get_process_info(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::ProcessNotFound(0))?;

    tracing::debug!("Getting info for process {}", pid);

    unsafe {
        let handle_result = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        );

        let is_openable = handle_result.is_ok();
        let handle_opt = handle_result.ok().map(SafeHandle::new);

        let name = get_process_name(pid).unwrap_or_else(|_| "unknown".to_string());

        let error_context = if handle_opt.is_none() {
            let retry_result = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid as u32,
            );
            if let Err(err) = retry_result {
                let err_msg = format!("{}", err);
                if err_msg.contains("Access is denied") || err_msg.contains("0x80070005") {
                    Some("Access denied. Possible causes: 1) UWP app is sandboxed 2) Requires SYSTEM privileges 3) Call enable_debug_privilege first".to_string())
                } else if err_msg.contains("Invalid parameter") || err_msg.contains("0x80070057") {
                    Some("Process does not exist".to_string())
                } else {
                    Some(format!("Error: {}", err))
                }
            } else {
                // Close the retried handle via SafeHandle
                let _ = retry_result.ok().map(SafeHandle::new);
                None
            }
        } else {
            None
        };

        let mut result = serde_json::json!({
            "pid": pid,
            "name": name,
            "is_openable": is_openable,
            "message": if is_openable { "Process accessible" } else { error_context.as_ref().unwrap() }
        });

        if is_openable {
            // handle_opt (SafeHandle) will be dropped automatically
            drop(handle_opt);
            if let Ok(cmdline) = get_process_cmdline(pid) {
                result["cmdline"] = serde_json::Value::String(cmdline);
            }
            if let Ok(is_64bit) = is_process_64bit(pid as u32) {
                result["is_64bit"] = serde_json::Value::Bool(is_64bit);
                result["arch"] =
                    serde_json::Value::String(if is_64bit { "x64" } else { "x86" }.to_string());
            }
        }

        Ok(result)
    }
}

pub fn process_fingerprint(pid: u32) -> ProcessFingerprint {
    let mut fingerprint = ProcessFingerprint {
        pid,
        ..Default::default()
    };

    match get_process_snapshot_entry(pid) {
        Ok((name, parent_pid)) => {
            fingerprint.name = Some(name);
            fingerprint.parent_pid = Some(parent_pid);
        }
        Err(err) => fingerprint.errors.push(err.to_string()),
    }

    match query_limited_process_identity(pid) {
        Ok((exe_path, protection_level, protection_name)) => {
            fingerprint.query_limited_openable = true;
            if let Some(path) = exe_path.as_deref() {
                match file_signer_identity(path) {
                    Ok(Some(signer)) => fingerprint.signer = Some(signer),
                    Ok(None) => fingerprint
                        .errors
                        .push("signer_identity: no embedded Authenticode signer".to_string()),
                    Err(err) => fingerprint.errors.push(format!("signer_identity: {}", err)),
                }
            }
            fingerprint.exe_path = exe_path;
            fingerprint.protection_level = protection_level;
            fingerprint.protection_name = protection_name;
        }
        Err(err) => fingerprint.errors.push(err),
    }

    match get_process_session_id(pid) {
        Ok(session_id) => fingerprint.session_id = Some(session_id),
        Err(err) => fingerprint.errors.push(err),
    }

    fingerprint
}

pub fn file_signer_identity(path: &str) -> Result<Option<String>, String> {
    use windows::Win32::Security::Cryptography::{
        CertFindCertificateInStore, CertGetNameStringW, CryptMsgGetParam, CryptQueryObject,
        CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut store = HCERTSTORE::default();
    let mut message: *mut core::ffi::c_void = std::ptr::null_mut();
    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const core::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut message),
            None,
        )
        .map_err(|err| format!("CryptQueryObject: {}", err))?;

        let _guard = CryptQueryGuard { store, message };

        let mut signer_len = 0u32;
        CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_len)
            .map_err(|err| format!("CryptMsgGetParam(size): {}", err))?;
        if signer_len == 0 {
            return Ok(None);
        }

        let mut signer_buf = vec![0u8; signer_len as usize];
        CryptMsgGetParam(
            message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut signer_len,
        )
        .map_err(|err| format!("CryptMsgGetParam(data): {}", err))?;
        let signer = &*(signer_buf.as_ptr() as *const CMSG_SIGNER_INFO);

        let mut cert_info = signer_id_cert_info(signer);
        let cert = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&mut cert_info as *mut _ as *const core::ffi::c_void),
            None,
        );
        if cert.is_null() {
            return Ok(None);
        }
        let _cert_guard = CertContextGuard(cert);

        let name_len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if name_len <= 1 {
            return Ok(None);
        }

        let mut name_buf = vec![0u16; name_len as usize];
        let written = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        if written <= 1 {
            return Ok(None);
        }

        Ok(Some(
            String::from_utf16_lossy(&name_buf[..written as usize])
                .trim_end_matches('\0')
                .trim()
                .to_string(),
        )
        .filter(|value| !value.is_empty()))
    }
}

#[cfg(target_os = "windows")]
struct CryptQueryGuard {
    store: windows::Win32::Security::Cryptography::HCERTSTORE,
    message: *mut core::ffi::c_void,
}

#[cfg(target_os = "windows")]
impl Drop for CryptQueryGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.message.is_null() {
                let _ = windows::Win32::Security::Cryptography::CryptMsgClose(Some(self.message));
            }
            if !self.store.is_invalid() {
                let _ = windows::Win32::Security::Cryptography::CertCloseStore(self.store, 0);
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct CertContextGuard(*const windows::Win32::Security::Cryptography::CERT_CONTEXT);

#[cfg(target_os = "windows")]
impl Drop for CertContextGuard {
    fn drop(&mut self) {
        unsafe {
            let _ =
                windows::Win32::Security::Cryptography::CertFreeCertificateContext(Some(self.0));
        }
    }
}

fn signer_id_cert_info(
    signer: &windows::Win32::Security::Cryptography::CMSG_SIGNER_INFO,
) -> windows::Win32::Security::Cryptography::CERT_INFO {
    windows::Win32::Security::Cryptography::CERT_INFO {
        Issuer: signer.Issuer,
        SerialNumber: signer.SerialNumber,
        ..Default::default()
    }
}

pub fn thread_owner_pid(tid: u32) -> Result<u32, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let snapshot = SafeHandle::new(snapshot);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(*snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ThreadID == tid {
                    return Ok(entry.th32OwnerProcessID);
                }
                if Thread32Next(*snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Err(MemoricError::ProcessNotFound(tid))
}

/// Get process name from PID
pub fn get_process_name(pid: u64) -> Result<String, MemoricError> {
    get_process_snapshot_entry(pid as u32).map(|(name, _)| name)
}

fn get_process_snapshot_entry(pid: u32) -> Result<(String, u32), MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    return Ok((process_entry_name(&entry), entry.th32ParentProcessID));
                }
                if Process32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Err(MemoricError::ProcessNotFound(pid))
}

fn query_limited_process_identity(
    pid: u32,
) -> Result<(Option<String>, Option<u32>, Option<String>), String> {
    use windows::Win32::System::Threading::{
        GetProcessInformation, OpenProcess, ProcessProtectionLevelInfo, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_PROTECTION_LEVEL_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| format!("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION): {}", e))?;
        let handle = SafeHandle::new(handle);

        let mut path_buf = vec![0u16; 32768];
        let mut path_len = path_buf.len() as u32;
        let exe_path = match QueryFullProcessImageNameW(
            *handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(path_buf.as_mut_ptr()),
            &mut path_len,
        ) {
            Ok(_) => Some(String::from_utf16_lossy(&path_buf[..path_len as usize])),
            Err(err) => {
                tracing::debug!("QueryFullProcessImageNameW({}) failed: {}", pid, err);
                None
            }
        };

        let mut protection = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
        let protection_level = match GetProcessInformation(
            *handle,
            ProcessProtectionLevelInfo,
            &mut protection as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        ) {
            Ok(_) => Some(protection.ProtectionLevel.0),
            Err(err) => {
                tracing::debug!(
                    "GetProcessInformation(ProcessProtectionLevelInfo, {}) failed: {}",
                    pid,
                    err
                );
                None
            }
        };
        let protection_name = protection_level
            .map(protection_level_name)
            .map(str::to_string);

        Ok((exe_path, protection_level, protection_name))
    }
}

fn get_process_session_id(pid: u32) -> Result<u32, String> {
    let mut session_id = 0u32;
    unsafe {
        windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut session_id)
            .map_err(|e| format!("ProcessIdToSessionId: {}", e))?;
    }
    Ok(session_id)
}

fn process_entry_name(
    entry: &windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W,
) -> String {
    String::from_utf16_lossy(&entry.szExeFile)
        .trim_end_matches('\0')
        .to_string()
}

fn protection_level_name(level: u32) -> &'static str {
    use windows::Win32::System::Threading::{
        PROTECTION_LEVEL_ANTIMALWARE_LIGHT, PROTECTION_LEVEL_AUTHENTICODE,
        PROTECTION_LEVEL_CODEGEN_LIGHT, PROTECTION_LEVEL_LSA_LIGHT, PROTECTION_LEVEL_NONE,
        PROTECTION_LEVEL_PPL_APP, PROTECTION_LEVEL_WINDOWS, PROTECTION_LEVEL_WINDOWS_LIGHT,
        PROTECTION_LEVEL_WINTCB, PROTECTION_LEVEL_WINTCB_LIGHT,
    };

    match level {
        value if value == PROTECTION_LEVEL_NONE.0 => "none",
        value if value == PROTECTION_LEVEL_WINTCB_LIGHT.0 => "wintcb-light",
        value if value == PROTECTION_LEVEL_WINDOWS.0 => "windows",
        value if value == PROTECTION_LEVEL_WINDOWS_LIGHT.0 => "windows-light",
        value if value == PROTECTION_LEVEL_ANTIMALWARE_LIGHT.0 => "antimalware-light",
        value if value == PROTECTION_LEVEL_LSA_LIGHT.0 => "lsa-light",
        value if value == PROTECTION_LEVEL_WINTCB.0 => "wintcb",
        value if value == PROTECTION_LEVEL_CODEGEN_LIGHT.0 => "codegen-light",
        value if value == PROTECTION_LEVEL_AUTHENTICODE.0 => "authenticode",
        value if value == PROTECTION_LEVEL_PPL_APP.0 => "ppl-app",
        _ => "unknown",
    }
}

pub fn is_critical_process_name(name: &str) -> bool {
    let normalized = name.trim().trim_end_matches('\0').to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "system"
            | "system idle process"
            | "registry"
            | "secure system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "services.exe"
            | "lsass.exe"
            | "lsm.exe"
    )
}

/// Get process command line via NtQueryInformationProcess + PEB
fn get_process_cmdline(pid: u64) -> Result<String, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess for cmdline: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // NtQueryInformationProcess(ProcessBasicInformation) to get PEB address
        #[repr(C)]
        struct ProcessBasicInfo {
            exit_status: i32,
            _pad0: u32,
            peb_base_address: u64,
            affinity_mask: u64,
            base_priority: i32,
            _pad1: u32,
            unique_process_id: u64,
            inherited_from_unique_process_id: u64,
        }

        let mut pbi: ProcessBasicInfo = std::mem::zeroed();
        let mut ret_len = 0u32;
        let status = ntapi::ntpsapi::NtQueryInformationProcess(
            (*handle).0 as *mut _,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInfo>() as u32,
            &mut ret_len,
        );
        if status != 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtQueryInformationProcess failed: 0x{:08X}",
                status
            )));
        }

        // Read PEB.ProcessParameters (offset 0x20 on x64)
        let mut params_ptr: u64 = 0;
        ReadProcessMemory(
            *handle,
            (pbi.peb_base_address + 0x20) as *const _,
            &mut params_ptr as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read PEB params ptr: {}", e)))?;

        if params_ptr == 0 {
            return Ok(String::new());
        }

        // Read RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING at offset 0x70)
        // UNICODE_STRING: Length(u16) + MaxLength(u16) + pad(u32) + Buffer(u64)
        let mut cmd_len: u16 = 0;
        ReadProcessMemory(
            *handle,
            (params_ptr + 0x70) as *const _,
            &mut cmd_len as *mut _ as *mut _,
            2,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read cmdline length: {}", e)))?;

        if cmd_len == 0 || cmd_len > 32766 {
            return Ok(String::new());
        }

        let mut cmd_buf_ptr: u64 = 0;
        ReadProcessMemory(
            *handle,
            (params_ptr + 0x78) as *const _,
            &mut cmd_buf_ptr as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read cmdline buffer ptr: {}", e)))?;

        if cmd_buf_ptr == 0 {
            return Ok(String::new());
        }

        // Read the actual command line (wide chars)
        let wchar_count = cmd_len as usize / 2;
        let mut cmd_buf = vec![0u16; wchar_count];
        ReadProcessMemory(
            *handle,
            cmd_buf_ptr as *const _,
            cmd_buf.as_mut_ptr() as *mut _,
            cmd_len as usize,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read cmdline data: {}", e)))?;

        Ok(String::from_utf16_lossy(&cmd_buf))
    }
}

/// Check if process is 64-bit
fn is_process_64bit(pid: u32) -> Result<bool, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::IsWow64Process;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut found = false;
        if Process32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    found = true;
                    break;
                }
                if Process32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        if !found {
            return Err(MemoricError::ProcessNotFound(pid));
        }

        #[cfg(target_arch = "x86_64")]
        {
            use windows::Win32::Foundation::BOOL;
            let mut is_wow64 = BOOL::default();
            let handle = windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
                false,
                pid,
            );

            if let Ok(h) = handle {
                let handle = SafeHandle::new(h);
                let result = IsWow64Process(*handle, &mut is_wow64);
                if result.is_ok() {
                    return Ok(is_wow64.0 == 0);
                }
            }
            Ok(true)
        }

        #[cfg(target_arch = "x86")]
        {
            Ok(false)
        }
    }
}

/// Enable SeDebugPrivilege
pub fn enable_debug_privilege(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    tracing::warn!("[REDTEAM] Enabling SeDebugPrivilege");

    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open token: {}", e)))?;
        let _token = SafeHandle::new(token_handle);

        let mut luid = std::mem::zeroed();
        LookupPrivilegeValueW(None, windows::Win32::Security::SE_DEBUG_NAME, &mut luid)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to lookup privilege: {}", e)))?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(
            *_token,
            false,
            Some(&tp as *const _ as *const _),
            0,
            None,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to adjust privileges: {}", e)))?;

        tracing::info!("SeDebugPrivilege enabled successfully");

        Ok(serde_json::json!({
            "success": true,
            "message": "SeDebugPrivilege enabled successfully"
        }))
    }
}

/// Find processes by name
pub fn find_process(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing process name".to_string()))?;

    tracing::debug!("Finding processes matching: {}", name);

    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                let proc_name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if proc_name.contains(&name.to_lowercase()) {
                    processes.push(serde_json::json!({
                        "pid": entry.th32ProcessID,
                        "ppid": entry.th32ParentProcessID,
                        "name": proc_name,
                        "full_path": proc_name
                    }));
                }

                if Process32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!("Found {} processes matching '{}'", processes.len(), name);

    Ok(serde_json::json!({
        "count": processes.len(),
        "search_term": name,
        "processes": processes
    }))
}
