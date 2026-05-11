//! Auto-elevation module for spawning elevated Worker process

use crate::error::{MemoricError, Result};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS};

/// Check if current process is elevated
pub fn is_elevated() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ACCESS_MASK, TOKEN_ELEVATION,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = Default::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(0x0008), // TOKEN_QUERY
            &mut token_handle,
        )
        .is_err()
        {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;

        if GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_err()
        {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

/// Spawn elevated Worker process using runas
pub fn spawn_elevated() -> Result<()> {
    use windows::Win32::System::Threading::WaitForSingleObject;

    unsafe {
        // Get current executable path
        let mut path_buf = [0u16; 512];
        let len = GetModuleFileNameW(None, &mut path_buf);
        if len == 0 {
            return Err(MemoricError::WindowsApi(
                "Failed to get module path".to_string(),
            ));
        }

        let exe_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        tracing::info!("Executable path: {}", exe_path);

        // Build command line: memoric.exe --worker
        let verb = "runas\0".encode_utf16().collect::<Vec<u16>>();
        let params = "--worker\0".encode_utf16().collect::<Vec<u16>>();

        let mut sei = windows::Win32::UI::Shell::SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<windows::Win32::UI::Shell::SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: HWND::default(),
            lpVerb: windows::core::PCWSTR(verb.as_ptr()),
            lpFile: windows::core::PCWSTR(path_buf.as_ptr()),
            lpParameters: windows::core::PCWSTR(params.as_ptr()),
            lpDirectory: windows::core::PCWSTR([0].as_ptr()),
            nShow: 1, // SW_SHOWNORMAL - show window so user sees UAC
            ..Default::default()
        };

        tracing::info!("Requesting UAC elevation...");

        match ShellExecuteExW(&mut sei) {
            Ok(_) => {
                tracing::info!("UAC elevation requested, waiting for Worker to start...");

                // Don't wait for process to complete, just let it run
                // The proxy will connect via Named Pipe
                if !sei.hProcess.is_invalid() {
                    // Give Worker time to initialize (up to 10 seconds)
                    tracing::debug!("Waiting for Worker initialization...");
                    let wait_result = WaitForSingleObject(sei.hProcess, 10000);
                    tracing::debug!("Wait result: {:?}", wait_result);
                    let _ = windows::Win32::Foundation::CloseHandle(sei.hProcess);
                }

                tracing::info!("Elevated Worker process spawned");
            }
            Err(e) => {
                // Common errors: user cancelled UAC, policy blocks elevation
                tracing::error!("UAC elevation failed: {}", e);

                return Err(MemoricError::PermissionDenied(format!(
                    "UAC elevation failed: {}. Please run Claude Desktop as Administrator.",
                    e
                )));
            }
        }
    }

    Ok(())
}
