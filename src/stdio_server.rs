//! STDIO MCP Server - direct stdin/stdout communication
//! This is the default mode, used by Claude Code and any MCP client.
//!
//! If not elevated, responds to initialize/tools/list locally, and lazily
//! spawns an elevated Worker via UAC only when the first tools/call arrives.
//! If already elevated, handles everything directly in-process.

use crate::error::MemoricError;
use crate::ipc::PipeServer;
use crate::mcp::tools::{call_tool, register_tools};
use serde_json::Value;
use std::io::{self, BufRead, Write};

/// Entry point
pub fn run_stdio() -> crate::error::Result<()> {
    tracing::info!(
        "Starting memoric STDIO MCP server (PID: {})",
        std::process::id()
    );

    let elevated = crate::elevation::is_elevated();
    if elevated {
        tracing::info!("Running with elevated privileges — direct mode");
    } else {
        tracing::info!("Running without elevation — will UAC on first tool call");
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    // Lazy worker connection (only created when needed and not elevated)
    let mut worker: Option<PipeServer> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to read stdin: {}", e);
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        tracing::debug!("Received: {}", line);

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to parse JSON: {}", e);
                continue;
            }
        };

        let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let id = request.get("id").cloned();

        // Notifications: no response
        if method.starts_with("notifications/") {
            continue;
        }

        let response = match method {
            // These are always handled locally (fast, no elevation needed)
            "initialize" => {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "memoric", "version": "0.1.0" }
                    }
                })
            }
            "tools/list" => {
                let tools = register_tools();
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": tools }
                })
            }
            "ping" => {
                serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} })
            }
            // tools/call: needs elevation
            "tools/call" => {
                if elevated {
                    handle_tools_call_direct(&request)
                } else {
                    // Bridged mode: ensure Worker is running, then forward
                    if worker.is_none() {
                        tracing::info!("First tools/call — spawning elevated Worker...");
                        match ensure_worker() {
                            Ok(server) => {
                                worker = Some(server);
                                tracing::info!("Elevated Worker ready");
                            }
                            Err(e) => {
                                tracing::error!("Failed to spawn elevated Worker: {}", e);
                            }
                        }
                    }

                    if let Some(ref server) = worker {
                        match forward_to_worker_safe(server, &request) {
                            Ok(response) => response,
                            Err(err_response) => {
                                // Pipe is broken — drop worker so next call re-spawns
                                tracing::warn!(
                                    "Worker pipe broken, will re-spawn on next call: {}",
                                    err_response
                                );
                                worker = None;
                                err_response
                            }
                        }
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{ "type": "text", "text": "Worker not available — UAC elevation was not approved. Run Claude Code as Administrator or accept the UAC prompt." }],
                                "isError": true
                            }
                        })
                    }
                }
            }
            _ => {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": format!("Method not found: {}", method) }
                })
            }
        };

        let response_str = serde_json::to_string(&response).unwrap();
        if let Err(e) = writeln!(stdout, "{}", response_str) {
            tracing::error!("Failed to write stdout: {}", e);
            break;
        }
        if let Err(e) = stdout.flush() {
            tracing::error!("Failed to flush stdout: {}", e);
            break;
        }
    }

    tracing::info!("STDIO server shutting down");
    Ok(())
}

/// Handle tools/call directly (elevated mode)
fn handle_tools_call_direct(request: &Value) -> Value {
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));
    let id = request.get("id").cloned();

    let name_owned = name.to_string();
    let args_for_call = args.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call_tool(&name_owned, args_for_call)
    }));

    match result {
        Ok(Ok(result)) => {
            let text = serde_json::to_string(&result).unwrap_or_default();
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }]
                }
            })
        }
        Ok(Err(e)) => {
            let text = crate::mcp::tools::tool_error_text(&name_owned, &args, &e);
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": true
                }
            })
        }
        Err(panic_info) => {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic in tool handler".to_string()
            };
            let text = crate::mcp::tools::tool_error_text(
                &name_owned,
                &args,
                &format!("Internal panic in tool '{}': {}", name_owned, panic_msg),
            );
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": true
                }
            })
        }
    }
}

/// Spawn elevated Worker and wait for it to connect via Named Pipe
fn ensure_worker() -> crate::error::Result<PipeServer> {
    // Create pipe server
    let mut server = PipeServer::new()?;

    // Spawn elevated Worker
    spawn_elevated_worker()?;

    // Wait for connection (with timeout handled by pipe server)
    server.wait_for_client()?;

    Ok(server)
}

/// Forward a JSON-RPC request to Worker over Named Pipe, return response.
/// Returns Ok(response) on success, Err(error_response) on pipe failure (so caller can drop worker).
fn forward_to_worker_safe(server: &PipeServer, request: &Value) -> Result<Value, Value> {
    let id = request.get("id").cloned();
    let request_str = serde_json::to_string(request).unwrap();

    if let Err(e) = server.write_message(request_str.as_bytes()) {
        tracing::error!("Failed to write to Worker: {}", e);
        return Err(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{ "type": "text", "text": format!("Worker pipe broken (write): {}. Will re-spawn on next call.", e) }],
                "isError": true
            }
        }));
    }

    match server.read_message() {
        Ok(bytes) => {
            let response_str = String::from_utf8_lossy(&bytes);
            match serde_json::from_str::<Value>(&response_str) {
                Ok(v) => Ok(v),
                Err(e) => {
                    tracing::error!("Failed to parse Worker response: {}", e);
                    Err(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{ "type": "text", "text": format!("Worker response parse error: {}. Will re-spawn on next call.", e) }],
                            "isError": true
                        }
                    }))
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to read from Worker: {}", e);
            Err(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Worker pipe broken (read): {}. Will re-spawn on next call.", e) }],
                    "isError": true
                }
            }))
        }
    }
}

/// Spawn elevated Worker process using ShellExecuteEx + runas
fn spawn_elevated_worker() -> crate::error::Result<()> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS};

    unsafe {
        let mut path_buf = [0u16; 512];
        let len = GetModuleFileNameW(None, &mut path_buf);
        if len == 0 {
            return Err(MemoricError::WindowsApi(
                "Failed to get module path".to_string(),
            ));
        }

        let exe_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        tracing::info!("Spawning elevated Worker: {} --worker", exe_path);

        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let params: Vec<u16> = "--worker\0".encode_utf16().collect();

        let mut sei = windows::Win32::UI::Shell::SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<windows::Win32::UI::Shell::SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: HWND::default(),
            lpVerb: windows::core::PCWSTR(verb.as_ptr()),
            lpFile: windows::core::PCWSTR(path_buf.as_ptr()),
            lpParameters: windows::core::PCWSTR(params.as_ptr()),
            lpDirectory: windows::core::PCWSTR::null(),
            nShow: 1, // SW_SHOWNORMAL - needed for UAC dialog to appear
            ..Default::default()
        };

        ShellExecuteExW(&mut sei).map_err(|e| {
            MemoricError::PermissionDenied(format!(
                "UAC elevation failed: {}. User may have cancelled the UAC prompt.",
                e
            ))
        })?;

        if !sei.hProcess.is_invalid() {
            let _ = windows::Win32::Foundation::CloseHandle(sei.hProcess);
        }

        // Give Worker time to start and connect
        std::thread::sleep(std::time::Duration::from_millis(2000));

        tracing::info!("Elevated Worker spawned");
        Ok(())
    }
}
