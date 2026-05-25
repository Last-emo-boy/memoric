//! STDIO MCP Server - direct stdin/stdout communication
//! This is the default mode, used by Claude Code and any MCP client.
//!
//! If not elevated, responds to initialize/tools/list locally, and lazily
//! spawns an elevated Worker via UAC only when the first tools/call arrives.
//! If already elevated, handles everything directly in-process.

use crate::error::MemoricError;
use crate::ipc::PipeServer;
use crate::mcp::protocol::{initialize_result, tool_error_content, tool_success_content};
use crate::mcp::tool_call::call_tool;
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

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
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let (notification_tx, notification_rx) = mpsc::channel::<Value>();
    crate::mcp::tasks::set_notification_sender(Some(notification_tx));
    let notification_stdout = Arc::clone(&stdout);
    let notification_writer = std::thread::Builder::new()
        .name("memoric-stdio-notifications".to_string())
        .spawn(move || {
            for notification in notification_rx {
                if let Err(err) = write_json_value(&notification_stdout, &notification) {
                    tracing::error!("Failed to write task notification: {}", err);
                    break;
                }
            }
        })
        .map_err(|err| {
            MemoricError::IpcError(format!("failed to spawn notification writer: {}", err))
        })?;
    // Lazy worker connection (only created when needed and not elevated)
    let mut worker: Option<WorkerBridge> = None;

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
                let response = crate::mcp::protocol::json_rpc_error_value(
                    -32700,
                    &format!("Parse error: {}", e),
                    None,
                );
                if let Err(e) = write_json_value(&stdout, &response) {
                    tracing::error!("Failed to write parse error response: {}", e);
                    break;
                }
                continue;
            }
        };

        let parts = match crate::mcp::protocol::validate_json_rpc_request(&request) {
            Ok(parts) => parts,
            Err(response) => {
                if let Err(e) = write_json_value(&stdout, &response) {
                    tracing::error!("Failed to write invalid request response: {}", e);
                    break;
                }
                continue;
            }
        };
        if !parts.expects_response {
            continue;
        }
        let method = parts.method;
        let id = parts.id.clone();

        let response = match method {
            // These are always handled locally (fast, no elevation needed)
            "initialize" => {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": initialize_result("memoric")
                })
            }
            "tools/list" => match crate::mcp::tools::list_request(&request) {
                Ok(result) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                }),
                Err(err) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": err }
                }),
            },
            "resources/list" => match crate::mcp::resources::list_request(&request) {
                Ok(result) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                }),
                Err(err) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": err }
                }),
            },
            "resources/templates/list" => {
                match crate::mcp::resources::templates_list_request(&request) {
                    Ok(result) => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": result
                    }),
                    Err(err) => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32602, "message": err }
                    }),
                }
            }
            "resources/read" => match crate::mcp::resources::read_request(&request) {
                Ok(result) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                }),
                Err(err) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": err }
                }),
            },
            "tasks/list"
            | "tasks/get"
            | "tasks/result"
            | "tasks/cancel"
            | "tasks/input_response"
            | "tasks/update" => {
                if !elevated {
                    if let Some(ref bridge) = worker {
                        match bridge.forward_request(&request) {
                            Ok(response) => response,
                            Err(err_response) => {
                                tracing::warn!(
                                    "Worker pipe broken during task request, will re-spawn on next tool call: {}",
                                    err_response
                                );
                                worker = None;
                                err_response
                            }
                        }
                    } else {
                        handle_local_task_request(method, &request, &id)
                    }
                } else {
                    handle_local_task_request(method, &request, &id)
                }
            }
            "ping" => {
                serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": Value::Null })
            }
            method if crate::mcp::protocol::is_app_bridge_host_only_method(method) => {
                crate::mcp::protocol::app_bridge_unsupported_error_value(method, id)
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
                                worker = Some(WorkerBridge::new(server, Arc::clone(&stdout)));
                                tracing::info!("Elevated Worker ready");
                            }
                            Err(e) => {
                                tracing::error!("Failed to spawn elevated Worker: {}", e);
                            }
                        }
                    }

                    if let Some(ref bridge) = worker {
                        match bridge.forward_request(&request) {
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

        if let Err(e) = write_json_value(&stdout, &response) {
            tracing::error!("Failed to write stdout: {}", e);
            break;
        }
    }

    crate::mcp::tasks::set_notification_sender(None);
    let _ = notification_writer.join();
    tracing::info!("STDIO server shutting down");
    Ok(())
}

fn write_json_value(stdout: &Arc<Mutex<io::Stdout>>, value: &Value) -> io::Result<()> {
    let response_str = serde_json::to_string(value)?;
    let mut stdout = stdout
        .lock()
        .map_err(|_| io::Error::other("stdout mutex poisoned"))?;
    writeln!(stdout, "{}", response_str)?;
    stdout.flush()
}

#[cfg(test)]
fn handle_stdio_request_for_test(raw: &str) -> String {
    let request: Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(err) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32700, "message": format!("Parse error: {}", err) }
            })
            .to_string();
        }
    };

    match handle_stdio_direct_request_for_test(&request) {
        Some(response) => response.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
fn handle_stdio_direct_request_for_test(request: &Value) -> Option<Value> {
    let parts = match crate::mcp::protocol::validate_json_rpc_request(request) {
        Ok(parts) => parts,
        Err(error) => return Some(error),
    };
    if !parts.expects_response {
        return None;
    }
    let id = parts.id.clone();
    let method = parts.method;

    let response = match method {
        "initialize" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": initialize_result("memoric")
        }),
        "tools/list" => stdio_string_result_response(id, crate::mcp::tools::list_request(request)),
        "tools/call" => handle_tools_call_direct(request),
        "resources/list" => {
            stdio_string_result_response(id, crate::mcp::resources::list_request(request))
        }
        "resources/templates/list" => {
            stdio_string_result_response(id, crate::mcp::resources::templates_list_request(request))
        }
        "resources/read" => {
            stdio_string_result_response(id, crate::mcp::resources::read_request(request))
        }
        "tasks/list"
        | "tasks/get"
        | "tasks/result"
        | "tasks/cancel"
        | "tasks/input_response"
        | "tasks/update" => handle_local_task_request(method, request, &id),
        "ping" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": Value::Null
        }),
        method if crate::mcp::protocol::is_app_bridge_host_only_method(method) => {
            crate::mcp::protocol::app_bridge_unsupported_error_value(method, id)
        }
        _ => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {}", method) }
        }),
    };

    Some(response)
}

#[cfg(test)]
fn stdio_string_result_response(
    id: Option<Value>,
    result: std::result::Result<Value, String>,
) -> Value {
    match result {
        Ok(result) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        }),
        Err(err) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32602, "message": err }
        }),
    }
}

/// Handle tools/call directly (elevated mode)
fn handle_tools_call_direct(request: &Value) -> Value {
    crate::mcp::request_context::with_request_context_from_request(
        request,
        crate::mcp::request_context::McpTransportKind::Stdio,
        || {
            crate::observability::record_mcp_request(
                crate::mcp::request_context::McpTransportKind::Stdio,
                request,
            );
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));
            let id = request.get("id").cloned();
            let name_owned = name.to_string();
            let task_augmented = crate::mcp::tasks::is_task_augmented_request(request);
            let as_task = args
                .get("as_task")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if task_augmented || as_task {
                let options = if task_augmented {
                    crate::mcp::tasks::task_options_from_request(request)
                } else {
                    crate::mcp::tasks::TaskOptions::default()
                };
                return match crate::mcp::tasks::spawn_tool_task_with_options(
                    &name_owned,
                    &args,
                    options,
                ) {
                    Ok(task_id) if task_augmented => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": crate::mcp::tasks::task_create_result(&task_id)
                    }),
                    Ok(task_id) => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": crate::mcp::tasks::task_accepted_content(&name_owned, &args, &task_id)
                    }),
                    Err(err) => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": tool_error_content(&name_owned, &args, &err)
                    }),
                };
            }

            let args_for_call = args.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                call_tool(&name_owned, args_for_call)
            }));

            match result {
                Ok(Ok(result)) => {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": tool_success_content(&name_owned, &args, &result)
                    })
                }
                Ok(Err(e)) => {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": tool_error_content(&name_owned, &args, &e)
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
                    let message = format!("Internal panic in tool '{}': {}", name_owned, panic_msg);
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": tool_error_content(&name_owned, &args, &message)
                    })
                }
            }
        },
    )
}

fn handle_local_task_request(method: &str, request: &Value, id: &Option<Value>) -> Value {
    let result = match method {
        "tasks/list" => crate::mcp::tasks::list_request(request),
        "tasks/get" => crate::mcp::tasks::get_request(request),
        "tasks/result" => crate::mcp::tasks::result_request(request),
        "tasks/cancel" => crate::mcp::tasks::cancel_request(request),
        "tasks/input_response" => crate::mcp::tasks::input_response_request(request),
        "tasks/update" => crate::mcp::tasks::update_request(request),
        _ => Err(format!("Method not found: {}", method)),
    };

    match result {
        Ok(result) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        }),
        Err(err) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32602, "message": err }
        }),
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
struct WorkerBridge {
    server: Arc<PipeServer>,
    responses: Receiver<Result<Value, String>>,
}

impl WorkerBridge {
    fn new(server: PipeServer, stdout: Arc<Mutex<io::Stdout>>) -> Self {
        let server = Arc::new(server);
        let reader_server = Arc::clone(&server);
        let (response_tx, responses) = mpsc::channel::<Result<Value, String>>();

        let _ = std::thread::Builder::new()
            .name("memoric-worker-reader".to_string())
            .spawn(move || loop {
                let bytes = match reader_server.read_message() {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        let _ =
                            response_tx.send(Err(format!("Worker pipe broken (read): {}", err)));
                        break;
                    }
                };

                let response_str = String::from_utf8_lossy(&bytes);
                match serde_json::from_str::<Value>(&response_str) {
                    Ok(value) if is_json_rpc_notification(&value) => {
                        if let Err(err) = write_json_value(&stdout, &value) {
                            let _ = response_tx
                                .send(Err(format!("Worker notification forward error: {}", err)));
                            break;
                        }
                    }
                    Ok(value) => {
                        if response_tx.send(Ok(value)).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ =
                            response_tx.send(Err(format!("Worker response parse error: {}", err)));
                        break;
                    }
                }
            });

        Self { server, responses }
    }

    fn forward_request(&self, request: &Value) -> Result<Value, Value> {
        let id = request.get("id").cloned();
        let request_str = serde_json::to_string(request).unwrap();

        if let Err(e) = self.server.write_message(request_str.as_bytes()) {
            tracing::error!("Failed to write to Worker: {}", e);
            return Err(worker_bridge_error(
                id,
                format!(
                    "Worker pipe broken (write): {}. Will re-spawn on next call.",
                    e
                ),
            ));
        }

        match self.responses.recv() {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => {
                tracing::error!("Worker bridge error: {}", err);
                Err(worker_bridge_error(
                    id,
                    format!("{}. Will re-spawn on next call.", err),
                ))
            }
            Err(err) => {
                tracing::error!("Worker response channel closed: {}", err);
                Err(worker_bridge_error(
                    id,
                    format!(
                        "Worker response channel closed: {}. Will re-spawn on next call.",
                        err
                    ),
                ))
            }
        }
    }
}

fn worker_bridge_error(id: Option<Value>, message: String) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": message }],
            "isError": true
        }
    })
}

fn is_json_rpc_notification(value: &Value) -> bool {
    value.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
        && value.get("id").is_none()
        && value
            .get("method")
            .and_then(|v| v.as_str())
            .is_some_and(|method| method.starts_with("notifications/"))
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

#[cfg(test)]
mod tests {
    use super::handle_stdio_request_for_test;
    use serde_json::json;

    #[test]
    fn stdio_direct_conformance_fixtures_cover_core_methods() {
        crate::mcp::conformance::run_conformance("stdio-direct", |case| {
            handle_stdio_request_for_test(&case.request)
        });
    }

    #[test]
    fn stdio_direct_adversarial_fixtures_are_stable() {
        crate::mcp::conformance::run_adversarial_conformance("stdio-direct", |case| {
            handle_stdio_request_for_test(&case.request)
        });
    }

    #[test]
    fn stdio_direct_records_app_origin_in_timeline_events() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "ui-origin-stdio",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": {
                    "action": "version",
                    "request_id": "ui-origin-stdio"
                },
                "_meta": {
                    "io.memoric/app-origin": "ui://memoric/dashboard"
                }
            }
        });

        let _ = handle_stdio_request_for_test(&request.to_string());
        let timeline = crate::observability::timeline_json(&json!({
            "correlation_id": "ui-origin-stdio",
            "limit": 20,
            "redaction": "strict"
        }));

        let events = timeline["events"].as_array().expect("timeline events");
        assert!(events.iter().any(|event| {
            event["kind"] == "mcp.request"
                && event["correlation_id"] == "ui-origin-stdio"
                && event["details"]["app_origin"] == "ui://memoric/dashboard"
                && event["details"]["policy_origin"] == "app"
        }));
    }
}
