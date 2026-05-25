//! Worker mode - runs with elevated privileges (High IL)
//! Connects to Proxy's Named Pipe Server
//! Executes privileged memory operations

use crate::error::{MemoricError, Result};
use crate::ipc::PipeClient;
use crate::mcp::protocol::{initialize_result, tool_error_content, tool_success_content};
use crate::mcp::tool_call::call_tool;
use serde_json::Value;
use std::sync::{mpsc, Arc, Mutex};

pub fn run_worker() -> Result<()> {
    // Log to stderr (will be captured by Windows Event Log for elevated processes)

    tracing::info!("=== Worker starting ===");
    tracing::info!("Worker PID: {}", std::process::id());
    tracing::info!("Worker mode (elevated)");

    // Verify we're elevated
    if !crate::elevation::is_elevated() {
        tracing::error!("Worker NOT elevated! This is a problem.");

        return Err(MemoricError::PermissionDenied(
            "Worker must run as elevated".to_string(),
        ));
    }

    tracing::info!("Worker is elevated: OK");

    // Connect to Proxy's Named Pipe Server
    tracing::info!("Connecting to Proxy's Named Pipe...");

    let pipe = match PipeClient::connect() {
        Ok(client) => {
            tracing::info!("Connected to Proxy successfully");

            Arc::new(client)
        }
        Err(e) => {
            tracing::error!("Failed to connect to Proxy: {}", e);

            return Err(e);
        }
    };

    run_worker_pipe_loop(pipe)
}

fn run_worker_pipe_loop(pipe: Arc<PipeClient>) -> Result<()> {
    tracing::info!("=== Worker ready, processing requests ===");
    let (notification_tx, notification_rx) = mpsc::channel::<Value>();
    crate::mcp::tasks::set_notification_sender(Some(notification_tx));
    let notification_pipe = Arc::clone(&pipe);
    let write_lock = Arc::new(Mutex::new(()));
    let notification_write_lock = Arc::clone(&write_lock);
    let notification_writer = std::thread::Builder::new()
        .name("memoric-worker-notifications".to_string())
        .spawn(move || {
            for notification in notification_rx {
                let notification_str = match serde_json::to_string(&notification) {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::error!("Failed to serialize worker notification: {}", err);
                        continue;
                    }
                };
                if let Err(err) = write_pipe_message(
                    &notification_pipe,
                    &notification_write_lock,
                    notification_str.as_bytes(),
                ) {
                    tracing::error!("Failed to send worker notification: {}", err);
                    break;
                }
            }
        })
        .map_err(|err| {
            MemoricError::IpcError(format!(
                "failed to spawn worker notification writer: {}",
                err
            ))
        })?;

    // Main request loop
    tracing::info!("Waiting for requests from Proxy...");

    loop {
        match pipe.read_message() {
            Ok(data) => {
                if !process_worker_pipe_message(&pipe, &write_lock, data) {
                    break;
                }
            }
            Err(e) => {
                tracing::error!("Read error: {}", e);
                break;
            }
        }
    }

    crate::mcp::tasks::set_notification_sender(None);
    let _ = notification_writer.join();
    tracing::info!("Worker shutting down...");

    Ok(())
}

fn process_worker_pipe_message(pipe: &PipeClient, write_lock: &Mutex<()>, data: Vec<u8>) -> bool {
    if data.is_empty() {
        tracing::warn!("Received empty message, breaking loop");
        return false;
    }

    let request_str = String::from_utf8_lossy(&data);
    tracing::info!("Received from Proxy: {}", request_str);

    let request: Value = match serde_json::from_str(&request_str) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!("Failed to parse JSON: {}", err);
            let response = crate::mcp::protocol::json_rpc_error_value(
                -32700,
                &format!("Parse error: {}", err),
                None,
            );
            let response_str = response.to_string();
            if let Err(write_err) = write_pipe_message(pipe, write_lock, response_str.as_bytes()) {
                tracing::error!("Failed to send parse error response: {}", write_err);
                return false;
            }
            return true;
        }
    };

    handle_request(pipe, write_lock, &request);
    true
}

#[cfg(test)]
fn run_worker_pipe_messages_for_test(pipe: Arc<PipeClient>, message_count: usize) -> Result<()> {
    let write_lock = Mutex::new(());
    for _ in 0..message_count {
        let data = pipe.read_message()?;
        if !process_worker_pipe_message(&pipe, &write_lock, data) {
            break;
        }
    }
    Ok(())
}

/// Handle a JSON-RPC request
fn handle_request(pipe: &PipeClient, write_lock: &Mutex<()>, request: &Value) {
    let parts = match crate::mcp::protocol::validate_json_rpc_request(request) {
        Ok(parts) => parts,
        Err(response) => {
            let _ = write_pipe_message(pipe, write_lock, response.to_string().as_bytes());
            return;
        }
    };
    if !parts.expects_response {
        tracing::info!("Received notification: {}", parts.method);
        return;
    }
    let method = parts.method;
    let id = parts.id.clone().unwrap_or(Value::Null);

    // Handle method
    match method {
        "initialize" => {
            let result = handle_initialize(request);
            send_response(pipe, write_lock, &id, result);
        }
        "tools/list" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tools::list_request(request),
            );
        }
        "tools/call" => {
            let result = handle_tools_call(request);
            send_response(pipe, write_lock, &id, result);
        }
        "resources/list" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::resources::list_request(request),
            );
        }
        "resources/templates/list" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::resources::templates_list_request(request),
            );
        }
        "resources/read" => {
            let result = crate::mcp::resources::read_request(request)
                .map_err(crate::error::MemoricError::IpcError);
            send_response(pipe, write_lock, &id, result);
        }
        "tasks/list" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tasks::list_request(request),
            );
        }
        "tasks/get" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tasks::get_request(request),
            );
        }
        "tasks/result" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tasks::result_request(request),
            );
        }
        "tasks/cancel" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tasks::cancel_request(request),
            );
        }
        "tasks/input_response" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tasks::input_response_request(request),
            );
        }
        "tasks/update" => {
            send_task_response(
                pipe,
                write_lock,
                &id,
                crate::mcp::tasks::update_request(request),
            );
        }
        "notifications/initialized" => {
            // This is a notification, no response needed
            tracing::info!("Received notifications/initialized");
        }
        "ping" => {
            let result = Ok(Value::Null);
            send_response(pipe, write_lock, &id, result);
        }
        method if crate::mcp::protocol::is_app_bridge_host_only_method(method) => {
            let response =
                crate::mcp::protocol::app_bridge_unsupported_error_value(method, Some(id));
            let _ = write_pipe_message(pipe, write_lock, response.to_string().as_bytes());
        }
        _ => {
            // JSON-RPC -32601: Method not found
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Method not found: {}", method)},
                "id": id
            });
            let _ = write_pipe_message(pipe, write_lock, response.to_string().as_bytes());
        }
    };
}

/// Send a response to Proxy
fn send_response(pipe: &PipeClient, write_lock: &Mutex<()>, id: &Value, result: Result<Value>) {
    let response = match result {
        Ok(result_value) => {
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": result_value,
                "id": id
            })
        }
        Err(e) => {
            serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": e.to_string()},
                "id": id
            })
        }
    };
    crate::observability::record_worker_ipc_event("outbound", "response", &response);

    let response_str = match serde_json::to_string(&response) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to serialize response: {}", e);
            return;
        }
    };

    tracing::info!("Sending to Proxy: {}", response_str);

    if let Err(e) = write_pipe_message(pipe, write_lock, response_str.as_bytes()) {
        tracing::error!("Failed to send response: {}", e);
    }
}

fn send_task_response(
    pipe: &PipeClient,
    write_lock: &Mutex<()>,
    id: &Value,
    result: std::result::Result<Value, String>,
) {
    let response = match result {
        Ok(result_value) => {
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": result_value,
                "id": id
            })
        }
        Err(err) => {
            serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": err},
                "id": id
            })
        }
    };
    crate::observability::record_worker_ipc_event("outbound", "response", &response);

    let response_str = match serde_json::to_string(&response) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to serialize task response: {}", e);
            return;
        }
    };

    tracing::info!("Sending task response to Proxy: {}", response_str);

    if let Err(e) = write_pipe_message(pipe, write_lock, response_str.as_bytes()) {
        tracing::error!("Failed to send task response: {}", e);
    }
}

fn write_pipe_message(pipe: &PipeClient, write_lock: &Mutex<()>, data: &[u8]) -> Result<()> {
    let _guard = write_lock
        .lock()
        .map_err(|_| MemoricError::IpcError("worker pipe write lock poisoned".to_string()))?;
    pipe.write_message(data)
}

#[cfg(test)]
fn handle_worker_request_for_test(raw: &str) -> String {
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

    match handle_worker_value_for_test(&request) {
        Some(response) => response.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
fn handle_worker_value_for_test(request: &Value) -> Option<Value> {
    let parts = match crate::mcp::protocol::validate_json_rpc_request(request) {
        Ok(parts) => parts,
        Err(error) => return Some(error),
    };
    if !parts.expects_response {
        return None;
    }
    let id = parts.id.clone().unwrap_or(Value::Null);
    let method = parts.method;

    let response = match method {
        "initialize" => worker_result_response(id, handle_initialize(request)),
        "tools/list" => worker_string_result_response(id, crate::mcp::tools::list_request(request)),
        "tools/call" => worker_result_response(id, handle_tools_call(request)),
        "resources/list" => {
            worker_string_result_response(id, crate::mcp::resources::list_request(request))
        }
        "resources/templates/list" => worker_string_result_response(
            id,
            crate::mcp::resources::templates_list_request(request),
        ),
        "resources/read" => {
            let result =
                crate::mcp::resources::read_request(request).map_err(MemoricError::IpcError);
            worker_result_response(id, result)
        }
        "tasks/list" => worker_string_result_response(id, crate::mcp::tasks::list_request(request)),
        "tasks/get" => worker_string_result_response(id, crate::mcp::tasks::get_request(request)),
        "tasks/result" => {
            worker_string_result_response(id, crate::mcp::tasks::result_request(request))
        }
        "tasks/cancel" => {
            worker_string_result_response(id, crate::mcp::tasks::cancel_request(request))
        }
        "tasks/input_response" => {
            worker_string_result_response(id, crate::mcp::tasks::input_response_request(request))
        }
        "tasks/update" => {
            worker_string_result_response(id, crate::mcp::tasks::update_request(request))
        }
        "notifications/initialized" => return None,
        "ping" => worker_result_response(id, Ok(Value::Null)),
        method if crate::mcp::protocol::is_app_bridge_host_only_method(method) => {
            crate::mcp::protocol::app_bridge_unsupported_error_value(method, Some(id))
        }
        _ => serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": format!("Method not found: {}", method)},
            "id": id
        }),
    };

    Some(response)
}

#[cfg(test)]
fn worker_result_response(id: Value, result: Result<Value>) -> Value {
    match result {
        Ok(result) => serde_json::json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id
        }),
        Err(err) => serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": err.to_string()},
            "id": id
        }),
    }
}

#[cfg(test)]
fn worker_string_result_response(id: Value, result: std::result::Result<Value, String>) -> Value {
    match result {
        Ok(result) => serde_json::json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id
        }),
        Err(err) => serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": err},
            "id": id
        }),
    }
}

/// Handle tools/call request
fn handle_tools_call(request: &Value) -> Result<Value> {
    crate::mcp::request_context::with_request_context_from_request(
        request,
        crate::mcp::request_context::McpTransportKind::Worker,
        || {
            crate::observability::record_mcp_request(
                crate::mcp::request_context::McpTransportKind::Worker,
                request,
            );
            crate::observability::record_worker_ipc_event("inbound", "request", request);
            let params = request
                .get("params")
                .ok_or_else(|| MemoricError::IpcError("Missing params".to_string()))?;

            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MemoricError::IpcError("Missing tool name".to_string()))?;

            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));

            tracing::info!("Calling tool: {} with args: {}", name, args);
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
                return match crate::mcp::tasks::spawn_tool_task_with_options(name, &args, options) {
                    Ok(task_id) if task_augmented => {
                        Ok(crate::mcp::tasks::task_create_result(&task_id))
                    }
                    Ok(task_id) => Ok(crate::mcp::tasks::task_accepted_content(
                        name, &args, &task_id,
                    )),
                    Err(err) => Ok(tool_error_content(name, &args, &err)),
                };
            }

            // Use catch_unwind to prevent tool panics from killing the Worker process
            let args_for_call = args.clone();
            let tool_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                call_tool(name, args_for_call)
            }));

            let tool_result = match tool_result {
                Ok(Ok(value)) => value,
                Ok(Err(e)) => {
                    return Ok(tool_error_content(name, &args, &e));
                }
                Err(panic_info) => {
                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };
                    tracing::error!("Tool '{}' panicked: {}", name, panic_msg);
                    let message = format!("Tool '{}' panicked: {}", name, panic_msg);
                    return Ok(tool_error_content(name, &args, &message));
                }
            };

            Ok(tool_success_content(name, &args, &tool_result))
        },
    )
}

/// Handle initialize request
fn handle_initialize(_request: &Value) -> Result<Value> {
    tracing::info!("Worker received initialize request");

    Ok(initialize_result("memoric-worker"))
}

#[cfg(test)]
mod tests {
    use super::{handle_worker_request_for_test, run_worker_pipe_messages_for_test};
    use crate::ipc::{PipeClient, PipeServer};
    use serde_json::{json, Value};
    use std::sync::Arc;

    #[test]
    fn worker_conformance_fixtures_cover_core_methods() {
        crate::mcp::conformance::run_conformance("worker-in-process", |case| {
            handle_worker_request_for_test(&case.request)
        });
    }

    #[test]
    fn worker_adversarial_fixtures_are_stable() {
        crate::mcp::conformance::run_adversarial_conformance("worker-in-process", |case| {
            handle_worker_request_for_test(&case.request)
        });
    }

    #[test]
    fn worker_records_app_origin_in_timeline_events() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "ui-origin-worker",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": {
                    "action": "version",
                    "request_id": "ui-origin-worker"
                },
                "_meta": {
                    "io.memoric/app-origin": "ui://memoric/dashboard"
                }
            }
        });

        let _ = handle_worker_request_for_test(&request.to_string());
        let timeline = crate::observability::timeline_json(&json!({
            "correlation_id": "ui-origin-worker",
            "limit": 20,
            "redaction": "strict"
        }));

        let events = timeline["events"].as_array().expect("timeline events");
        assert!(events.iter().any(|event| {
            event["kind"] == "mcp.request"
                && event["correlation_id"] == "ui-origin-worker"
                && event["details"]["app_origin"] == "ui://memoric/dashboard"
                && event["details"]["policy_origin"] == "app"
        }));
    }

    #[test]
    fn worker_named_pipe_replays_mixed_jsonrpc_messages() {
        let pipe_name = format!(
            r"\\.\pipe\memoric-worker-test-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let mut server =
            PipeServer::new_test_with_name(&pipe_name).expect("create unique worker test pipe");

        let client = PipeClient::connect_with_name(&pipe_name).expect("connect worker test pipe");
        server.wait_for_client().expect("worker connects to pipe");

        let worker_thread = std::thread::spawn(move || {
            run_worker_pipe_messages_for_test(Arc::new(client), 6)
                .expect("worker pipe message replay should exit cleanly");
        });

        let input_messages = [
            json!({
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {}
            })
            .to_string(),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })
            .to_string(),
            "{not-json".to_string(),
            json!({
                "jsonrpc": "2.0",
                "id": "ping",
                "method": "ping"
            })
            .to_string(),
            json!({
                "jsonrpc": "2.0",
                "id": "tools",
                "method": "tools/list",
                "params": { "limit": 2 }
            })
            .to_string(),
            json!({
                "jsonrpc": "2.0",
                "id": "unknown",
                "method": "not/a_method"
            })
            .to_string(),
        ];

        let mut responses = Vec::new();
        for message in input_messages {
            server
                .write_message(message.as_bytes())
                .expect("write worker request message");
            if message.contains("notifications/initialized") {
                continue;
            }
            responses.push(read_json_pipe_message(&server));
        }

        assert_eq!(responses.len(), 5);
        assert_eq!(responses[0]["id"], "init");
        assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(
            responses[0]["result"]["serverInfo"]["name"],
            "memoric-worker"
        );

        assert_eq!(responses[1]["id"], Value::Null);
        assert_eq!(responses[1]["error"]["code"], -32700);

        assert_eq!(responses[2]["id"], "ping");
        assert_eq!(responses[2]["result"], Value::Null);

        assert_eq!(responses[3]["id"], "tools");
        let tools = responses[3]["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert_eq!(tools.len(), 2);

        assert_eq!(responses[4]["id"], "unknown");
        assert_eq!(responses[4]["error"]["code"], -32601);

        drop(server);
        worker_thread
            .join()
            .expect("worker named-pipe test thread should join");
    }

    fn read_json_pipe_message(server: &PipeServer) -> Value {
        let bytes = server.read_message().expect("read worker response message");
        let text = String::from_utf8(bytes).expect("worker response should be utf-8");
        serde_json::from_str(&text).expect("worker response should be JSON")
    }
}
