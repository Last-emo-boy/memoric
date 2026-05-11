//! Worker mode - runs with elevated privileges (High IL)
//! Connects to Proxy's Named Pipe Server
//! Executes privileged memory operations

use crate::error::{MemoricError, Result};
use crate::ipc::PipeClient;
use crate::mcp::tools::{call_tool, tool_error_text};
use serde_json::Value;

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

            client
        }
        Err(e) => {
            tracing::error!("Failed to connect to Proxy: {}", e);

            return Err(e);
        }
    };

    tracing::info!("=== Worker ready, processing requests ===");

    // Main request loop
    tracing::info!("Waiting for requests from Proxy...");

    loop {
        match pipe.read_message() {
            Ok(data) => {
                if data.is_empty() {
                    tracing::warn!("Received empty message, breaking loop");

                    break;
                }

                let request_str = String::from_utf8_lossy(&data);
                tracing::info!("Received from Proxy: {}", request_str);

                let request: Value = match serde_json::from_str(&request_str) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Failed to parse JSON: {}", e);

                        continue;
                    }
                };

                // Handle request (sends response internally)
                handle_request(&pipe, &request);
            }
            Err(e) => {
                tracing::error!("Read error: {}", e);
                break;
            }
        }
    }

    tracing::info!("Worker shutting down...");

    Ok(())
}

/// Handle a JSON-RPC request
fn handle_request(pipe: &PipeClient, request: &Value) {
    use serde_json::json;

    // Validate JSON-RPC 2.0
    let jsonrpc = request.get("jsonrpc").and_then(|v| v.as_str());
    if jsonrpc != Some("2.0") {
        let response = json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid JSON-RPC version"},
            "id": request.get("id").unwrap_or(&Value::Null)
        });
        let _ = pipe.write_message(response.to_string().as_bytes());
        return;
    }

    // Get method
    let method = match request.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            let response = json!({
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Missing method"},
                "id": request.get("id").unwrap_or(&Value::Null)
            });
            let _ = pipe.write_message(response.to_string().as_bytes());
            return;
        }
    };

    // Get id
    let id = request.get("id").cloned().unwrap_or(Value::Null);

    // Handle method
    match method {
        "initialize" => {
            let result = handle_initialize(request);
            send_response(&pipe, &id, result);
        }
        "tools/list" => {
            let result = handle_tools_list();
            send_response(&pipe, &id, result);
        }
        "tools/call" => {
            let result = handle_tools_call(request);
            send_response(&pipe, &id, result);
        }
        "notifications/initialized" => {
            // This is a notification, no response needed
            tracing::info!("Received notifications/initialized");
        }
        "ping" => {
            let result = Ok(Value::Null);
            send_response(&pipe, &id, result);
        }
        _ => {
            // JSON-RPC -32601: Method not found
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Method not found: {}", method)},
                "id": id
            });
            let _ = pipe.write_message(response.to_string().as_bytes());
        }
    };
}

/// Send a response to Proxy
fn send_response(pipe: &PipeClient, id: &Value, result: Result<Value>) {
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

    let response_str = match serde_json::to_string(&response) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to serialize response: {}", e);
            return;
        }
    };

    tracing::info!("Sending to Proxy: {}", response_str);

    if let Err(e) = pipe.write_message(response_str.as_bytes()) {
        tracing::error!("Failed to send response: {}", e);
    }
}

/// Handle tools/call request
fn handle_tools_call(request: &Value) -> Result<Value> {
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

    // Use catch_unwind to prevent tool panics from killing the Worker process
    let args_for_call = args.clone();
    let tool_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call_tool(name, args_for_call)
    }));

    let tool_result = match tool_result {
        Ok(Ok(value)) => value,
        Ok(Err(e)) => {
            let result_text = tool_error_text(name, &args, &e);
            return Ok(serde_json::json!({
                "content": [
                    {
                        "type": "text",
                        "text": result_text
                    }
                ],
                "isError": true
            }));
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
            let result_text = tool_error_text(
                name,
                &args,
                &format!("Tool '{}' panicked: {}", name, panic_msg),
            );
            return Ok(serde_json::json!({
                "content": [
                    {
                        "type": "text",
                        "text": result_text
                    }
                ],
                "isError": true
            }));
        }
    };

    // Convert tool result to string for MCP content format
    let result_text = serde_json::to_string(&tool_result)
        .unwrap_or_else(|_| "Failed to serialize result".to_string());

    // Wrap result in MCP content format
    Ok(serde_json::json!({
        "content": [
            {
                "type": "text",
                "text": result_text
            }
        ]
    }))
}

/// Handle initialize request
fn handle_initialize(_request: &Value) -> Result<Value> {
    tracing::info!("Worker received initialize request");

    Ok(serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "memoric-worker",
            "version": "0.1.0"
        }
    }))
}

/// Handle tools/list request
fn handle_tools_list() -> Result<Value> {
    use crate::mcp::tools::register_tools;

    tracing::info!("Worker received tools/list request");
    let tools = register_tools();

    Ok(serde_json::json!({
        "tools": tools
    }))
}
