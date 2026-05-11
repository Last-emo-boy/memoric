//! Proxy mode - runs with normal user privileges (Medium IL)
//! Handles STDIO communication with Claude Desktop
//! Creates Named Pipe Server and waits for Worker to connect

use crate::elevation::spawn_elevated;
use crate::error::{MemoricError, Result};
use crate::ipc::PipeServer;
use serde_json::Value;
use std::io::{self, BufRead, Write};

pub fn run_proxy() -> Result<()> {
    tracing::info!("Starting memoric in proxy mode...");

    // Create Named Pipe Server FIRST (before spawning Worker)
    tracing::info!("Creating Named Pipe Server...");

    let mut server = PipeServer::new()?;

    // Spawn elevated Worker
    tracing::info!("Spawning elevated Worker...");

    spawn_elevated()?;

    // Wait for Worker to connect
    tracing::info!("Waiting for Worker to connect...");

    // This blocks until Worker connects
    server.wait_for_client()?;

    tracing::info!("=== Proxy ready, starting STDIO bridge ===");

    // STDIO server loop
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to read STDIN: {}", e);
                continue;
            }
        };

        if line.is_empty() {
            continue;
        }

        tracing::debug!("Received from Claude: {}", line);

        // Parse JSON-RPC request
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to parse JSON: {}", e);
                continue;
            }
        };

        // Handle initialize locally (don't forward to Worker)
        if let Some(method) = request.get("method").and_then(|v| v.as_str()) {
            if method == "initialize" {
                tracing::info!("Handling initialize locally");
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request.get("id").unwrap_or(&Value::Null),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "memoric",
                            "version": "0.1.0"
                        }
                    }
                });
                let response_str = serde_json::to_string(&response).unwrap();
                writeln!(stdout, "{}", response_str)?;
                stdout.flush()?;
                continue;
            }

            // Don't wait for response for notifications
            if method.starts_with("notifications/") {
                tracing::info!("Sending notification (no response expected): {}", method);
                forward_to_worker_no_response(&server, &request)?;
                continue;
            }
        }

        // All tool calls go to Worker
        tracing::info!("Forwarding tool call to Worker...");
        match forward_to_worker(&server, &request) {
            Ok(response) => {
                tracing::info!("Got response from Worker, sending to Claude...");
                match serde_json::to_string(&response) {
                    Ok(response_str) => {
                        tracing::info!("Response length: {} bytes", response_str.len());

                        // Write to stdout with explicit error handling
                        use std::io::Write;
                        let write_result = writeln!(stdout, "{}", response_str);
                        tracing::info!("writeln! result: {:?}", write_result.is_ok());

                        match write_result {
                            Ok(_) => {
                                tracing::info!("Response written to stdout, flushing...");
                                // Force flush multiple times to ensure data is sent
                                for i in 1..=3 {
                                    match stdout.flush() {
                                        Ok(_) => {
                                            tracing::info!("Flush #{} successful", i);
                                        }
                                        Err(e) => {
                                            tracing::error!("Flush #{} failed: {}", i, e);
                                        }
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(10));
                                }
                                tracing::info!("✓ Response successfully sent to Claude");
                            }
                            Err(e) => {
                                tracing::error!("Failed to write response to stdout: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to serialize response: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Worker communication error: {}", e);
                let error_response = format!(
                    r#"{{"jsonrpc":"2.0","error":{{"code":-32000,"message":"{}"}},"id":{}}}"#,
                    e.to_string(),
                    request.get("id").unwrap_or(&Value::Null)
                );
                if let Err(e) = writeln!(stdout, "{}", error_response) {
                    tracing::error!("Failed to write error to stdout: {}", e);
                }
                let _ = stdout.flush();
            }
        }
    }

    tracing::info!("Proxy shutting down...");
    Ok(())
}

/// Forward request to Worker and return response
fn forward_to_worker(pipe: &PipeServer, request: &Value) -> Result<Value> {
    // Send request
    let request_str = serde_json::to_string(request)
        .map_err(|e| MemoricError::IpcError(format!("Serialize error: {}", e)))?;

    tracing::info!("Sending to Worker: {}", request_str);

    pipe.write_message(request_str.as_bytes())?;
    tracing::info!("Sent request to Worker");

    // Read response
    tracing::info!("Waiting for response from Worker...");

    let response_bytes = pipe.read_message()?;
    let response_str = String::from_utf8_lossy(&response_bytes);
    tracing::info!("Received from Worker: {}", response_str);

    let response: Value = serde_json::from_str(&response_str)
        .map_err(|e| MemoricError::IpcError(format!("Deserialize error: {}", e)))?;

    Ok(response)
}

/// Forward notification to Worker without waiting for response
fn forward_to_worker_no_response(pipe: &PipeServer, request: &Value) -> Result<()> {
    let request_str = serde_json::to_string(request)
        .map_err(|e| MemoricError::IpcError(format!("Serialize error: {}", e)))?;

    tracing::info!("Sending notification to Worker: {}", request_str);

    pipe.write_message(request_str.as_bytes())?;
    tracing::info!("Notification sent (no response expected)");

    Ok(())
}
