//! Legacy top-level tool aliases mapped to consolidated MCP tools.

use serde_json::{json, Value};

pub fn resolve(name: &str, args: Value) -> Result<(String, Value), String> {
    match name {
        "ps" | "modules" | "threads" | "suspend_thread" | "resume_thread" => {
            tracing::warn!("Tool '{}' is deprecated, use 'target' instead", name);
            Ok(("target".to_string(), convert_target(name, args)))
        }
        "read" | "write" | "scan" | "regions" | "alloc" | "free" | "protect" => {
            tracing::warn!("Tool '{}' is deprecated, use 'memory' instead", name);
            Ok(("memory".to_string(), convert_memory(name, args)))
        }
        "inject_dll" | "spawn" | "hijack" | "pe_parse" | "obfuscate" | "inject_ctl" | "unhook" => {
            tracing::warn!(
                "Tool '{}' is deprecated, forwarding to modern equivalent",
                name
            );
            Ok(convert_error_tool(name, args))
        }
        "patch" | "syscall" | "cloak" => {
            tracing::warn!("Tool '{}' is deprecated, use 'stealth'", name);
            Ok(("stealth".to_string(), convert_stealth(name, args)))
        }
        "edr" | "vm_detect" | "anti_forensics" => {
            tracing::warn!("Tool '{}' is deprecated, use 'detect'", name);
            Ok(("detect".to_string(), convert_detect(name, args)))
        }
        "elevate" | "token" | "debug_priv" | "check_admin" => {
            tracing::warn!("Tool '{}' is deprecated, use 'privilege'", name);
            Ok(("privilege".to_string(), convert_privilege(name, args)))
        }
        "driver" | "kernel_read" | "kernel_write" | "kernel_op" | "bruteforce" | "sniff" => {
            tracing::warn!("Tool '{}' is deprecated, use 'kernel'", name);
            Ok(("kernel".to_string(), convert_kernel(name, args)))
        }
        "self_protect" => {
            tracing::warn!("Tool '{}' is deprecated, use 'self'", name);
            Ok(("self".to_string(), convert_self_protect(args)))
        }
        "peb" | "heap" | "self_test" | "status" => {
            tracing::warn!("Tool '{}' is deprecated, use 'self'", name);
            Ok(("self".to_string(), convert_self(name, args)))
        }
        _ => Err(format!(
            "Unknown tool: {}. Call `memoric` to see available tools.",
            name
        )),
    }
}

fn convert_target(name: &str, args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match name {
            "ps" => match args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
            {
                "list" | "ps_list" => "ps_list",
                "find" | "search" | "ps_find" => "ps_find",
                "info" | "get" | "ps_info" => "ps_info",
                _ => "ps_list",
            },
            "modules" => "modules",
            "threads" => {
                if args.get("tid").is_some() {
                    "thread_context"
                } else {
                    "threads_list"
                }
            }
            "suspend_thread" => "thread_suspend",
            "resume_thread" => "thread_resume",
            _ => "ps_list",
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_memory(name: &str, args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match name {
            "regions" => "query",
            _ => name,
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_stealth(name: &str, args: Value) -> Value {
    let action = match name {
        "patch" => args
            .get("target")
            .and_then(|v| v.as_str())
            .map(|t| format!("patch_{}", t)),
        "syscall" => args
            .get("op")
            .and_then(|v| v.as_str())
            .map(|o| format!("syscall_{}", o)),
        "cloak" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| a.to_string()),
        _ => None,
    };
    let mut new_args = args.clone();
    if let Some(a) = action {
        new_args.as_object_mut().map(|m| {
            m.insert("action".to_string(), a.into());
        });
    }
    new_args
}

fn convert_detect(name: &str, args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match name {
            "edr" => match args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("products")
            {
                "products" | "list" => "edr_products",
                "hooks" => "edr_hooks",
                "quick" | "quick_check" => "edr_quick_check",
                "suspend" => "edr_suspend",
                _ => "edr_products",
            },
            "vm_detect" => "vm_sandbox",
            "anti_forensics" => "forensics",
            _ => "edr_products",
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_self_protect(args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("init")
        {
            "init" => "protect_init",
            "encrypt" => "protect_encrypt",
            "decrypt" => "protect_decrypt",
            "wipe" | "clear" => "protect_wipe",
            _ => "protect_init",
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_privilege(name: &str, args: Value) -> Value {
    let action = match name {
        "elevate" => "elevate",
        "token" => args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("token_steal"),
        "debug_priv" => "debug_priv",
        "check_admin" => "check",
        _ => "check",
    };
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        m.insert("action".to_string(), action.to_string().into());
    });
    new_args
}

fn convert_kernel(name: &str, args: Value) -> Value {
    let action = match name {
        "driver" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("driver_{}", a)),
        "kernel_read" => Some("read".to_string()),
        "kernel_write" => Some("write".to_string()),
        "kernel_op" => args
            .get("op")
            .and_then(|v| v.as_str())
            .map(|o| o.to_string()),
        "bruteforce" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| a.to_string()),
        "sniff" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("sniff_{}", a)),
        "anti_forensics" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| a.to_string()),
        "self_protect" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("protect_{}", a)),
        _ => None,
    };
    let mut new_args = args.clone();
    if let Some(a) = action {
        new_args.as_object_mut().map(|m| {
            m.insert("action".to_string(), a.into());
        });
    }
    new_args
}

fn convert_self(name: &str, args: Value) -> Value {
    let action = match name {
        "peb" => "peb",
        "heap" => "heap",
        "self_test" => "test",
        "status" => "info",
        _ => "test",
    };
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_error_tool(name: &str, args: Value) -> (String, Value) {
    match name {
        "inject_dll" => {
            let dll_method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("classic");
            let dll_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            (
                "inject".to_string(),
                json!({
                    "action": "dll",
                    "dll_path": dll_path,
                    "dll_method": dll_method,
                    "pid": args.get("pid").unwrap_or(&json!(0)),
                }),
            )
        }
        "spawn" => {
            let spawn_method = args
                .get("spawn_method")
                .and_then(|v| v.as_str())
                .unwrap_or("hollow");
            (
                "inject".to_string(),
                json!({
                    "action": "spawn",
                    "spawn_method": spawn_method,
                    "target_exe": args.get("target_exe").unwrap_or(&json!("")),
                    "payload": args.get("payload").unwrap_or(&json!("")),
                }),
            )
        }
        "hijack" => (
            "inject".to_string(),
            json!({
                "action": "hijack_enum",
                "pid": args.get("pid").unwrap_or(&json!(0)),
            }),
        ),
        "pe_parse" => (
            "payload".to_string(),
            json!({
                "action": "pe_parse",
                "pid": args.get("pid").unwrap_or(&json!(0)),
                "module": args.get("module").unwrap_or(&json!("")),
            }),
        ),
        "obfuscate" => (
            "payload".to_string(),
            json!({
                "action": "obfuscate",
                "obf_method": args.get("method").unwrap_or(&json!("xor")),
            }),
        ),
        "inject_ctl" => (
            "payload".to_string(),
            json!({
                "action": args.get("action").and_then(|v| v.as_str()).unwrap_or("cleanup"),
                "pid": args.get("pid").unwrap_or(&json!(0)),
            }),
        ),
        "unhook" => (
            "stealth".to_string(),
            json!({
                "action": "unhook_ntdll",
            }),
        ),
        _ => unreachable!(),
    }
}
