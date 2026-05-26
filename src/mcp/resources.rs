//! Shared MCP resource providers.

use once_cell::sync::Lazy;
use serde_json::{json, Value};

const DEFAULT_RESOURCE_LIST_LIMIT: usize = 100;
const MAX_RESOURCE_LIST_LIMIT: usize = 500;
const RESOURCE_CURSOR_PREFIX: &str = "resource-cursor:";
const DEFAULT_TEMPLATE_LIST_LIMIT: usize = 100;
const MAX_TEMPLATE_LIST_LIMIT: usize = 500;
const TEMPLATE_CURSOR_PREFIX: &str = "resource-template-cursor:";
const UI_RESOURCE_MIME_TYPE: &str = "text/html;profile=mcp-app";

static RESOURCE_DEFINITIONS: Lazy<Vec<Value>> = Lazy::new(build_resource_definitions);
static RESOURCE_TEMPLATE_DEFINITIONS: Lazy<Vec<Value>> =
    Lazy::new(build_resource_template_definitions);

pub fn list() -> Value {
    json!({ "resources": resource_definitions() })
}

pub fn templates_list() -> Value {
    json!({ "resourceTemplates": resource_template_definitions() })
}

pub fn list_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params");
    let uses_pagination = params
        .map(|params| params.get("limit").is_some() || params.get("cursor").is_some())
        .unwrap_or(false);

    if !uses_pagination {
        return Ok(list());
    }

    let limit = parse_resource_list_limit(params)?;
    let cursor = match params.and_then(|params| params.get("cursor")) {
        Some(Value::String(cursor)) => Some(cursor.as_str()),
        Some(_) => return Err("Invalid cursor: expected opaque string token".to_string()),
        None => None,
    };

    list_page(limit, cursor)
}

pub fn templates_list_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params");
    let uses_pagination = params
        .map(|params| params.get("limit").is_some() || params.get("cursor").is_some())
        .unwrap_or(false);

    if !uses_pagination {
        return Ok(templates_list());
    }

    let limit = parse_template_list_limit(params)?;
    let cursor = match params.and_then(|params| params.get("cursor")) {
        Some(Value::String(cursor)) => Some(cursor.as_str()),
        Some(_) => return Err("Invalid cursor: expected opaque string token".to_string()),
        None => None,
    };

    templates_list_page(limit, cursor)
}

pub fn list_page(limit: usize, cursor: Option<&str>) -> Result<Value, String> {
    let limit = limit.clamp(1, MAX_RESOURCE_LIST_LIMIT);
    let start = decode_resource_cursor(cursor)?;
    let resources = resource_definitions();

    if start > resources.len() {
        return Err("Invalid cursor: pagination position is outside resource list".to_string());
    }

    let total = resources.len();
    let page = resources
        .iter()
        .skip(start)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut response = json!({ "resources": page });
    let next_offset = start.saturating_add(limit);
    if next_offset < total {
        response["nextCursor"] = json!(encode_resource_cursor(next_offset));
    }
    Ok(response)
}

pub fn templates_list_page(limit: usize, cursor: Option<&str>) -> Result<Value, String> {
    let limit = limit.clamp(1, MAX_TEMPLATE_LIST_LIMIT);
    let start = decode_template_cursor(cursor)?;
    let templates = resource_template_definitions();

    if start > templates.len() {
        return Err(
            "Invalid cursor: pagination position is outside resource template list".to_string(),
        );
    }

    let total = templates.len();
    let page = templates
        .iter()
        .skip(start)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut response = json!({ "resourceTemplates": page });
    let next_offset = start.saturating_add(limit);
    if next_offset < total {
        response["nextCursor"] = json!(encode_template_cursor(next_offset));
    }
    Ok(response)
}

fn resource_definitions() -> &'static [Value] {
    &RESOURCE_DEFINITIONS
}

fn resource_template_definitions() -> &'static [Value] {
    &RESOURCE_TEMPLATE_DEFINITIONS
}

fn build_resource_definitions() -> Vec<Value> {
    vec![
        json!({
            "uri": "memoric://status",
            "name": "Server Status",
            "description": "Current memoric server status, privilege level, and capabilities",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://capabilities",
            "name": "Capabilities",
            "description": "Runtime readiness, policy, and action registry summary",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://policy",
            "name": "Policy",
            "description": "Current policy level and audit configuration",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://tasks",
            "name": "Tasks",
            "description": "Process-local MCP task registry",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://audit/recent",
            "name": "Recent Audit",
            "description": "Recent JSONL audit entries when MEMORIC_AUDIT_PATH is configured",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://artifacts",
            "name": "Artifact Registry",
            "description": "Process-local artifact resource links with retention and integrity metadata",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://timeline",
            "name": "Observability Timeline",
            "description": "Read-only timeline linking MCP requests, tasks, audit entries, worker IPC, and artifacts by correlation ID",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "ui://memoric/dashboard",
            "name": "Memoric Dashboard UI Data",
            "description": "Read-only MCP Apps dashboard hydration data for tasks, policy, audit, capabilities, artifacts, and timeline",
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "_meta": crate::mcp::meta::app_resource_meta("dashboard", false)
        }),
        json!({
            "uri": "ui://memoric/scans",
            "name": "Memoric Scan Explorer UI Data",
            "description": "Read-only MCP Apps scan explorer hydration data with bounded scan session and candidate pages",
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "_meta": crate::mcp::meta::app_resource_meta("scans", false)
        }),
        json!({
            "uri": "ui://memoric/plans",
            "name": "Memoric Plan Review UI Data",
            "description": "Read-only MCP Apps plan review hydration data for dry-run plans, templates, blocked steps, and capability blockers",
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "_meta": crate::mcp::meta::app_resource_meta("plans", false)
        }),
        json!({
            "uri": "memoric://processes",
            "name": "Process List",
            "description": "Running processes on the target system",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://scan-sessions",
            "name": "Scan Sessions",
            "description": "Active memory scan sessions",
            "mimeType": "application/json"
        }),
        json!({
            "uri": "memoric://drivers",
            "name": "Loaded Drivers",
            "description": "Available BYOVD drivers and their status",
            "mimeType": "application/json"
        }),
    ]
}

fn build_resource_template_definitions() -> Vec<Value> {
    vec![
        json!({
            "uriTemplate": "ui://memoric/dashboard{?limit,correlation_id}",
            "name": "Memoric Dashboard",
            "description": "Read-only operation dashboard for task status, policy, audit, capability readiness, artifacts, and timeline context",
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "_meta": crate::mcp::meta::app_resource_meta("dashboard", false)
        }),
        json!({
            "uriTemplate": "ui://memoric/scans{?session_id,limit,offset,cursor,sort,summary_only}",
            "name": "Memoric Scan Explorer",
            "description": "Read-only scan session explorer with bounded pagination and strict default redaction",
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "_meta": crate::mcp::meta::app_resource_meta("scans", false)
        }),
        json!({
            "uriTemplate": "ui://memoric/plans{?template,limit,offset,cursor,dry_run}",
            "name": "Memoric Plan Review",
            "description": "Read-only orchestration plan review for effective plans, blocked steps, policy decisions, templates, and capability blockers",
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "_meta": crate::mcp::meta::app_resource_meta("plans", false)
        }),
        json!({
            "uriTemplate": "memoric://artifact/sha256/{sha256}",
            "name": "Artifact By SHA-256",
            "description": "Retention-bound artifact resource content with SHA-256 verification",
            "mimeType": "application/octet-stream",
            "_meta": {
                "x-memoric-resource-kind": "artifact",
                "x-memoric-visibility": "user",
                "x-memoric-read-only": true
            }
        }),
    ]
}

fn parse_resource_list_limit(params: Option<&Value>) -> Result<usize, String> {
    match params.and_then(|params| params.get("limit")) {
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| "Invalid limit: expected positive integer".to_string())?;
            let limit = usize::try_from(raw).map_err(|_| "Invalid limit: too large".to_string())?;
            Ok(limit.clamp(1, MAX_RESOURCE_LIST_LIMIT))
        }
        None => Ok(DEFAULT_RESOURCE_LIST_LIMIT),
    }
}

fn parse_template_list_limit(params: Option<&Value>) -> Result<usize, String> {
    match params.and_then(|params| params.get("limit")) {
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| "Invalid limit: expected positive integer".to_string())?;
            let limit = usize::try_from(raw).map_err(|_| "Invalid limit: too large".to_string())?;
            Ok(limit.clamp(1, MAX_TEMPLATE_LIST_LIMIT))
        }
        None => Ok(DEFAULT_TEMPLATE_LIST_LIMIT),
    }
}

fn encode_resource_cursor(offset: usize) -> String {
    format!("{}{}", RESOURCE_CURSOR_PREFIX, offset)
}

fn encode_template_cursor(offset: usize) -> String {
    format!("{}{}", TEMPLATE_CURSOR_PREFIX, offset)
}

fn decode_resource_cursor(cursor: Option<&str>) -> Result<usize, String> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let raw = cursor
        .strip_prefix(RESOURCE_CURSOR_PREFIX)
        .ok_or_else(|| "Invalid cursor: unrecognized opaque token".to_string())?;
    if raw.is_empty() {
        return Err("Invalid cursor: empty pagination position".to_string());
    }
    raw.parse::<usize>()
        .map_err(|_| "Invalid cursor: malformed pagination position".to_string())
}

fn decode_template_cursor(cursor: Option<&str>) -> Result<usize, String> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let raw = cursor
        .strip_prefix(TEMPLATE_CURSOR_PREFIX)
        .ok_or_else(|| "Invalid cursor: unrecognized opaque token".to_string())?;
    if raw.is_empty() {
        return Err("Invalid cursor: empty pagination position".to_string());
    }
    raw.parse::<usize>()
        .map_err(|_| "Invalid cursor: malformed pagination position".to_string())
}

pub fn read(uri: &str) -> Result<Value, String> {
    let content = match uri {
        "memoric://status" => status_json(),
        "memoric://capabilities" => capabilities_json(),
        "memoric://policy" => serde_json::json!({"configured_policy": "destructive", "levels": ["observe","research","lab-write","privileged","kernel","destructive"], "default_behavior": "all operations are allowed"}),
        "memoric://tasks" => crate::mcp::tasks::resource_json(),
        "memoric://audit/recent" => recent_audit_json(),
        "memoric://artifacts" => crate::artifact::registry_json(),
        "memoric://timeline" => crate::observability::timeline_json(&json!({})),
        "memoric://processes" => crate::info::process::list_processes(&json!({"limit": 200}))
            .unwrap_or_else(|e| json!({"success": false, "error": e.to_string()})),
        "memoric://scan-sessions" => crate::memory::session::scan_list(&json!({}))
            .unwrap_or_else(|e| json!({"success": false, "error": e.to_string()})),
        "memoric://drivers" => crate::kernel::discover_vulnerable_drivers(&json!({}))
            .unwrap_or_else(|e| json!({"success": false, "error": e.to_string()})),
        _ if uri.starts_with("ui://memoric/dashboard") => {
            return html_content_response(
                uri,
                "Memoric Dashboard",
                "Read-only operational dashboard",
                dashboard_ui_json(uri),
            );
        }
        _ if uri.starts_with("ui://memoric/scans") => {
            return html_content_response(
                uri,
                "Memoric Scan Explorer",
                "Read-only scan session explorer",
                scans_ui_json(uri),
            );
        }
        _ if uri.starts_with("ui://memoric/plans") => {
            return html_content_response(
                uri,
                "Memoric Plan Review",
                "Read-only orchestration plan review",
                plans_ui_json(uri),
            );
        }
        _ if crate::artifact::is_artifact_uri(uri) => {
            return Ok(json!({
                "contents": [
                    crate::artifact::read_resource_content(uri)?
                ]
            }))
        }
        _ => return Err(format!("Unknown resource URI: {}", uri)),
    };

    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&content).unwrap_or_default()
        }]
    }))
}

fn json_content_response(uri: &str, mime_type: &str, content: Value) -> Result<Value, String> {
    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": mime_type,
            "text": serde_json::to_string_pretty(&content).unwrap_or_default()
        }]
    }))
}

fn html_content_response(
    uri: &str,
    title: &str,
    subtitle: &str,
    payload: Value,
) -> Result<Value, String> {
    let payload_json = escape_json_for_script(
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()),
    );
    let html = render_ui_html(title, subtitle, &payload_json);
    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": UI_RESOURCE_MIME_TYPE,
            "text": html
        }]
    }))
}

fn render_ui_html(title: &str, subtitle: &str, payload_json: &str) -> String {
    let title = escape_html(title);
    let subtitle = escape_html(subtitle);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0d1117;
      color: #e6edf3;
    }}
    main {{
      box-sizing: border-box;
      padding: 20px;
      max-width: 1200px;
      margin: 0 auto;
    }}
    header {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 20px;
      border-bottom: 1px solid #30363d;
      padding-bottom: 12px;
    }}
    h1 {{ margin: 0; font-size: 20px; }}
    .subtitle {{ color: #8b949e; margin: 4px 0 0; }}
    .badge {{
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      background: #161b22;
      border: 1px solid #30363d;
      color: #8b949e;
      font-size: 12px;
    }}
    section {{
      margin-top: 16px;
      border: 1px solid #30363d;
      background: #161b22;
      border-radius: 8px;
      padding: 14px;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0;
      font-size: 12px;
      line-height: 1.5;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>{title}</h1>
        <p class="subtitle">{subtitle}</p>
      </div>
      <span class="badge">ui://memoric</span>
    </header>
    <section>
      <pre id="memoric-rendered">Loading...</pre>
    </section>
    <script id="memoric-data" type="application/json">{payload_json}</script>
    <script>
      const source = document.getElementById('memoric-data');
      const rendered = document.getElementById('memoric-rendered');
      try {{
        const value = JSON.parse(source.textContent || '{{}}');
        rendered.textContent = JSON.stringify(value, null, 2);
      }} catch (error) {{
        rendered.textContent = 'Failed to render UI payload: ' + error;
      }}
    </script>
  </main>
</body>
</html>"#,
        title = title,
        subtitle = subtitle,
        payload_json = payload_json,
    )
}

fn escape_json_for_script(value: String) -> String {
    if !value.contains("</") {
        return value;
    }

    let mut escaped = String::with_capacity(value.len());
    let mut start = 0;
    while let Some(offset) = value[start..].find("</") {
        let found = start + offset;
        escaped.push_str(&value[start..found]);
        escaped.push_str("<\\/");
        start = found + 2;
    }
    escaped.push_str(&value[start..]);
    escaped
}

fn escape_html(value: &str) -> String {
    if !value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'&' | b'<' | b'>' | b'"' | b'\''))
    {
        return value.to_string();
    }

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub fn read_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params").ok_or("Missing params")?;
    let uri = params
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or("Missing resource URI")?;
    read(uri)
}

fn status_json() -> Value {
    crate::capability::status_json(&json!({}))
}

fn capabilities_json() -> Value {
    crate::capability::capabilities_json(&json!({}))
}

fn recent_audit_json() -> Value {
    let Some(path) = crate::audit::audit_path() else {
        return json!({
            "success": true,
            "configured": false,
            "entries": []
        });
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            return json!({
                "success": false,
                "configured": true,
                "path": path,
                "error": err.to_string()
            })
        }
    };

    let entries = content
        .lines()
        .rev()
        .take(50)
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();

    json!({
        "success": true,
        "configured": true,
        "path": path,
        "count": entries.len(),
        "entries": entries,
    })
}

fn dashboard_ui_json(uri: &str) -> Value {
    let query = parse_uri_query(uri);
    let limit = query_usize(&query, "limit", 10, 50);
    let correlation_id = query.get("correlation_id").cloned();
    let timeline_args = match correlation_id.as_deref() {
        Some(value) if !value.is_empty() => json!({"correlation_id": value, "limit": limit}),
        _ => json!({"limit": limit}),
    };

    json!({
        "success": true,
        "schema_version": 1,
        "resource": "ui://memoric/dashboard",
        "mode": "read_only",
        "fallback": {
            "text_clients": [
                "memoric://tasks",
                "memoric://policy",
                "memoric://capabilities",
                "memoric://audit/recent",
                "memoric://timeline"
            ]
        },
        "_meta": crate::mcp::meta::app_resource_meta("dashboard", false),
        "data": {
            "state": crate::state::get_state_json().unwrap_or_else(|err| json!({"success": false, "error": err})),
            "policy": serde_json::json!({"configured_policy": "destructive", "levels": ["observe","research","lab-write","privileged","kernel","destructive"], "default_behavior": "all operations are allowed"}),
            "capabilities": crate::capability::status_json(&json!({})),
            "tasks": crate::mcp::tasks::resource_json(),
            "audit": recent_audit_json(),
            "artifacts": crate::artifact::registry_json(),
            "timeline": crate::observability::timeline_json(&timeline_args),
            "operation_history": crate::state::operation_history_json(&json!({"limit": limit}))
        }
    })
}

fn scans_ui_json(uri: &str) -> Value {
    let query = parse_uri_query(uri);
    let mut args = serde_json::Map::new();
    args.insert(
        "limit".to_string(),
        json!(query_usize(&query, "limit", 50, 500)),
    );
    if let Some(offset) = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
    {
        args.insert("offset".to_string(), json!(offset));
    }
    if let Some(value) = query.get("session_id").filter(|value| !value.is_empty()) {
        args.insert("session_id".to_string(), json!(value));
    }
    if let Some(value) = query.get("cursor").filter(|value| !value.is_empty()) {
        args.insert("cursor".to_string(), json!(value));
    }
    if let Some(value) = query.get("sort").filter(|value| !value.is_empty()) {
        args.insert("sort".to_string(), json!(value));
    }
    if let Some(summary_only) = query_bool(&query, "summary_only") {
        args.insert("summary_only".to_string(), json!(summary_only));
    }

    json!({
        "success": true,
        "schema_version": 1,
        "resource": "ui://memoric/scans",
        "mode": "read_only",
        "redaction": "strict",
        "fallback": {
            "text_clients": [
                "memoric://scan-sessions"
            ]
        },
        "_meta": crate::mcp::meta::app_resource_meta("scans", false),
        "data": {
            "scan_list": crate::memory::session::scan_list(&Value::Object(args))
                .unwrap_or_else(|err| json!({"success": false, "error": err})),
            "artifacts": crate::artifact::registry_json()
        }
    })
}

fn plans_ui_json(uri: &str) -> Value {
    let query = parse_uri_query(uri);
    let mut plan_args = serde_json::Map::new();
    plan_args.insert("dry_run".to_string(), json!(true));
    plan_args.insert(
        "limit".to_string(),
        json!(query_usize(&query, "limit", 50, 500)),
    );
    if let Some(offset) = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
    {
        plan_args.insert("offset".to_string(), json!(offset));
    }
    if let Some(value) = query.get("cursor").filter(|value| !value.is_empty()) {
        plan_args.insert("cursor".to_string(), json!(value));
    }
    if let Some(value) = query.get("template").filter(|value| !value.is_empty()) {
        plan_args.insert("template".to_string(), json!(value));
    }

    let plan_preview = if plan_args.contains_key("template") {
        crate::orchestration::engine::plan_chain(&Value::Object(plan_args))
            .unwrap_or_else(|err| json!({"success": false, "error": err.to_string()}))
    } else {
        json!({
            "success": true,
            "mode": "template_index_only",
            "message": "Provide a template query parameter to preview a concrete plan",
            "template": null,
            "plan": [],
            "effective_plan": [],
            "blocked_steps": [],
            "validation_errors": [],
            "validation_warnings": []
        })
    };

    json!({
        "success": true,
        "schema_version": 1,
        "resource": "ui://memoric/plans",
        "mode": "read_only",
        "fallback": {
            "text_clients": [
                "orchestrate(action='templates')",
                "orchestrate(action='plan', dry_run=true)"
            ]
        },
        "_meta": crate::mcp::meta::app_resource_meta("plans", false),
        "data": {
            "templates": crate::orchestration::templates::templates_json(),
            "plan": plan_preview,
            "replay": crate::state::workflow_replay_dry_run_json(&json!({"limit": 25})),
            "capabilities": crate::capability::status_json(&json!({})),
            "policy": serde_json::json!({"configured_policy": "destructive", "levels": ["observe","research","lab-write","privileged","kernel","destructive"], "default_behavior": "all operations are allowed"})
        }
    })
}

fn parse_uri_query(uri: &str) -> std::collections::BTreeMap<String, String> {
    let mut query = std::collections::BTreeMap::new();
    let Some((_, raw_query)) = uri.split_once('?') else {
        return query;
    };

    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(key), percent_decode(value));
    }

    query
}

fn query_usize(
    query: &std::collections::BTreeMap<String, String>,
    key: &str,
    default: usize,
    max: usize,
) -> usize {
    query
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(max)
}

fn query_bool(query: &std::collections::BTreeMap<String, String>, key: &str) -> Option<bool> {
    match query.get(key).map(|value| value.as_str()) {
        Some("true" | "1" | "yes") => Some(true),
        Some("false" | "0" | "no") => Some(false),
        Some(_) | None => None,
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = hex_value(bytes[index + 1]);
                let lo = hex_value(bytes[index + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    decoded.push((hi << 4) | lo);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_list_contains_new_observability_resources() {
        let resources = list();
        let uris = resources["resources"].as_array().unwrap();
        assert!(uris.iter().any(|r| r["uri"] == "memoric://capabilities"));
        assert!(uris.iter().any(|r| r["uri"] == "memoric://policy"));
        assert!(uris.iter().any(|r| r["uri"] == "memoric://tasks"));
        assert!(uris.iter().any(|r| r["uri"] == "memoric://audit/recent"));
        assert!(uris.iter().any(|r| r["uri"] == "memoric://artifacts"));
        assert!(uris.iter().any(|r| r["uri"] == "memoric://timeline"));
        assert!(uris.iter().any(|r| r["uri"] == "ui://memoric/dashboard"));
        assert!(uris.iter().any(|r| r["uri"] == "ui://memoric/scans"));
        assert!(uris.iter().any(|r| r["uri"] == "ui://memoric/plans"));
    }

    #[test]
    fn resource_templates_list_contains_ui_resources() {
        let templates = templates_list();
        let values = templates["resourceTemplates"].as_array().unwrap();
        assert!(values
            .iter()
            .any(|r| r["uriTemplate"] == "ui://memoric/dashboard{?limit,correlation_id}"));
        assert!(values.iter().any(|r| r["uriTemplate"]
            == "ui://memoric/scans{?session_id,limit,offset,cursor,sort,summary_only}"));
        assert!(values.iter().any(
            |r| r["uriTemplate"] == "ui://memoric/plans{?template,limit,offset,cursor,dry_run}"
        ));
        for template in values {
            if template["uriTemplate"]
                .as_str()
                .unwrap_or_default()
                .starts_with("ui://memoric/")
            {
                assert_eq!(
                    template["_meta"]["ui"]["resourceUri"],
                    template["uriTemplate"]
                        .as_str()
                        .unwrap_or_default()
                        .split('{')
                        .next()
                        .unwrap_or_default()
                );
                assert_eq!(template["_meta"]["ui"]["visibility"], "user");
                assert_eq!(template["_meta"]["ui"]["widgetOnlyHydration"], true);
                assert_eq!(template["_meta"]["openai/widgetDomain"], "ui://memoric");
                assert!(template["_meta"]["openai/widgetCSP"]["connect_domains"]
                    .as_array()
                    .unwrap()
                    .is_empty());
                assert_eq!(template["_meta"]["x-memoric-ui"]["readOnly"], true);
                assert_eq!(template["_meta"]["io.memoric/ui"]["readOnly"], true);
                assert_eq!(template["_meta"]["x-memoric-ui"]["toolCalls"], "none");
                assert!(template["_meta"]["ui"]["csp"]["connect_domains"]
                    .as_array()
                    .unwrap()
                    .is_empty());
            }
        }
    }

    #[test]
    fn resource_templates_support_cursor_pagination() {
        let first = templates_list_page(2, None).expect("first template page");
        let templates = first["resourceTemplates"].as_array().unwrap();
        assert_eq!(templates.len(), 2);
        let cursor = first["nextCursor"].as_str().expect("next cursor");

        let second = templates_list_page(2, Some(cursor)).expect("second template page");
        let second_templates = second["resourceTemplates"].as_array().unwrap();
        assert!(!second_templates.is_empty());
        assert_ne!(
            second_templates[0]["uriTemplate"],
            templates[0]["uriTemplate"]
        );
    }

    #[test]
    fn resource_templates_reject_invalid_cursor() {
        let err = templates_list_page(2, Some("not-a-template-cursor")).unwrap_err();
        assert!(err.contains("Invalid cursor"));
    }

    #[test]
    fn ui_resource_reads_dashboard_scans_and_plans() {
        for uri in [
            "ui://memoric/dashboard?limit=2",
            "ui://memoric/scans?limit=2&sort=address_desc&summary_only=true",
            "ui://memoric/plans?limit=2&template=memory_diagnostics",
        ] {
            let value = read(uri).expect("ui resource");
            assert_eq!(value["contents"][0]["uri"], uri);
            assert_eq!(value["contents"][0]["mimeType"], UI_RESOURCE_MIME_TYPE);
            let text = value["contents"][0]["text"].as_str().expect("ui text");
            assert!(text.contains("<!DOCTYPE html>"));
            assert!(text.contains("application/json"));
            assert!(text.contains("memoric-rendered"));
            assert!(text.contains("application/json\""));
            assert!(text.contains("ui://memoric"));
        }
    }

    #[test]
    fn ui_script_payload_escapes_closing_tags_only_when_needed() {
        let safe = r#"{"x":"safe"}"#.to_string();
        assert_eq!(escape_json_for_script(safe.clone()), safe);

        let escaped = escape_json_for_script(r#"{"x":"</script><div></div>"}"#.to_string());
        assert!(escaped.contains(r#"<\/script>"#));
        assert!(escaped.contains(r#"<\/div>"#));
        assert!(!escaped.contains("</script>"));
    }

    #[test]
    fn escape_html_encodes_reserved_characters_in_one_pass() {
        assert_eq!(escape_html("plain text"), "plain text");
        assert_eq!(
            escape_html(r#"A&B <tag> "quote" 'apos'"#),
            "A&amp;B &lt;tag&gt; &quot;quote&quot; &#39;apos&#39;"
        );
    }

    #[test]
    fn policy_resource_reads() {
        let value = read("memoric://policy").expect("policy resource");
        assert_eq!(value["contents"][0]["uri"], "memoric://policy");
    }

    #[test]
    fn timeline_resource_reads_safe_json() {
        let value = read("memoric://timeline").expect("timeline resource");
        assert_eq!(value["contents"][0]["uri"], "memoric://timeline");
        let text = value["contents"][0]["text"]
            .as_str()
            .expect("timeline text");
        let parsed: Value = serde_json::from_str(text).expect("timeline json");
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["timeline_version"], 1);
    }

    #[test]
    fn artifact_resource_reads_registered_file() {
        let path = std::env::temp_dir().join(format!(
            "memoric-resource-artifact-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "resource text").unwrap();
        let artifact = crate::artifact::register_file_artifact(&path, 60).unwrap();
        let uri = artifact["uri"].as_str().unwrap();

        let value = read(uri).expect("artifact resource read");
        assert_eq!(value["contents"][0]["uri"], uri);
        assert_eq!(value["contents"][0]["text"], "resource text");

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(path);
    }
}
