//! MCP tools/list pagination helpers.

use serde_json::{json, Value};

const DEFAULT_TOOL_LIST_LIMIT: usize = 100;
const MAX_TOOL_LIST_LIMIT: usize = 500;
const TOOL_CURSOR_PREFIX: &str = "tool-cursor:";

pub fn list_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params");
    let uses_pagination = params
        .map(|params| params.get("limit").is_some() || params.get("cursor").is_some())
        .unwrap_or(false);

    if !uses_pagination {
        return Ok(json!({ "tools": crate::mcp::tool_schema::register_tools() }));
    }

    let limit = parse_tool_list_limit(params)?;
    let cursor = match params.and_then(|params| params.get("cursor")) {
        Some(Value::String(cursor)) => Some(cursor.as_str()),
        Some(_) => return Err("Invalid cursor: expected opaque string token".to_string()),
        None => None,
    };

    list_page(limit, cursor)
}

pub fn list_page(limit: usize, cursor: Option<&str>) -> Result<Value, String> {
    let limit = limit.clamp(1, MAX_TOOL_LIST_LIMIT);
    let start = decode_tool_cursor(cursor)?;
    let tools = crate::mcp::tool_schema::register_tools();

    if start > tools.len() {
        return Err("Invalid cursor: pagination position is outside tool list".to_string());
    }

    let total = tools.len();
    let page = tools
        .into_iter()
        .skip(start)
        .take(limit)
        .collect::<Vec<_>>();
    let mut response = json!({ "tools": page });
    let next_offset = start.saturating_add(limit);
    if next_offset < total {
        response["nextCursor"] = json!(encode_tool_cursor(next_offset));
    }
    Ok(response)
}

fn parse_tool_list_limit(params: Option<&Value>) -> Result<usize, String> {
    match params.and_then(|params| params.get("limit")) {
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| "Invalid limit: expected positive integer".to_string())?;
            let limit = usize::try_from(raw).map_err(|_| "Invalid limit: too large".to_string())?;
            Ok(limit.clamp(1, MAX_TOOL_LIST_LIMIT))
        }
        None => Ok(DEFAULT_TOOL_LIST_LIMIT),
    }
}

fn encode_tool_cursor(offset: usize) -> String {
    format!("{}{}", TOOL_CURSOR_PREFIX, offset)
}

fn decode_tool_cursor(cursor: Option<&str>) -> Result<usize, String> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let raw = cursor
        .strip_prefix(TOOL_CURSOR_PREFIX)
        .ok_or_else(|| "Invalid cursor: unrecognized opaque token".to_string())?;
    if raw.is_empty() {
        return Err("Invalid cursor: empty pagination position".to_string());
    }
    raw.parse::<usize>()
        .map_err(|_| "Invalid cursor: malformed pagination position".to_string())
}
