use serde_json::{json, Value};

pub(crate) fn parse_u64_arg(value: Option<&Value>) -> Option<u64> {
    crate::args::parse_u64_value(value)
}

pub(crate) fn parse_address_arg(value: Option<&Value>) -> Option<u64> {
    crate::args::parse_address_value(value)
}

pub(crate) fn normalize_alias(
    args: &Value,
    canonical: &str,
    alias: &str,
    tool: &str,
    action: &str,
) -> Value {
    if args.get(canonical).is_some() || args.get(alias).is_none() {
        return args.clone();
    }

    tracing::warn!(
        "{}(action='{}', {}=...) is deprecated, use {} instead",
        tool,
        action,
        alias,
        canonical
    );

    let mut normalized = args.clone();
    if let Some(value) = args.get(alias) {
        normalized
            .as_object_mut()
            .map(|m| m.insert(canonical.to_string(), value.clone()));
    }
    normalized
}

pub(crate) fn normalize_common_args(tool: &str, args: &Value) -> Value {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let mut normalized = args.clone();

    for alias in crate::mcp::action_registry::parameter_aliases(tool, action) {
        normalized = normalize_alias(&normalized, alias.canonical, alias.alias, tool, action);
    }

    normalized = normalize_parser_hint_values(tool, action, &normalized);

    normalized
}

fn normalize_parser_hint_values(tool: &str, action: &str, args: &Value) -> Value {
    let mut normalized = args.clone();

    for hint in crate::mcp::action_registry::parser_hints(tool, action) {
        let Some(value) = normalized.get(hint.parameter.as_str()) else {
            continue;
        };
        let normalized_value = if hint.parser == "object_array" {
            hint.object_item_schema
                .and_then(|schema| normalize_object_array_items(value, schema))
        } else if matches!(hint.parser, "array_length" | "string_array") {
            hint.array_item_parser
                .and_then(|parser| normalize_array_items(value, parser))
        } else {
            normalize_value_for_parser_hint(hint.parser, value)
        };
        let Some(normalized_value) = normalized_value else {
            continue;
        };
        if let Some(obj) = normalized.as_object_mut() {
            obj.insert(hint.parameter, normalized_value);
        }
    }

    normalized
}

fn normalize_value_for_parser_hint(parser: &str, value: &Value) -> Option<Value> {
    match parser {
        "pid_u32" | "tid_u32" => {
            let parsed = crate::args::parse_u64(value)?;
            if parsed > u32::MAX as u64 {
                return None;
            }
            Some(json!(parsed))
        }
        "u64" => crate::args::parse_u64(value).map(|parsed| json!(parsed)),
        "address_u64" => {
            if !value.is_string() {
                return None;
            }
            crate::util::parse_address(value).map(|parsed| json!(parsed))
        }
        "pool_tag" => {
            let parsed = crate::args::parse_u64(value)
                .filter(|number| *number <= u32::MAX as u64)
                .or_else(|| {
                    let tag = value.as_str()?;
                    if tag.is_empty() || tag.len() > 4 || !tag.is_ascii() {
                        return None;
                    }
                    let mut bytes = [0u8; 4];
                    for (idx, byte) in tag.as_bytes().iter().enumerate() {
                        bytes[idx] = *byte;
                    }
                    Some(u32::from_le_bytes(bytes) as u64)
                })?;
            Some(json!(parsed))
        }
        "bytes" => {
            if value.is_array() {
                return None;
            }
            crate::args::parse_bytes_value(value, crate::args::DEFAULT_MAX_BYTES)
                .ok()
                .map(|bytes| Value::Array(bytes.into_iter().map(|byte| json!(byte)).collect()))
        }
        "protection" => {
            crate::args::parse_protection_value(value).map(|protection| json!(protection))
        }
        "module_name" => {
            crate::args::parse_module_name_value(value, crate::args::DEFAULT_MAX_MODULE_NAME_LEN)
                .ok()
                .map(|module| json!(module))
        }
        "path" => crate::args::parse_path_value(value, crate::args::DEFAULT_MAX_PATH_LEN)
            .ok()
            .map(|path| json!(path)),
        _ => None,
    }
}

fn normalize_object_array_items(
    value: &Value,
    schema: crate::mcp::action_registry::ObjectItemSchemaDescriptor,
) -> Option<Value> {
    let values = value.as_array()?;
    let mut changed = false;
    let mut normalized_values = Vec::with_capacity(values.len());

    for item in values {
        let Some(object) = item.as_object() else {
            normalized_values.push(item.clone());
            continue;
        };
        let mut normalized_item = item.clone();

        for property in schema.properties {
            let Some(property_value) = object.get(property.name) else {
                continue;
            };
            let Some(normalized_property) =
                normalize_value_for_parser_hint(property.parser, property_value)
            else {
                continue;
            };
            if normalized_property == *property_value {
                continue;
            }
            if let Some(normalized_object) = normalized_item.as_object_mut() {
                normalized_object.insert(property.name.to_string(), normalized_property);
                changed = true;
            }
        }

        normalized_values.push(normalized_item);
    }

    changed.then_some(Value::Array(normalized_values))
}

fn normalize_array_items(value: &Value, item_parser: &str) -> Option<Value> {
    let values = value.as_array()?;
    let mut changed = false;
    let mut normalized_values = Vec::with_capacity(values.len());

    for item in values {
        let Some(normalized_item) = normalize_value_for_parser_hint(item_parser, item) else {
            normalized_values.push(item.clone());
            continue;
        };
        if normalized_item == *item {
            normalized_values.push(item.clone());
            continue;
        }
        changed = true;
        normalized_values.push(normalized_item);
    }

    changed.then_some(Value::Array(normalized_values))
}

pub(crate) fn normalize_kernel_args(args: &Value) -> Value {
    let mut normalized = args.clone();

    if let Some(action) = normalized.get("action").and_then(|v| v.as_str()) {
        let canonical_action = match action {
            "notify_routine" => Some("driver_notify_routine"),
            "reg_protect" => Some("driver_reg_protect"),
            "object_hook" => Some("driver_object_hook"),
            "port_hide" => Some("driver_port_hide"),
            _ => None,
        };

        if let Some(canonical) = canonical_action {
            tracing::warn!(
                "kernel(action='{}') is deprecated, use action='{}' instead",
                action,
                canonical
            );
            normalized
                .as_object_mut()
                .map(|m| m.insert("action".to_string(), json!(canonical)));
        }
    }

    normalize_common_args("kernel", &normalized)
}

pub(crate) fn require_action<'a>(
    args: &'a Value,
    tool: &str,
    available: &str,
) -> Result<&'a str, String> {
    args.get("action").and_then(|v| v.as_str()).ok_or_else(|| {
        format!(
            "{} requires 'action'. Available actions: {}. Call `memoric` with domain='{}' for current usage.",
            tool, available, tool
        )
    })
}

pub(crate) fn require_registered_action<'a>(
    args: &'a Value,
    tool: &str,
) -> Result<&'a str, String> {
    let available = crate::mcp::action_registry::actions_csv(tool);
    require_action(args, tool, &available)
}

pub(crate) fn require_typed_action(
    args: &Value,
    tool: &str,
) -> Result<crate::mcp::action_registry::RegisteredAction, String> {
    let action = require_registered_action(args, tool)?;
    crate::mcp::action_registry::registered_action(tool, action)
        .ok_or_else(|| unknown_registered_action_error(tool, action))
}

fn unknown_action_error(tool: &str, action: &str, available: &str) -> String {
    format!(
        "Unknown {} action: {}. Available: {}. Call `memoric` with domain='{}' for examples.",
        tool, action, available, tool
    )
}

pub(crate) fn unknown_registered_action_error(tool: &str, action: &str) -> String {
    unknown_action_error(
        tool,
        action,
        &crate::mcp::action_registry::actions_csv(tool),
    )
}

pub(crate) fn validate_required_parameters(tool: &str, args: &Value) -> Result<(), String> {
    if tool == "memoric" {
        return Ok(());
    }

    let action = require_typed_action(args, tool)?;
    let action_name = action.as_str();

    let aliases = &action.parameter_aliases;
    for parameter in action.required_parameters {
        let parameter = *parameter;
        let alias_supplied = aliases
            .iter()
            .any(|alias| alias.canonical == parameter && has_required_value(args, alias.alias));
        if !has_required_value(args, parameter) && !alias_supplied {
            return Err(missing_param_error(
                tool,
                action_name,
                parameter,
                Some("This requirement is declared by the action registry."),
            ));
        }
    }

    for condition in &action.conditional_required_parameters {
        if !condition.matches_args(args) {
            continue;
        }
        for parameter in condition.parameters {
            let alias_supplied = aliases.iter().any(|alias| {
                alias.canonical == *parameter && has_required_value(args, alias.alias)
            });
            if !has_required_value(args, parameter) && !alias_supplied {
                return Err(missing_param_error(
                    tool,
                    action_name,
                    parameter,
                    Some(condition.description),
                ));
            }
        }
    }

    for alternative in &action.alternative_required_parameters {
        if !alternative.matches_args(args) {
            continue;
        }
        let has_any = alternative.parameters.iter().any(|parameter| {
            has_required_value(args, parameter)
                || aliases.iter().any(|alias| {
                    alias.canonical == *parameter && has_required_value(args, alias.alias)
                })
        });
        if !has_any {
            let display = alternative.parameters.join("' or '");
            return Err(missing_param_error(
                tool,
                action_name,
                &display,
                Some(alternative.description),
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_choice_parameters(tool: &str, args: &Value) -> Result<(), String> {
    if tool == "memoric" {
        return Ok(());
    }

    let action = require_typed_action(args, tool)?;
    let action_name = action.as_str();

    let aliases = &action.parameter_aliases;
    for choice in &action.choice_parameters {
        let Some(value) = args.get(choice.parameter).or_else(|| {
            aliases
                .iter()
                .find(|alias| alias.canonical == choice.parameter)
                .and_then(|alias| args.get(alias.alias))
        }) else {
            continue;
        };
        let Some(value) = value.as_str() else {
            return Err(invalid_param_error(
                tool,
                action_name,
                choice.parameter,
                "expected a string value from the action registry choice descriptor",
            ));
        };
        if !choice.values.contains(&value) {
            return Err(invalid_choice_error(
                tool,
                action_name,
                choice.parameter,
                value,
                &choice.values.join(", "),
            ));
        }
    }

    for choice in &action.array_choice_parameters {
        let Some(value) = args.get(choice.parameter).or_else(|| {
            aliases
                .iter()
                .find(|alias| alias.canonical == choice.parameter)
                .and_then(|alias| args.get(alias.alias))
        }) else {
            continue;
        };
        let Some(items) = value.as_array() else {
            return Err(invalid_param_error(
                tool,
                action_name,
                choice.parameter,
                "expected an array value from the action registry array choice descriptor",
            ));
        };
        for item in items {
            let Some(item) = item.as_str() else {
                return Err(invalid_param_error(
                    tool,
                    action_name,
                    choice.parameter,
                    "expected array items to be strings from the action registry array choice descriptor",
                ));
            };
            if !choice.values.contains(&item) {
                return Err(invalid_choice_error(
                    tool,
                    action_name,
                    choice.parameter,
                    item,
                    &choice.values.join(", "),
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_parameter_bounds(tool: &str, args: &Value) -> Result<(), String> {
    if tool == "memoric" {
        return Ok(());
    }

    let action = require_typed_action(args, tool)?;
    let action_name = action.as_str();

    let aliases = &action.parameter_aliases;
    for bounds in &action.parameter_bounds {
        let Some(value) = args.get(bounds.parameter).or_else(|| {
            aliases
                .iter()
                .find(|alias| alias.canonical == bounds.parameter)
                .and_then(|alias| args.get(alias.alias))
        }) else {
            continue;
        };
        let value = parameter_bound_value_from_parser_hint(
            tool,
            action_name,
            &action.parser_hints,
            bounds,
            value,
        )?;
        if let Some(minimum) = bounds.minimum {
            if value < minimum {
                return Err(invalid_param_error(
                    tool,
                    action_name,
                    bounds.parameter,
                    &format!("expected a value >= {}", minimum),
                ));
            }
        }
        if let Some(maximum) = bounds.maximum {
            if value > maximum {
                return Err(invalid_param_error(
                    tool,
                    action_name,
                    bounds.parameter,
                    &format!("expected a value <= {}", maximum),
                ));
            }
        }
    }

    Ok(())
}

fn parameter_bound_value_from_parser_hint(
    tool: &str,
    action: &str,
    hints: &[crate::mcp::action_registry::ParserHintDescriptor],
    bounds: &crate::mcp::action_registry::ParameterBoundsDescriptor,
    value: &Value,
) -> Result<u64, String> {
    let parser = hints
        .iter()
        .find(|hint| hint.parameter == bounds.parameter)
        .map(|hint| hint.parser)
        .unwrap_or("u64");

    match parser {
        "bytes" => crate::args::parse_bytes_value(value, crate::args::DEFAULT_MAX_BYTES)
            .map(|bytes| bytes.len() as u64)
            .map_err(|error| {
                invalid_param_error(
                    tool,
                    action,
                    bounds.parameter,
                    &format!(
                        "expected byte array or hex byte string from the action registry parser hint ({})",
                        error
                    ),
                )
            }),
        "array_length" | "object_array" => {
            let Some(values) = value.as_array() else {
                return Err(invalid_param_error(
                    tool,
                    action,
                    bounds.parameter,
                    "expected an array value from the action registry parser hint",
                ));
            };
            if parser == "object_array" && values.iter().any(|item| !item.is_object()) {
                return Err(invalid_param_error(
                    tool,
                    action,
                    bounds.parameter,
                    "expected an array of objects from the action registry parser hint",
                ));
            }
            Ok(values.len() as u64)
        }
        "byte_pattern" => crate::args::parse_byte_pattern_value(value, crate::args::DEFAULT_MAX_BYTES)
            .map(|pattern| pattern.len() as u64)
            .map_err(|error| {
                invalid_param_error(
                    tool,
                    action,
                    bounds.parameter,
                    &format!(
                        "expected byte pattern string/array from the action registry parser hint ({})",
                        error
                    ),
                )
            }),
        _ => crate::args::parse_u64(value).ok_or_else(|| {
            invalid_param_error(
                tool,
                action,
                bounds.parameter,
                "expected an unsigned integer value from the action registry parser hint",
            )
        }),
    }
}

pub(crate) fn validate_common_input_bounds(tool: &str, args: &Value) -> Result<(), String> {
    if tool == "memoric" {
        return Ok(());
    }

    let action = require_typed_action(args, tool)?;
    let action_name = action.as_str();

    for field in crate::mcp::action_registry::common_input_fields() {
        let Some(bounds) = field.bounds else {
            continue;
        };
        let Some(value) = args.get(field.name) else {
            continue;
        };
        let Some(value) = crate::args::parse_u64(value) else {
            return Err(invalid_param_error(
                tool,
                action_name,
                field.name,
                "expected an unsigned integer value from the common input field descriptor",
            ));
        };
        if let Some(minimum) = bounds.minimum {
            if value < minimum {
                return Err(invalid_param_error(
                    tool,
                    action_name,
                    field.name,
                    &format!("expected a value >= {}", minimum),
                ));
            }
        }
        if let Some(maximum) = bounds.maximum {
            if value > maximum {
                return Err(invalid_param_error(
                    tool,
                    action_name,
                    field.name,
                    &format!("expected a value <= {}", maximum),
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_parser_hints(tool: &str, args: &Value) -> Result<(), String> {
    if tool == "memoric" {
        return Ok(());
    }

    let action = require_typed_action(args, tool)?;
    let action_name = action.as_str();

    for hint in &action.parser_hints {
        let Some(value) = args.get(hint.parameter.as_str()) else {
            continue;
        };
        validate_parser_hint_value(
            tool,
            action_name,
            &hint.parameter,
            hint.parser,
            value,
            hint.array_item_parser,
            hint.object_item_schema,
        )?;
    }

    Ok(())
}

fn validate_parser_hint_value(
    tool: &str,
    action: &str,
    parameter: &str,
    parser: &str,
    value: &Value,
    array_item_parser: Option<&str>,
    object_item_schema: Option<crate::mcp::action_registry::ObjectItemSchemaDescriptor>,
) -> Result<(), String> {
    match parser {
        "pid_u32" | "tid_u32" => {
            let Some(value) = crate::args::parse_u64(value) else {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an unsigned integer from the action registry parser hints",
                ));
            };
            if value > u32::MAX as u64 {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected a value in the supported u32 range from the action registry parser hints",
                ));
            }
        }
        "address_u64" => {
            if crate::util::parse_address(value).is_none() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected integer, decimal string, or hex string address from the action registry parser hints",
                ));
            }
        }
        "pool_tag" => {
            if let Some(number) = crate::args::parse_u64(value) {
                if number > u32::MAX as u64 {
                    return Err(invalid_param_error(
                        tool,
                        action,
                        parameter,
                        "expected a pool tag integer in the supported u32 range from the action registry parser hints",
                    ));
                }
            } else if let Some(tag) = value.as_str() {
                if tag.is_empty() || tag.len() > 4 || !tag.is_ascii() {
                    return Err(invalid_param_error(
                        tool,
                        action,
                        parameter,
                        "expected a 1-4 byte ASCII pool tag string or u32 integer from the action registry parser hints",
                    ));
                }
            } else {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected a 1-4 byte ASCII pool tag string or u32 integer from the action registry parser hints",
                ));
            }
        }
        "u64" => {
            if crate::args::parse_u64(value).is_none() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an unsigned integer from the action registry parser hints",
                ));
            }
        }
        "number" => {
            if value.as_f64().is_none() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected JSON number from the action registry parser hints",
                ));
            }
        }
        "bytes" => {
            if crate::args::parse_bytes_value(value, crate::args::DEFAULT_MAX_BYTES).is_err() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected byte array or hex byte string from the action registry parser hints",
                ));
            }
        }
        "number_array" => {
            let Some(values) = value.as_array() else {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an array from the action registry parser hints",
                ));
            };
            if values.iter().any(|item| item.as_f64().is_none()) {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an array of JSON numbers from the action registry parser hints",
                ));
            }
        }
        "array_length" | "object_array" | "string_array" => {
            if !value.is_array() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an array from the action registry parser hints",
                ));
            }
            if parser == "object_array"
                && value
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| !item.is_object()))
            {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an array of objects from the action registry parser hints",
                ));
            }
            if parser == "string_array"
                && value
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| !item.is_string()))
            {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected an array of strings from the action registry parser hints",
                ));
            }
            if let (Some(values), Some(item_parser)) = (value.as_array(), array_item_parser) {
                for (index, item) in values.iter().enumerate() {
                    validate_array_item_parser_hint(
                        tool,
                        action,
                        parameter,
                        index,
                        item_parser,
                        item,
                    )?;
                }
            }
            if let (Some(values), Some(item_schema)) = (value.as_array(), object_item_schema) {
                for (index, item) in values.iter().enumerate() {
                    validate_object_array_item(tool, action, parameter, index, item, item_schema)?;
                }
            }
        }
        "byte_pattern" => {
            if crate::args::parse_byte_pattern_value(value, crate::args::DEFAULT_MAX_BYTES).is_err()
            {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected byte pattern string/array with hex bytes and optional ?? wildcards from the action registry parser hints",
                ));
            }
        }
        "protection" => {
            if crate::args::parse_protection_value(value).is_none() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected page protection string or integer from the action registry parser hints",
                ));
            }
        }
        "module_name" => {
            if let Err(err) = crate::args::parse_module_name_value(
                value,
                crate::args::DEFAULT_MAX_MODULE_NAME_LEN,
            ) {
                return Err(invalid_param_error(tool, action, parameter, &err));
            }
        }
        "path" => {
            if let Err(err) =
                crate::args::parse_path_value(value, crate::args::DEFAULT_MAX_PATH_LEN)
            {
                return Err(invalid_param_error(tool, action, parameter, &err));
            }
        }
        "boolean" => {
            if !value.is_boolean() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected boolean from the action registry parser hints",
                ));
            }
        }
        "string" => {
            if value.as_str().is_none() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected string from the action registry parser hints",
                ));
            }
        }
        "object" => {
            if !value.is_object() {
                return Err(invalid_param_error(
                    tool,
                    action,
                    parameter,
                    "expected object from the action registry parser hints",
                ));
            }
        }
        _ => {
            return Err(invalid_param_error(
                tool,
                action,
                parameter,
                &format!("unsupported action registry parser hint '{parser}'"),
            ));
        }
    }

    Ok(())
}

fn validate_array_item_parser_hint(
    tool: &str,
    action: &str,
    parameter: &str,
    index: usize,
    item_parser: &str,
    value: &Value,
) -> Result<(), String> {
    let invalid = |detail: &str| {
        invalid_param_error(
            tool,
            action,
            parameter,
            &format!(
                "expected {}[{}] to match registry array item parser '{}': {}",
                parameter, index, item_parser, detail
            ),
        )
    };

    match item_parser {
        "address_u64" => {
            if crate::util::parse_address(value).is_none() {
                return Err(invalid(
                    "expected integer, decimal string, or hex string address",
                ));
            }
        }
        "u64" => {
            if crate::args::parse_u64(value).is_none() {
                return Err(invalid("expected unsigned integer"));
            }
        }
        "string" => {
            if value.as_str().is_none() {
                return Err(invalid("expected string"));
            }
        }
        "boolean" => {
            if !value.is_boolean() {
                return Err(invalid("expected boolean"));
            }
        }
        "number" => {
            if value.as_f64().is_none() {
                return Err(invalid("expected JSON number"));
            }
        }
        "object" => {
            if !value.is_object() {
                return Err(invalid("expected object"));
            }
        }
        _ => {
            return Err(invalid(&format!(
                "unsupported action registry array item parser '{item_parser}'"
            )));
        }
    }

    Ok(())
}

fn validate_object_array_item(
    tool: &str,
    action: &str,
    parameter: &str,
    index: usize,
    item: &Value,
    schema: crate::mcp::action_registry::ObjectItemSchemaDescriptor,
) -> Result<(), String> {
    for required in schema.required {
        let present = item
            .get(*required)
            .is_some_and(|value| !matches!(value, Value::Null));
        if !present {
            return Err(invalid_param_error(
                tool,
                action,
                parameter,
                &format!(
                    "expected {}[{}] object item to include required field '{}' from the action registry parser hints",
                    parameter, index, required
                ),
            ));
        }
    }

    for property in schema.properties {
        let Some(value) = item.get(property.name) else {
            continue;
        };
        validate_object_item_property_value(tool, action, parameter, index, property, value)?;
    }

    Ok(())
}

fn validate_object_item_property_value(
    tool: &str,
    action: &str,
    parameter: &str,
    index: usize,
    property: &crate::mcp::action_registry::ObjectItemPropertyDescriptor,
    value: &Value,
) -> Result<(), String> {
    let invalid = |detail: &str| {
        invalid_param_error(
            tool,
            action,
            parameter,
            &format!(
                "expected {}[{}].{} to match registry object item parser '{}': {}",
                parameter, index, property.name, property.parser, detail
            ),
        )
    };

    match property.parser {
        "address_u64" => {
            if crate::util::parse_address(value).is_none() {
                return Err(invalid(
                    "expected integer, decimal string, or hex string address",
                ));
            }
        }
        "object" => {
            if !value.is_object() {
                return Err(invalid("expected object"));
            }
        }
        "boolean" => {
            if !value.is_boolean() {
                return Err(invalid("expected boolean"));
            }
        }
        "string_array" => {
            let Some(values) = value.as_array() else {
                return Err(invalid("expected array"));
            };
            if values.iter().any(|item| !item.is_string()) {
                return Err(invalid("expected array of strings"));
            }
        }
        "string" => {
            if value.as_str().is_none() {
                return Err(invalid("expected string"));
            }
        }
        "u64" => {
            if crate::args::parse_u64(value).is_none() {
                return Err(invalid("expected unsigned integer"));
            }
        }
        _ => {
            return Err(invalid(&format!(
                "unsupported action registry object item parser '{}'",
                property.parser
            )));
        }
    }

    Ok(())
}

pub(crate) fn invalid_registered_choice_error(
    tool: &str,
    action: &str,
    field: &str,
    value: &str,
) -> String {
    let allowed = crate::mcp::action_registry::choice_values_csv(tool, action, field)
        .unwrap_or_else(|| "no registered choices".to_string());
    invalid_choice_error(tool, action, field, value, &allowed)
}

pub(crate) fn invalid_choice_error(
    tool: &str,
    action: &str,
    field: &str,
    value: &str,
    allowed: &str,
) -> String {
    format!(
        "Invalid {} for {}(action='{}'): {}. Allowed: {}.",
        field, tool, action, value, allowed
    )
}

pub(crate) fn missing_param_error(
    tool: &str,
    action: &str,
    param: &str,
    hint: Option<&str>,
) -> String {
    match hint {
        Some(hint) => format!(
            "{}(action='{}') requires '{}'. {}",
            tool, action, param, hint
        ),
        None => format!("{}(action='{}') requires '{}'.", tool, action, param),
    }
}

pub(crate) fn invalid_param_error(tool: &str, action: &str, param: &str, detail: &str) -> String {
    format!(
        "{}(action='{}') invalid '{}': {}.",
        tool, action, param, detail
    )
}

pub(crate) fn require_u64_param(
    args: &Value,
    key: &str,
    tool: &str,
    action: &str,
) -> Result<u64, String> {
    if is_address_like_param(key) {
        crate::args::require_address(args, key)
            .map_err(|_| missing_param_error(tool, action, key, None))
    } else {
        crate::args::require_u64(args, key)
            .map_err(|_| missing_param_error(tool, action, key, None))
    }
}

pub(crate) fn require_u32_param(
    args: &Value,
    key: &str,
    tool: &str,
    action: &str,
) -> Result<u32, String> {
    let value = require_u64_param(args, key, tool, action)?;
    u32::try_from(value).map_err(|_| {
        invalid_param_error(
            tool,
            action,
            key,
            "expected a value in the supported u32 range",
        )
    })
}

pub(crate) fn require_byte_array_param(
    args: &Value,
    key: &str,
    tool: &str,
    action: &str,
) -> Result<Vec<u8>, String> {
    let value = args
        .get(key)
        .ok_or_else(|| missing_param_error(tool, action, key, None))?;

    match crate::args::parse_bytes_value(value, crate::args::DEFAULT_MAX_BYTES) {
        Ok(bytes) => Ok(bytes),
        Err(err) if err == "expected byte array or hex string" => Err(missing_param_error(
            tool,
            action,
            key,
            Some("Provide a non-empty byte array with values in 0..255."),
        )),
        Err(err) => Err(invalid_param_error(tool, action, key, &err)),
    }
}

pub(crate) fn require_nonzero_usize_param(
    args: &Value,
    key: &str,
    tool: &str,
    action: &str,
) -> Result<usize, String> {
    let value = require_u64_param(args, key, tool, action)?;
    if value == 0 {
        return Err(invalid_param_error(
            tool,
            action,
            key,
            "expected a non-zero value",
        ));
    }

    let maximum = crate::mcp::action_registry::registered_action(tool, action)
        .and_then(|registered| {
            registered
                .parameter_bounds
                .iter()
                .find(|bounds| bounds.parameter == key)
                .and_then(|bounds| bounds.maximum)
        })
        .and_then(|maximum| usize::try_from(maximum).ok())
        .unwrap_or(usize::MAX);

    crate::args::require_nonzero_usize(args, key, maximum)
        .map_err(|err| invalid_param_error(tool, action, key, &err))
}

pub(crate) fn optional_bounded_u64_param(
    args: &Value,
    key: &str,
    tool: &str,
    action: &str,
    default: u64,
) -> Result<u64, String> {
    let Some(value) = args.get(key) else {
        return Ok(default);
    };
    let value = crate::args::parse_u64(value).ok_or_else(|| {
        invalid_param_error(
            tool,
            action,
            key,
            "expected an unsigned integer value from the action registry parser hint",
        )
    })?;

    if let Some(bounds) = crate::mcp::action_registry::parameter_bounds(tool, action)
        .into_iter()
        .find(|bounds| bounds.parameter == key)
    {
        if let Some(minimum) = bounds.minimum {
            if value < minimum {
                return Err(invalid_param_error(
                    tool,
                    action,
                    key,
                    &format!("expected a value >= {}", minimum),
                ));
            }
        }
        if let Some(maximum) = bounds.maximum {
            if value > maximum {
                return Err(invalid_param_error(
                    tool,
                    action,
                    key,
                    &format!("expected a value <= {}", maximum),
                ));
            }
        }
    }

    Ok(value)
}

pub(crate) fn require_str_param<'a>(
    args: &'a Value,
    key: &str,
    tool: &str,
    action: &str,
    hint: Option<&str>,
) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| missing_param_error(tool, action, key, hint))
}

pub(crate) fn require_module_name_param<'a>(
    args: &'a Value,
    key: &str,
    tool: &str,
    action: &str,
    hint: Option<&str>,
) -> Result<&'a str, String> {
    let value = args
        .get(key)
        .ok_or_else(|| missing_param_error(tool, action, key, hint))?;

    match crate::args::parse_module_name_value(value, crate::args::DEFAULT_MAX_MODULE_NAME_LEN) {
        Ok(module) => Ok(module),
        Err(err)
            if err == "expected module name string" || err == "module name must not be empty" =>
        {
            Err(missing_param_error(tool, action, key, hint))
        }
        Err(err) => Err(invalid_param_error(tool, action, key, &err)),
    }
}

fn is_address_like_param(key: &str) -> bool {
    key == "address"
        || key.ends_with("_address")
        || key.ends_with("_addr")
        || matches!(
            key,
            "base_address"
                | "target_address"
                | "hook_address"
                | "iat_address"
                | "original_address"
                | "replacement_addr"
                | "handler_address"
                | "new_handler"
                | "alloc_address"
                | "thread_start"
                | "thread_context"
        )
}

fn has_required_value(args: &Value, key: &str) -> bool {
    match args.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::String(value)) => !value.trim().is_empty(),
        Some(Value::Array(values)) => !values.is_empty(),
        Some(Value::Object(values)) => !values.is_empty(),
        Some(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn normalizes_common_aliases_from_action_registry_descriptors() {
        let memory = normalize_common_args(
            "memory",
            &json!({
                "action": "scan_new",
                "base_address": "0x1000",
                "length": 128,
                "data": [1, 2, 3],
                "pattern_bytes": "AA BB"
            }),
        );
        assert_eq!(memory["address"], json!(0x1000u64));
        assert_eq!(memory["size"], 128);
        assert_eq!(memory["bytes"], json!([1, 2, 3]));
        assert_eq!(memory["signature"], "AA BB");

        let write = normalize_common_args(
            "memory",
            &json!({
                "action": "write",
                "pid": 1234,
                "address": "0x1000",
                "data": "DE AD BE EF"
            }),
        );
        assert_eq!(write["bytes"], json!([0xDE, 0xAD, 0xBE, 0xEF]));

        let payload = normalize_common_args(
            "payload",
            &json!({
                "action": "obfuscate",
                "obf_method": "xor",
                "payload_hex": "90 C3"
            }),
        );
        assert_eq!(payload["payload"], json!([0x90, 0xC3]));

        let target = normalize_common_args(
            "target",
            &json!({"action": "module_base", "module": " kernel32.dll "}),
        );
        assert_eq!(target["module_name"], "kernel32.dll");
    }

    #[test]
    fn normalizes_numeric_parser_hint_values_from_action_registry_descriptors() {
        let target = normalize_common_args(
            "target",
            &json!({
                "action": "windows",
                "pid": "1234",
                "limit": "0x20",
                "wait_ms": "1000"
            }),
        );
        assert_eq!(target["pid"], json!(1234));
        assert_eq!(target["limit"], json!(32));
        assert_eq!(target["wait_ms"], json!(1000));

        let hook = normalize_common_args(
            "hook",
            &json!({
                "action": "install_hwbp",
                "tid": "42",
                "dr_index": "0x2",
                "target_address": "0x1000"
            }),
        );
        assert_eq!(hook["tid"], json!(42));
        assert_eq!(hook["dr_index"], json!(2));
        assert_eq!(hook["target_address"], json!(0x1000u64));

        let kernel = normalize_common_args(
            "kernel",
            &json!({
                "action": "pte_modify",
                "read_ioctl": "0x222004",
                "write_ioctl": "0x222008",
                "address": "0xFFFF800000001000",
                "cr3": "0x12345000"
            }),
        );
        assert_eq!(kernel["read_ioctl"], json!(0x222004u64));
        assert_eq!(kernel["write_ioctl"], json!(0x222008u64));
        assert_eq!(kernel["cr3"], json!(0x12345000u64));
        assert_eq!(kernel["address"], json!(0xFFFF800000001000u64));

        let cred_dump = normalize_common_args(
            "kernel",
            &json!({
                "action": "driver_cred_dump",
                "cred_action": "read",
                "pid": "500",
                "address": "0xFFFF800000123000",
                "size": "0x80"
            }),
        );
        assert_eq!(cred_dump["pid"], json!(500));
        assert_eq!(cred_dump["address"], json!(0xFFFF800000123000u64));
        assert_eq!(cred_dump["size"], json!(0x80u64));
    }

    #[test]
    fn normalizes_pool_tag_parser_hint_values_from_action_registry_descriptors() {
        let kernel = normalize_common_args(
            "kernel",
            &json!({
                "action": "driver_memory_pool",
                "pool_tag": "Proc",
                "max_entries": "0x100"
            }),
        );

        assert_eq!(kernel["pool_tag"], json!(0x636F7250u64));
        assert_eq!(kernel["max_entries"], json!(256));

        let numeric_pool_tag = normalize_common_args(
            "kernel",
            &json!({
                "action": "driver_memory_pool",
                "pool_tag": "0x636F7250"
            }),
        );
        assert_eq!(numeric_pool_tag["pool_tag"], json!(0x636F7250u64));
    }

    #[test]
    fn normalizes_string_parser_hint_values_from_action_registry_descriptors() {
        let inject = normalize_common_args(
            "inject",
            &json!({
                "action": "dll",
                "pid": 42,
                "dll_path": " C:\\temp\\payload.dll "
            }),
        );
        assert_eq!(inject["dll_path"], "C:\\temp\\payload.dll");

        let kernel = normalize_kernel_args(&json!({
            "action": "driver_global_hook",
            "module": " ntoskrnl.exe ",
            "function": "NtOpenProcess",
            "hook_address": "0x1000"
        }));
        assert_eq!(kernel["target_module"], "ntoskrnl.exe");
        assert_eq!(kernel["target_function"], "NtOpenProcess");
        assert_eq!(kernel["replacement_addr"], json!(0x1000u64));
    }

    #[test]
    fn normalizes_object_array_item_parser_hint_values_from_action_registry_descriptors() {
        let hook = normalize_common_args(
            "hook",
            &json!({
                "action": "detour",
                "pid": 42,
                "hooks": [
                    {
                        "target_address": "0x1000",
                        "hook_address": "8192",
                        "note": "preserve unmodeled fields"
                    }
                ]
            }),
        );

        assert_eq!(hook["hooks"][0]["target_address"], json!(0x1000u64));
        assert_eq!(hook["hooks"][0]["hook_address"], json!(8192u64));
        assert_eq!(hook["hooks"][0]["note"], "preserve unmodeled fields");
    }

    #[test]
    fn normalizes_array_item_parser_hint_values_from_action_registry_descriptors() {
        let cleanup = normalize_common_args(
            "payload",
            &json!({
                "action": "cleanup",
                "addresses": ["0x1000", "8192"],
                "thread_handles": ["42", "0x2A"]
            }),
        );

        assert_eq!(cleanup["addresses"], json!([0x1000u64, 8192u64]));
        assert_eq!(cleanup["thread_handles"], json!([42u64, 42u64]));

        let obfuscate = normalize_common_args(
            "payload",
            &json!({
                "action": "obfuscate",
                "payload": [1, 2, 3],
                "strings": ["alpha", "beta"],
                "transforms": ["xor"]
            }),
        );

        assert_eq!(obfuscate["strings"], json!(["alpha", "beta"]));
        assert_eq!(obfuscate["transforms"], json!(["xor"]));
    }

    #[test]
    fn explicit_canonical_values_win_over_aliases() {
        let normalized = normalize_common_args(
            "inject",
            &json!({
                "action": "spawn",
                "target_path": "C:\\canonical.exe",
                "target_exe": "C:\\legacy.exe",
                "payload": "4D 5A 90"
            }),
        );

        assert_eq!(normalized["target_path"], "C:\\canonical.exe");
        assert_eq!(normalized["payload"], json!([0x4D, 0x5A, 0x90]));
    }

    #[test]
    fn normalizes_kernel_and_special_value_aliases() {
        let kernel = normalize_common_args(
            "kernel",
            &json!({
                "action": "driver_notify_routine",
                "callback_type": "process",
                "callback_action": "query"
            }),
        );
        assert_eq!(kernel["notify_type"], "process");
        assert_eq!(kernel["notify_action"], "query");

        let stealth = normalize_common_args(
            "stealth",
            &json!({
                "action": "syscall_protect",
                "protect": "RWX"
            }),
        );
        assert_eq!(stealth["protection"], 0x40);
    }

    #[test]
    fn module_name_helper_rejects_paths_before_handlers_open_targets() {
        let error = require_module_name_param(
            &json!({"module_name": "C:\\Windows\\System32\\ntdll.dll"}),
            "module_name",
            "target",
            "module_base",
            None,
        )
        .expect_err("path-like module names should fail shared validation");

        assert!(error.contains("target(action='module_base')"));
        assert!(error.contains("module_name"));
        assert!(error.contains("path separators"));
    }

    #[test]
    fn normalizes_kernel_legacy_actions_and_aliases() {
        let notify = normalize_kernel_args(&json!({
            "action": "notify_routine",
            "callback_type": "image",
            "callback_action": "query"
        }));
        assert_eq!(notify["action"], "driver_notify_routine");
        assert_eq!(notify["notify_type"], "image");
        assert_eq!(notify["notify_action"], "query");

        let write = normalize_kernel_args(&json!({
            "action": "write",
            "data": "DE AD BE EF"
        }));
        assert_eq!(write["bytes"], json!([0xDE, 0xAD, 0xBE, 0xEF]));

        let apc = normalize_kernel_args(&json!({
            "action": "driver_kernel_apc",
            "thread_id": 1234
        }));
        assert_eq!(apc["tid"], 1234);
    }

    #[test]
    fn kernel_normalization_reuses_registry_alias_descriptors() {
        let normalized = normalize_kernel_args(&json!({
            "action": "driver_global_hook",
            "module": "ntoskrnl.exe",
            "function": "NtOpenProcess",
            "hook_address": "0x1000"
        }));

        assert_eq!(normalized["target_module"], "ntoskrnl.exe");
        assert_eq!(normalized["target_function"], "NtOpenProcess");
        assert_eq!(normalized["replacement_addr"], json!(0x1000u64));

        let aliases =
            crate::mcp::action_registry::parameter_aliases("kernel", "driver_global_hook");
        assert!(aliases
            .iter()
            .any(|alias| alias.canonical == "target_module" && alias.alias == "module"));
        assert!(aliases
            .iter()
            .any(|alias| alias.canonical == "target_function" && alias.alias == "function"));
        assert!(aliases
            .iter()
            .any(|alias| alias.canonical == "replacement_addr" && alias.alias == "hook_address"));
    }

    #[test]
    fn registered_action_errors_use_registry_actions() {
        let args = json!({"action": "ps_list"});
        assert_eq!(
            require_registered_action(&args, "target").unwrap(),
            "ps_list"
        );

        let missing = require_registered_action(&json!({}), "target").unwrap_err();
        assert!(missing.contains("target requires 'action'"));
        assert!(missing.contains("ps_list"));

        let unknown = unknown_registered_action_error("memory", "not_real");
        assert!(unknown.contains("Unknown memory action: not_real"));
        assert!(unknown.contains("scan_new"));

        assert_eq!(
            invalid_choice_error("memory", "read", "mode", "bad", "raw, string"),
            "Invalid mode for memory(action='read'): bad. Allowed: raw, string."
        );
    }

    #[test]
    fn validates_required_parameters_from_action_registry() {
        let error = validate_required_parameters("memory", &json!({"action": "alloc", "pid": 42}))
            .expect_err("alloc should require registry-declared size");
        assert!(error.contains("memory(action='alloc')"));
        assert!(error.contains("requires 'size'"));
        assert!(error.contains("action registry"));

        let empty = validate_required_parameters(
            "inject",
            &json!({"action": "dll", "pid": 42, "dll_path": ""}),
        )
        .expect_err("empty required strings should be rejected");
        assert!(empty.contains("requires 'dll_path'"));

        let shellcode = validate_required_parameters(
            "inject",
            &json!({"action": "shellcode", "pid": 42, "method": "thread"}),
        )
        .expect_err("shellcode(thread) should require registry-declared shellcode bytes");
        assert!(shellcode.contains("inject(action='shellcode')"));
        assert!(shellcode.contains("requires 'shellcode'"));
        assert!(shellcode.contains("Most shellcode injection methods"));

        let spawn_payload = validate_required_parameters(
            "inject",
            &json!({
                "action": "spawn",
                "target_path": "C:\\Windows\\System32\\notepad.exe",
                "spawn_method": "hollow"
            }),
        )
        .expect_err("spawn(hollow) should require registry-declared PE payload bytes");
        assert!(spawn_payload.contains("inject(action='spawn')"));
        assert!(spawn_payload.contains("requires 'payload'"));
        assert!(spawn_payload.contains("Hollow and transacted spawn methods"));

        let spawn_shellcode = validate_required_parameters(
            "inject",
            &json!({
                "action": "spawn",
                "target_exe": "C:\\Windows\\System32\\notepad.exe",
                "spawn_method": "early_bird"
            }),
        )
        .expect_err("spawn(early_bird) should require shellcode bytes after target alias");
        assert!(spawn_shellcode.contains("inject(action='spawn')"));
        assert!(spawn_shellcode.contains("requires 'shellcode'"));
        assert!(spawn_shellcode.contains("Early-bird spawn"));

        validate_required_parameters(
            "inject",
            &json!({
                "action": "spawn",
                "target_exe": "C:\\Windows\\System32\\notepad.exe",
                "spawn_method": "ghost"
            }),
        )
        .expect("legacy target_exe alias should satisfy the registry target_path requirement");

        validate_required_parameters(
            "inject",
            &json!({"action": "shellcode", "pid": 42, "method": "mockingjay"}),
        )
        .expect("mockingjay should remain the registry-described shellcode exception");

        let hook_iat =
            validate_required_parameters("hook", &json!({"action": "install", "pid": 42}))
                .expect_err("hook install defaults to IAT requirements from the registry");
        assert!(hook_iat.contains("hook(action='install')"));
        assert!(hook_iat.contains("requires 'module'"));
        assert!(hook_iat.contains("IAT hook installation"));

        let hook_inline = validate_required_parameters(
            "hook",
            &json!({"action": "hook_function", "pid": 42, "method": "inline"}),
        )
        .expect_err("hook_function(inline) should require address descriptors");
        assert!(hook_inline.contains("hook(action='hook_function')"));
        assert!(hook_inline.contains("requires 'target_address'"));
        assert!(hook_inline.contains("Inline hook_function"));

        let memory_write = validate_required_parameters(
            "memory",
            &json!({"action": "write", "pid": 42, "address": "0x1000"}),
        )
        .expect_err("memory write should require bytes or deprecated text input");
        assert!(memory_write.contains("memory(action='write')"));
        assert!(memory_write.contains("requires 'bytes' or 'text'"));
        assert!(memory_write.contains("either a byte payload or deprecated text"));

        validate_required_parameters(
            "memory",
            &json!({"action": "write", "pid": 42, "address": "0x1000", "text": "ok"}),
        )
        .expect("deprecated memory write text should satisfy the registry alternative group");

        let pe_parse = validate_required_parameters(
            "payload",
            &json!({"action": "pe_parse", "pid": 42, "show": "imports"}),
        )
        .expect_err("pe_parse imports should require a registry-declared base address");
        assert!(pe_parse.contains("payload(action='pe_parse')"));
        assert!(pe_parse.contains("requires 'address'"));
        assert!(pe_parse.contains("base_address is accepted as an alias"));

        validate_required_parameters(
            "payload",
            &json!({
                "action": "pe_parse",
                "pid": 42,
                "show": "imports",
                "base_address": "0x400000"
            }),
        )
        .expect("pe_parse base_address alias should satisfy address requirement");

        let pe_parse_iat = validate_required_parameters(
            "payload",
            &json!({"action": "pe_parse", "pid": 42, "show": "iat_entry"}),
        )
        .expect_err("pe_parse iat_entry should require module metadata");
        assert!(pe_parse_iat.contains("requires 'module'"));
        assert!(pe_parse_iat.contains("module_name is accepted as an alias"));

        validate_required_parameters(
            "payload",
            &json!({
                "action": "pe_parse",
                "pid": 42,
                "show": "iat_entry",
                "module_name": "kernel32.dll"
            }),
        )
        .expect("pe_parse module_name alias should satisfy module requirement");

        validate_required_parameters(
            "target",
            &json!({"action": "module_base", "pid": 42, "module": "kernel32.dll"}),
        )
        .expect("alias normalization should satisfy required canonical parameters");

        let kernel_pte_write = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_pte_rw", "pte_action": "write", "address": "0xFFFF800000100000"}),
        )
        .expect_err("driver_pte_rw(write) should require replacement PTE before dispatch");
        assert!(kernel_pte_write.contains("kernel(action='driver_pte_rw')"));
        assert!(kernel_pte_write.contains("requires 'new_pte'"));
        assert!(kernel_pte_write.contains("PTE write/restore operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_pte_rw", "pte_action": "make_writable", "address": "0xFFFF800000100000"}),
        )
        .expect("driver_pte_rw(make_writable) derives the replacement value from the current PTE");

        let kernel_msr_write = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_msr_rw", "msr_action": "write", "msr_index": 0xC0000082_u64}),
        )
        .expect_err("driver_msr_rw(write) should require replacement value before dispatch");
        assert!(kernel_msr_write.contains("kernel(action='driver_msr_rw')"));
        assert!(kernel_msr_write.contains("requires 'msr_value'"));
        assert!(kernel_msr_write.contains("MSR writes require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_msr_rw", "msr_action": "read"}),
        )
        .expect("driver_msr_rw(read) may use the handler's default MSR index");

        let kernel_object_register = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_object_hook", "obj_action": "register"}),
        )
        .expect_err("driver_object_hook(register) should require a protected PID");
        assert!(kernel_object_register.contains("kernel(action='driver_object_hook')"));
        assert!(kernel_object_register.contains("requires 'protect_pid'"));
        assert!(kernel_object_register.contains("Object hook registration requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_object_hook", "obj_action": "register", "pid": 500}),
        )
        .expect("driver_object_hook(register) should accept pid as protect_pid alias");

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_object_hook", "obj_action": "query"}),
        )
        .expect("driver_object_hook(query) may omit a protected PID");

        let kernel_thread_create = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_system_thread", "thread_action": "create"}),
        )
        .expect_err("driver_system_thread(create) should require a start address before dispatch");
        assert!(kernel_thread_create.contains("kernel(action='driver_system_thread')"));
        assert!(kernel_thread_create.contains("requires 'thread_start'"));
        assert!(kernel_thread_create.contains("System thread creation requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_system_thread", "thread_action": "query"}),
        )
        .expect("driver_system_thread(query) may omit a start routine");

        let kernel_exec_run =
            validate_required_parameters("kernel", &json!({"action": "driver_kernel_exec"}))
                .expect_err("driver_kernel_exec default run mode should require shellcode");
        assert!(kernel_exec_run.contains("kernel(action='driver_kernel_exec')"));
        assert!(kernel_exec_run.contains("requires 'shellcode_bytes'"));
        assert!(kernel_exec_run.contains("Kernel exec run/alloc operations require"));

        let kernel_exec_free = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_kernel_exec", "exec_action": "free"}),
        )
        .expect_err("driver_kernel_exec(free) should require an allocation address");
        assert!(kernel_exec_free.contains("requires 'alloc_address'"));
        assert!(kernel_exec_free.contains("Kernel exec free requires"));

        let kernel_cloak_target = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_cloak", "cloak_action": "target"}),
        )
        .expect_err("driver_cloak(target) should require a target driver name");
        assert!(kernel_cloak_target.contains("kernel(action='driver_cloak')"));
        assert!(kernel_cloak_target.contains("requires 'driver_name'"));
        assert!(kernel_cloak_target.contains("Driver cloak target mode requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_cloak", "cloak_action": "self"}),
        )
        .expect("driver_cloak(self) may use the current driver name");

        let kernel_reg_hide_add = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_reg_hide", "reg_action": "add"}),
        )
        .expect_err("driver_reg_hide(add) should require a key path before dispatch");
        assert!(kernel_reg_hide_add.contains("kernel(action='driver_reg_hide')"));
        assert!(kernel_reg_hide_add.contains("requires 'key_path'"));
        assert!(kernel_reg_hide_add.contains("Registry hide add/remove operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_reg_hide", "reg_action": "list"}),
        )
        .expect("driver_reg_hide(list) may omit a key path");

        let kernel_file_lock_remove = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_file_lock", "lock_action": "remove"}),
        )
        .expect_err("driver_file_lock(remove) should require a file path before dispatch");
        assert!(kernel_file_lock_remove.contains("kernel(action='driver_file_lock')"));
        assert!(kernel_file_lock_remove.contains("requires 'file_path'"));
        assert!(kernel_file_lock_remove.contains("File lock add/remove operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_file_lock", "lock_action": "clear"}),
        )
        .expect("driver_file_lock(clear) may omit a file path");

        let kernel_ppl_strip = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_ppl_bypass", "ppl_action": "strip"}),
        )
        .expect_err("driver_ppl_bypass(strip) should require a target PID before dispatch");
        assert!(kernel_ppl_strip.contains("kernel(action='driver_ppl_bypass')"));
        assert!(kernel_ppl_strip.contains("requires 'pid'"));
        assert!(kernel_ppl_strip.contains("PPL strip/set operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_ppl_bypass", "ppl_action": "query"}),
        )
        .expect("driver_ppl_bypass(query) may omit a target PID");

        let kernel_token_default =
            validate_required_parameters("kernel", &json!({"action": "driver_token_swap"}))
                .expect_err("driver_token_swap default steal mode should require target_pid");
        assert!(kernel_token_default.contains("kernel(action='driver_token_swap')"));
        assert!(kernel_token_default.contains("requires 'target_pid'"));
        assert!(kernel_token_default.contains("Token steal/swap operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_token_swap", "swap_action": "query"}),
        )
        .expect("driver_token_swap(query) may omit target_pid");

        let kernel_process_protect_set = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_process_protect", "protect_action": "set"}),
        )
        .expect_err("driver_process_protect(set) should require a target PID before dispatch");
        assert!(kernel_process_protect_set.contains("kernel(action='driver_process_protect')"));
        assert!(kernel_process_protect_set.contains("requires 'pid'"));
        assert!(
            kernel_process_protect_set.contains("Process protection set/strip operations require")
        );

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_process_protect", "protect_action": "query"}),
        )
        .expect("driver_process_protect(query) may omit a target PID");

        let kernel_cred_read = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_cred_dump", "cred_action": "read", "pid": 500}),
        )
        .expect_err("driver_cred_dump(read) should require a source address before dispatch");
        assert!(kernel_cred_read.contains("kernel(action='driver_cred_dump')"));
        assert!(kernel_cred_read.contains("requires 'address'"));
        assert!(kernel_cred_read.contains("Credential memory reads require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_cred_dump", "cred_action": "dump"}),
        )
        .expect("driver_cred_dump(dump) may derive its target internally");

        let kernel_impersonate_swap = validate_required_parameters(
            "kernel",
            &json!({
                "action": "driver_impersonate",
                "imp_action": "swap",
                "target_path": "\\??\\C:\\Windows\\System32\\drivers\\target.sys"
            }),
        )
        .expect_err("driver_impersonate(swap) should require both driver paths");
        assert!(kernel_impersonate_swap.contains("kernel(action='driver_impersonate')"));
        assert!(kernel_impersonate_swap.contains("requires 'legit_path'"));
        assert!(kernel_impersonate_swap.contains("Driver impersonation swap requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_impersonate", "imp_action": "restore"}),
        )
        .expect("driver_impersonate(restore) may use stored backup state");

        let kernel_callback_remove = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_callback_nuke", "cb_action": "remove"}),
        )
        .expect_err("driver_callback_nuke(remove) should require a callback index");
        assert!(kernel_callback_remove.contains("kernel(action='driver_callback_nuke')"));
        assert!(kernel_callback_remove.contains("requires 'index'"));
        assert!(kernel_callback_remove.contains("Callback single-remove requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_callback_nuke", "cb_action": "enum"}),
        )
        .expect("driver_callback_nuke(enum) may omit a callback index");

        let kernel_minifilter_detach = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_minifilter_detach", "mf_action": "detach", "filter_name": "WdFilter"}),
        )
        .expect_err("driver_minifilter_detach(detach) should require a frame ID");
        assert!(kernel_minifilter_detach.contains("kernel(action='driver_minifilter_detach')"));
        assert!(kernel_minifilter_detach.contains("requires 'frame_id'"));
        assert!(kernel_minifilter_detach.contains("Minifilter detach requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_minifilter_detach", "mf_action": "enum"}),
        )
        .expect("driver_minifilter_detach(enum) may omit a specific filter target");

        let kernel_apc_default =
            validate_required_parameters("kernel", &json!({"action": "driver_kernel_apc", "pid": 500}))
                .expect_err("driver_kernel_apc default inject mode should require target thread and shellcode fields");
        assert!(kernel_apc_default.contains("kernel(action='driver_kernel_apc')"));
        assert!(kernel_apc_default.contains("requires 'tid'"));
        assert!(kernel_apc_default.contains("Kernel APC shellcode injection requires"));

        let kernel_apc_dll = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_kernel_apc", "apc_action": "dll", "pid": 500, "tid": 42}),
        )
        .expect_err("driver_kernel_apc(dll) should require a DLL path");
        assert!(kernel_apc_dll.contains("kernel(action='driver_kernel_apc')"));
        assert!(kernel_apc_dll.contains("requires 'dll_path'"));
        assert!(kernel_apc_dll.contains("Kernel APC DLL injection requires"));

        let kernel_wfp_remove = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_wfp_remove", "wfp_action": "remove"}),
        )
        .expect_err("driver_wfp_remove(remove) should require a callout ID");
        assert!(kernel_wfp_remove.contains("kernel(action='driver_wfp_remove')"));
        assert!(kernel_wfp_remove.contains("requires 'callout_id'"));
        assert!(kernel_wfp_remove.contains("WFP single-remove requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_wfp_remove", "wfp_action": "enum"}),
        )
        .expect("driver_wfp_remove(enum) may omit a callout ID");

        let kernel_port_hide_add = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_port_hide", "port_action": "add"}),
        )
        .expect_err("driver_port_hide(add) should require a target port");
        assert!(kernel_port_hide_add.contains("kernel(action='driver_port_hide')"));
        assert!(kernel_port_hide_add.contains("requires 'port'"));
        assert!(kernel_port_hide_add.contains("Port hide add/remove operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_port_hide", "port_action": "list"}),
        )
        .expect("driver_port_hide(list) may omit a target port");

        let kernel_token_copy = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_token_dup", "token_action": "copy", "pid": 500}),
        )
        .expect_err("driver_token_dup(copy) should require a source PID");
        assert!(kernel_token_copy.contains("kernel(action='driver_token_dup')"));
        assert!(kernel_token_copy.contains("requires 'source_pid'"));
        assert!(kernel_token_copy.contains("Token copy requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_token_dup", "token_action": "system", "pid": 500}),
        )
        .expect("driver_token_dup(system) may use driver-managed token state");

        let kernel_global_hook_install = validate_required_parameters(
            "kernel",
            &json!({
                "action": "driver_global_hook",
                "hook_action": "install",
                "target_module": "ntoskrnl.exe",
                "target_function": "NtQuerySystemInformation"
            }),
        )
        .expect_err("driver_global_hook(install) should require replacement address");
        assert!(kernel_global_hook_install.contains("kernel(action='driver_global_hook')"));
        assert!(kernel_global_hook_install.contains("requires 'replacement_addr'"));
        assert!(kernel_global_hook_install.contains("Global hook installation requires"));

        let kernel_global_hook_remove = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_global_hook", "hook_action": "remove"}),
        )
        .expect_err("driver_global_hook(remove) should require a hook index");
        assert!(kernel_global_hook_remove.contains("kernel(action='driver_global_hook')"));
        assert!(kernel_global_hook_remove.contains("requires 'hook_index'"));
        assert!(kernel_global_hook_remove.contains("Global hook removal requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_global_hook", "hook_action": "query"}),
        )
        .expect("driver_global_hook(query) may omit hook target fields");

        let kernel_infinity_enable_syscall = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_infinity_hook", "infhook_action": "enable"}),
        )
        .expect_err("driver_infinity_hook(enable) should require syscall number first");
        assert!(kernel_infinity_enable_syscall.contains("kernel(action='driver_infinity_hook')"));
        assert!(kernel_infinity_enable_syscall.contains("requires 'syscall_number'"));
        assert!(kernel_infinity_enable_syscall
            .contains("Infinity hook enable/disable operations require"));

        let kernel_infinity_enable_handler = validate_required_parameters(
            "kernel",
            &json!({
                "action": "driver_infinity_hook",
                "infhook_action": "enable",
                "syscall_number": 0x33
            }),
        )
        .expect_err("driver_infinity_hook(enable) should require a handler address");
        assert!(kernel_infinity_enable_handler.contains("kernel(action='driver_infinity_hook')"));
        assert!(kernel_infinity_enable_handler.contains("requires 'handler_address'"));
        assert!(kernel_infinity_enable_handler.contains("Infinity hook enable requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_infinity_hook", "infhook_action": "query"}),
        )
        .expect("driver_infinity_hook(query) may omit syscall target fields");

        let kernel_unloaded_clear_name = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_unloaded_drv_clear", "unloaded_action": "clear_name"}),
        )
        .expect_err("driver_unloaded_drv_clear(clear_name) should require a driver name");
        assert!(kernel_unloaded_clear_name.contains("kernel(action='driver_unloaded_drv_clear')"));
        assert!(kernel_unloaded_clear_name.contains("requires 'driver_name'"));
        assert!(kernel_unloaded_clear_name.contains("Unloaded-driver clear_name requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_unloaded_drv_clear", "unloaded_action": "clear_all"}),
        )
        .expect("driver_unloaded_drv_clear(clear_all) may omit a driver name");

        let kernel_etw_disable = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_etw_blind", "etw_action": "disable"}),
        )
        .expect_err("driver_etw_blind(disable) should require a provider GUID");
        assert!(kernel_etw_disable.contains("kernel(action='driver_etw_blind')"));
        assert!(kernel_etw_disable.contains("requires 'provider_guid'"));
        assert!(kernel_etw_disable.contains("ETW provider disable/enable operations require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_etw_blind", "etw_action": "kill_all"}),
        )
        .expect("driver_etw_blind(kill_all) may omit a provider GUID");

        let kernel_eprocess_image = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_eprocess_spoof", "spoof_action": "image_name", "pid": 500}),
        )
        .expect_err("driver_eprocess_spoof(image_name) should require a new image name");
        assert!(kernel_eprocess_image.contains("kernel(action='driver_eprocess_spoof')"));
        assert!(kernel_eprocess_image.contains("requires 'new_image_name'"));
        assert!(kernel_eprocess_image.contains("EPROCESS image-name spoofing requires"));

        let kernel_eprocess_command = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_eprocess_spoof", "spoof_action": "command_line", "pid": 500}),
        )
        .expect_err("driver_eprocess_spoof(command_line) should require a new command line");
        assert!(kernel_eprocess_command.contains("kernel(action='driver_eprocess_spoof')"));
        assert!(kernel_eprocess_command.contains("requires 'new_command_line'"));
        assert!(kernel_eprocess_command.contains("EPROCESS command-line spoofing requires"));

        let kernel_eprocess_parent = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_eprocess_spoof", "spoof_action": "pid", "pid": 500}),
        )
        .expect_err("driver_eprocess_spoof(pid) should require a new parent PID");
        assert!(kernel_eprocess_parent.contains("kernel(action='driver_eprocess_spoof')"));
        assert!(kernel_eprocess_parent.contains("requires 'new_parent_pid'"));
        assert!(kernel_eprocess_parent.contains("EPROCESS parent-PID spoofing requires"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_eprocess_spoof", "spoof_action": "query"}),
        )
        .expect("driver_eprocess_spoof(query) may omit spoof target fields");

        let kernel_cr_write = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_cr_rw", "cr_action": "write", "cr_index": 4}),
        )
        .expect_err("driver_cr_rw(write) should require replacement value before dispatch");
        assert!(kernel_cr_write.contains("kernel(action='driver_cr_rw')"));
        assert!(kernel_cr_write.contains("requires 'value'"));
        assert!(kernel_cr_write.contains("Control register writes require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_cr_rw", "cr_action": "read"}),
        )
        .expect("driver_cr_rw(read) may use the handler's default CR index");

        let kernel_idt_write = validate_required_parameters(
            "kernel",
            &json!({"action": "driver_idt_rw", "idt_action": "write", "vector": 0x2E}),
        )
        .expect_err("driver_idt_rw(write) should require a replacement handler before dispatch");
        assert!(kernel_idt_write.contains("kernel(action='driver_idt_rw')"));
        assert!(kernel_idt_write.contains("requires 'new_handler'"));
        assert!(kernel_idt_write.contains("IDT writes require"));

        validate_required_parameters(
            "kernel",
            &json!({"action": "driver_idt_rw", "idt_action": "dump"}),
        )
        .expect("driver_idt_rw(dump) may use handler defaults");

        let unknown =
            validate_required_parameters("memory", &json!({"action": "not_real"})).unwrap_err();
        assert!(unknown.contains("Unknown memory action: not_real"));
    }

    #[test]
    fn validates_choice_parameters_from_action_registry() {
        validate_choice_parameters("memory", &json!({"action": "read", "mode": "stealth"}))
            .expect("registered read mode should pass");
        validate_choice_parameters(
            "memory",
            &json!({"action": "typed_read", "value_type": "u32", "endian": "little"}),
        )
        .expect("registered alias-backed primitive type and endian should pass");
        validate_choice_parameters(
            "memory",
            &json!({"action": "scan_new", "value_type": "dword"}),
        )
        .expect("scan_new should accept registered value_type aliases");
        validate_choice_parameters(
            "memory",
            &json!({"action": "read", "region_cache": "force_refresh"}),
        )
        .expect("read should accept registered region cache aliases");
        validate_choice_parameters(
            "memory",
            &json!({"action": "scan", "region_cache": "bypass"}),
        )
        .expect("scan should accept registered region cache aliases");

        let error = validate_choice_parameters("memory", &json!({"action": "read", "mode": "bad"}))
            .expect_err("unknown read mode should fail from registry choices");
        assert!(error.contains("memory(action='read')"));
        assert!(error.contains("mode"));
        assert!(error.contains("raw"));
        assert!(error.contains("physical"));

        let type_error =
            validate_choice_parameters("memory", &json!({"action": "typed_write", "type": "i64"}))
                .expect_err("typed_write should reject unsupported primitive types");
        assert!(type_error.contains("typed_write"));
        assert!(type_error.contains("type"));
        assert!(type_error.contains("f64"));

        let typed_error =
            validate_choice_parameters("memory", &json!({"action": "scan", "scan_mode": 42}))
                .expect_err("choice parameters should be strings");
        assert!(typed_error.contains("scan_mode"));
        assert!(typed_error.contains("expected a string"));

        let cache_error =
            validate_choice_parameters("memory", &json!({"action": "scan", "region_cache": "bad"}))
                .expect_err("unknown region cache mode should fail from registry choices");
        assert!(cache_error.contains("scan"));
        assert!(cache_error.contains("region_cache"));
        assert!(cache_error.contains("force_refresh"));
        assert!(cache_error.contains("bypass"));

        validate_choice_parameters(
            "stealth",
            &json!({"action": "defender_mpcmdrun", "command": "scan"}),
        )
        .expect("registered stealth command choice should pass");
        validate_choice_parameters(
            "stealth",
            &json!({"action": "firewall_add_rule", "direction": "out"}),
        )
        .expect("registered firewall direction should pass");
        validate_choice_parameters(
            "stealth",
            &json!({"action": "wdac_disable", "method": "kernel_rw"}),
        )
        .expect("registered stealth policy method should pass");
        let stealth_error = validate_choice_parameters(
            "stealth",
            &json!({"action": "defender_mpcmdrun", "command": "purge"}),
        )
        .expect_err("unknown stealth command should fail from registry choices");
        assert!(stealth_error.contains("defender_mpcmdrun"));
        assert!(stealth_error.contains("command"));
        assert!(stealth_error.contains("remove_definitions"));
        assert!(stealth_error.contains("cancel_scan"));
        let firewall_direction_error = validate_choice_parameters(
            "stealth",
            &json!({"action": "firewall_add_rule", "direction": "sideways"}),
        )
        .expect_err("unknown firewall direction should fail from registry choices");
        assert!(firewall_direction_error.contains("firewall_add_rule"));
        assert!(firewall_direction_error.contains("direction"));
        assert!(firewall_direction_error.contains("in"));
        assert!(firewall_direction_error.contains("out"));
        let stealth_method_error = validate_choice_parameters(
            "stealth",
            &json!({"action": "wdac_disable", "method": "powershell"}),
        )
        .expect_err("unknown stealth policy method should fail from registry choices");
        assert!(stealth_method_error.contains("wdac_disable"));
        assert!(stealth_method_error.contains("method"));
        assert!(stealth_method_error.contains("driver_ci"));
        assert!(stealth_method_error.contains("kernel_rw"));

        validate_choice_parameters(
            "kernel",
            &json!({
                "action": "driver_notify_routine",
                "callback_type": "image",
                "callback_action": "query"
            }),
        )
        .expect("kernel choice aliases should satisfy registry validation");
        let kernel_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_reg_protect", "registry_action": "drop"}),
        )
        .expect_err("unknown kernel alias-backed choice should fail from registry choices");
        assert!(kernel_error.contains("driver_reg_protect"));
        assert!(kernel_error.contains("reg_action"));
        assert!(kernel_error.contains("add"));
        assert!(kernel_error.contains("clear"));

        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_patch_kernel", "patch_type": "dse"}),
        )
        .expect("kernel patch type choices should validate through the registry");
        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_idt_rw", "idt_action": "dump"}),
        )
        .expect("kernel IDT action choices should validate through the registry");
        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_keylogger", "keylog_action": "read"}),
        )
        .expect("kernel keylogger action choices should validate through the registry");
        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_event_log_clear", "log_action": "kill_service"}),
        )
        .expect("kernel event-log action choices should validate through the registry");
        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_cred_dump", "cred_action": "dump"}),
        )
        .expect("kernel credential action choices should validate through the registry");
        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_impersonate", "imp_action": "restore"}),
        )
        .expect("kernel impersonation action choices should validate through the registry");
        validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_auto_inject", "inject_flags": ["ntquery", "amsi"]}),
        )
        .expect("kernel auto-inject array item choices should validate through the registry");
        let inject_action_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_auto_inject", "inject_action": "set_payload"}),
        )
        .expect_err("unsupported auto-inject action should fail from registry choices");
        assert!(inject_action_error.contains("driver_auto_inject"));
        assert!(inject_action_error.contains("inject_action"));
        assert!(inject_action_error.contains("set_payload"));
        assert!(inject_action_error.contains("enable"));
        assert!(inject_action_error.contains("disable"));
        assert!(inject_action_error.contains("query"));

        let kernel_patch_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_patch_kernel", "patch_type": "ci"}),
        )
        .expect_err("unknown kernel patch selector should fail from registry choices");
        assert!(kernel_patch_error.contains("driver_patch_kernel"));
        assert!(kernel_patch_error.contains("patch_type"));
        assert!(kernel_patch_error.contains("etw_ti"));
        assert!(kernel_patch_error.contains("dse"));

        let kernel_log_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_event_log_clear", "log_action": "delete"}),
        )
        .expect_err("unknown kernel event-log selector should fail from registry choices");
        assert!(kernel_log_error.contains("driver_event_log_clear"));
        assert!(kernel_log_error.contains("log_action"));
        assert!(kernel_log_error.contains("clear_sysmon"));
        assert!(kernel_log_error.contains("kill_service"));

        let inject_flags_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_auto_inject", "inject_flags": ["bad"]}),
        )
        .expect_err("unknown auto-inject flag should fail from registry choices");
        assert!(inject_flags_error.contains("driver_auto_inject"));
        assert!(inject_flags_error.contains("inject_flags"));
        assert!(inject_flags_error.contains("ntquery"));
        assert!(inject_flags_error.contains("custom"));

        let inject_flags_item_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_auto_inject", "inject_flags": [42]}),
        )
        .expect_err("auto-inject flags should be strings");
        assert!(inject_flags_item_error.contains("inject_flags"));
        assert!(inject_flags_item_error.contains("array items"));

        let inject_flags_shape_error = validate_choice_parameters(
            "kernel",
            &json!({"action": "driver_auto_inject", "inject_flags": "ntquery"}),
        )
        .expect_err("auto-inject flags should be an array");
        assert!(inject_flags_shape_error.contains("inject_flags"));
        assert!(inject_flags_shape_error.contains("expected an array"));

        validate_choice_parameters(
            "self",
            &json!({"action": "state", "sub_action": "replay_dry_run"}),
        )
        .expect("self state should accept registry-described sub_action aliases");
        let self_error =
            validate_choice_parameters("self", &json!({"action": "state", "sub_action": "drop"}))
                .expect_err("unknown self state sub_action should fail from registry choices");
        assert!(self_error.contains("state"));
        assert!(self_error.contains("sub_action"));
        assert!(self_error.contains("artifact_cleanup"));

        validate_choice_parameters(
            "privilege",
            &json!({"action": "symlink", "type": "junction"}),
        )
        .expect("registered privilege symlink type should pass");
        let symlink_type_error = validate_choice_parameters(
            "privilege",
            &json!({"action": "symlink", "type": "shortcut"}),
        )
        .expect_err("unknown privilege symlink type should fail from registry choices");
        assert!(symlink_type_error.contains("symlink"));
        assert!(symlink_type_error.contains("type"));
        assert!(symlink_type_error.contains("hardlink"));
        assert!(symlink_type_error.contains("junction"));

        validate_choice_parameters(
            "orchestrate",
            &json!({"action": "plan", "template": "driver_readiness"}),
        )
        .expect("registered orchestration template should pass");
        let template_error = validate_choice_parameters(
            "orchestrate",
            &json!({"action": "plan", "template": "not_real"}),
        )
        .expect_err("unknown orchestration template should fail from registry choices");
        assert!(template_error.contains("plan"));
        assert!(template_error.contains("template"));
        assert!(template_error.contains("lab_validation"));
        assert!(template_error.contains("privilege_review"));

        validate_choice_parameters("payload", &json!({"action": "pe_parse", "show": "imports"}))
            .expect("registered payload PE parse view should pass");
        validate_choice_parameters(
            "payload",
            &json!({"action": "obfuscate", "obf_method": "aes_ctr"}),
        )
        .expect("registered payload obfuscation method should pass");
        validate_choice_parameters(
            "payload",
            &json!({"action": "serialize", "format": "struct"}),
        )
        .expect("registered payload serialization format should pass");
        let payload_error =
            validate_choice_parameters("payload", &json!({"action": "pe_parse", "show": "tls"}))
                .expect_err("unknown payload show selector should fail from registry choices");
        assert!(payload_error.contains("pe_parse"));
        assert!(payload_error.contains("show"));
        assert!(payload_error.contains("iat_entry"));

        let obfuscation_error = validate_choice_parameters(
            "payload",
            &json!({"action": "obfuscate", "obf_method": "base64"}),
        )
        .expect_err("unknown payload obfuscation selector should fail from registry choices");
        assert!(obfuscation_error.contains("obfuscate"));
        assert!(obfuscation_error.contains("obf_method"));
        assert!(obfuscation_error.contains("aes_ctr"));

        validate_choice_parameters("hook", &json!({"action": "install", "method": "inline"}))
            .expect("registered hook install method should pass");
        let hook_method_error =
            validate_choice_parameters("hook", &json!({"action": "install", "method": "hwbp"}))
                .expect_err("hardware breakpoint should use install_hwbp, not install(method)");
        assert!(hook_method_error.contains("install"));
        assert!(hook_method_error.contains("method"));
        assert!(hook_method_error.contains("iat"));
        assert!(hook_method_error.contains("inline"));

        validate_choice_parameters(
            "inject",
            &json!({"action": "shellcode", "method": "threadless"}),
        )
        .expect("registered shellcode injection method should pass");
        validate_choice_parameters(
            "inject",
            &json!({"action": "dll", "dll_method": "manual_map"}),
        )
        .expect("registered DLL injection method should pass");
        validate_choice_parameters(
            "inject",
            &json!({"action": "spawn", "spawn_method": "early_bird"}),
        )
        .expect("registered spawn injection method should pass");

        let shellcode_method_error = validate_choice_parameters(
            "inject",
            &json!({"action": "shellcode", "method": "unknown"}),
        )
        .expect_err("unknown shellcode injection method should fail from registry choices");
        assert!(shellcode_method_error.contains("shellcode"));
        assert!(shellcode_method_error.contains("method"));
        assert!(shellcode_method_error.contains("threadless"));
        assert!(shellcode_method_error.contains("pool_party"));

        let dll_method_error = validate_choice_parameters(
            "inject",
            &json!({"action": "dll", "dll_method": "unknown"}),
        )
        .expect_err("unknown DLL injection method should fail from registry choices");
        assert!(dll_method_error.contains("dll"));
        assert!(dll_method_error.contains("dll_method"));
        assert!(dll_method_error.contains("manual_map"));
        assert!(dll_method_error.contains("reflective"));

        let spawn_method_error = validate_choice_parameters(
            "inject",
            &json!({"action": "spawn", "spawn_method": "unknown"}),
        )
        .expect_err("unknown spawn injection method should fail from registry choices");
        assert!(spawn_method_error.contains("spawn"));
        assert!(spawn_method_error.contains("spawn_method"));
        assert!(spawn_method_error.contains("early_bird"));
        assert!(spawn_method_error.contains("transacted"));
    }

    #[test]
    fn validates_parameter_bounds_from_action_registry() {
        validate_parameter_bounds(
            "stealth",
            &json!({"action": "mutate_code", "size": 4096, "intensity": 3}),
        )
        .expect("registered stealth parameter bounds should pass");
        validate_parameter_bounds(
            "stealth",
            &json!({"action": "sentinel_start", "interval_ms": 1000}),
        )
        .expect("registered sentinel lower bound should pass");
        validate_parameter_bounds(
            "memory",
            &json!({"action": "diagnostics", "region_limit": 0, "entropy_sample_bytes": 65536}),
        )
        .expect("diagnostics maximum-only bounds should allow zero and the upper edge");
        validate_parameter_bounds(
            "memory",
            &json!({"action": "read", "region_cache_ttl_ms": "300000"}),
        )
        .expect("registry bounds should use shared numeric string parsing");
        validate_parameter_bounds(
            "memory",
            &json!({"action": "scan", "limit": "10000", "timeout_secs": "3600"}),
        )
        .expect("memory scan bounds should accept shared numeric strings");
        validate_parameter_bounds("memory", &json!({"action": "write", "bytes": [0, 1, 2]}))
            .expect("memory write byte payload bounds should accept small buffers");
        validate_parameter_bounds(
            "memory",
            &json!({"action": "alloc", "size": 64 * 1024 * 1024}),
        )
        .expect("memory allocation bounds should accept the operation maximum");
        validate_parameter_bounds("orchestrate", &json!({"action": "plan", "limit": "100"}))
            .expect("orchestrate page limits should accept shared numeric strings");
        validate_parameter_bounds(
            "target",
            &json!({"action": "windows", "limit": "10000", "offset": 10000, "wait_ms": 60000}),
        )
        .expect("target pagination and wait bounds should accept registry maximums");
        validate_parameter_bounds(
            "target",
            &json!({"action": "string_read", "max_len": 1024 * 1024}),
        )
        .expect("target string_read max_len should accept the registry maximum");
        validate_parameter_bounds("inject", &json!({"action": "shellcode", "variant": 8}))
            .expect("pool_party variant bounds should accept variant 8");
        validate_parameter_bounds("inject", &json!({"action": "fiber", "shellcode": "90 C3"}))
            .expect("inject fiber shellcode bounds should accept hex byte strings");
        validate_parameter_bounds(
            "inject",
            &json!({"action": "export_forward", "shellcode": [0x90], "module": "x.dll", "export_name": "Run"}),
        )
        .expect("inject export_forward shellcode bounds should accept byte arrays");
        validate_parameter_bounds("inject", &json!({"action": "spawn", "payload": "4D 5A 90"}))
            .expect("inject spawn PE payload bounds should accept hex byte strings");
        validate_parameter_bounds("inject", &json!({"action": "spawn", "shellcode": "90 C3"}))
            .expect("inject spawn early_bird shellcode bounds should accept hex byte strings");
        validate_parameter_bounds(
            "hook",
            &json!({"action": "restore", "original_bytes": "90 C3"}),
        )
        .expect("hook restore original_bytes should accept hex strings through byte bounds");
        validate_parameter_bounds(
            "hook",
            &json!({"action": "detour", "hooks": [{"target_address": "0x1000", "hook_address": "0x2000"}]}),
        )
        .expect("hook detour should accept bounded hook arrays");
        validate_parameter_bounds(
            "payload",
            &json!({"action": "obfuscate", "payload_hex": "90C3", "key": [1, 2, 3]}),
        )
        .expect("payload obfuscate should accept hex payload and bounded key");
        validate_parameter_bounds(
            "payload",
            &json!({"action": "cleanup", "addresses": [], "thread_handles": [1, 2]}),
        )
        .expect("payload cleanup should accept bounded cleanup item arrays");
        validate_parameter_bounds(
            "payload",
            &json!({"action": "serialize", "params": [1, "x"]}),
        )
        .expect("payload serialize should accept bounded params arrays");
        validate_parameter_bounds(
            "stealth",
            &json!({"action": "module_stomp", "dll_path": "xpsservices.dll", "shellcode": "90 C3"}),
        )
        .expect("stealth module_stomp should accept hex shellcode bounds from registry");
        validate_parameter_bounds(
            "stealth",
            &json!({"action": "sleep_gargoyle", "shellcode": [0x90, 0xC3]}),
        )
        .expect("stealth sleep_gargoyle should accept byte-array shellcode bounds from registry");
        validate_parameter_bounds(
            "stealth",
            &json!({"action": "syscall_write", "pid": 42, "address": "0x1000", "bytes": "90 C3"}),
        )
        .expect("stealth syscall_write should accept bounded byte payloads from registry");
        validate_parameter_bounds(
            "stealth",
            &json!({"action": "syscall_alloc", "pid": 42, "size": 64 * 1024 * 1024}),
        )
        .expect("stealth syscall_alloc should accept the shared operation maximum");
        validate_parameter_bounds(
            "self",
            &json!({"action": "protect_encrypt", "address": "0x1000", "size": 64 * 1024 * 1024}),
        )
        .expect("self protect_encrypt should accept the shared operation maximum");
        validate_parameter_bounds(
            "self",
            &json!({"action": "protect_wipe", "address": "0x1000", "size": 4096}),
        )
        .expect("self protect_wipe should accept bounded local memory sizes");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_enum_process", "max_entries": 1024}),
        )
        .expect("kernel enum_process should accept the driver enumeration maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_callback_enum", "max_entries": 64}),
        )
        .expect("kernel callback_enum should accept the callback response maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_memory_pool", "max_entries": 256}),
        )
        .expect("kernel memory_pool should accept the wrapper output entry maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_notify_routine", "notify_action": "query", "max_events": 256}),
        )
        .expect("kernel notify query should accept the ring buffer event maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_process_dump", "max_size": 16 * 1024 * 1024}),
        )
        .expect("kernel process_dump should accept the driver documented dump maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_process_dump", "max_dump_size": "16777216"}),
        )
        .expect("kernel process_dump max_dump_size alias should accept numeric strings");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_keylogger", "max_keys": 512}),
        )
        .expect("kernel keylogger should accept the response key buffer maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_cred_dump", "cred_action": "read", "size": crate::args::DEFAULT_MAX_BYTES}),
        )
        .expect("kernel credential read should accept the driver IO maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_apc_inject", "shellcode_size": crate::args::DEFAULT_MAX_BYTES}),
        )
        .expect("kernel driver_apc_inject should accept the shared byte maximum");
        validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_kernel_apc", "shellcode_size": crate::args::DEFAULT_MAX_BYTES}),
        )
        .expect("kernel APC shellcode size should accept the shared byte maximum");

        let low =
            validate_parameter_bounds("stealth", &json!({"action": "mutate_code", "size": 0}))
                .expect_err("mutate_code zero size should fail from registry bounds");
        assert!(low.contains("mutate_code"));
        assert!(low.contains("size"));
        assert!(low.contains(">= 1"));

        let high = validate_parameter_bounds(
            "stealth",
            &json!({"action": "sentinel_start", "interval_ms": 300001}),
        )
        .expect_err("sentinel interval should reject values above registry bounds");
        assert!(high.contains("sentinel_start"));
        assert!(high.contains("interval_ms"));
        assert!(high.contains("<= 300000"));

        validate_parameter_bounds(
            "stealth",
            &json!({"action": "sentinel_self_destruct", "passes": 7}),
        )
        .expect("sentinel self-destruct should accept bounded wipe passes");
        let low_passes = validate_parameter_bounds(
            "stealth",
            &json!({"action": "sentinel_self_destruct", "passes": 0}),
        )
        .expect_err("sentinel self-destruct should reject zero wipe passes from registry bounds");
        assert!(low_passes.contains("sentinel_self_destruct"));
        assert!(low_passes.contains("passes"));
        assert!(low_passes.contains(">= 1"));
        let high_passes = validate_parameter_bounds(
            "stealth",
            &json!({"action": "sentinel_self_destruct", "passes": 8}),
        )
        .expect_err("sentinel self-destruct should reject wipe passes above registry bounds");
        assert!(high_passes.contains("sentinel_self_destruct"));
        assert!(high_passes.contains("passes"));
        assert!(high_passes.contains("<= 7"));

        let stealth_shellcode_empty = validate_parameter_bounds(
            "stealth",
            &json!({"action": "module_stomp", "dll_path": "xpsservices.dll", "shellcode": []}),
        )
        .expect_err("stealth module_stomp should reject empty shellcode before dispatch");
        assert!(stealth_shellcode_empty.contains("stealth(action='module_stomp')"));
        assert!(stealth_shellcode_empty.contains("shellcode"));
        assert!(stealth_shellcode_empty.contains("byte payload must not be empty"));

        let stealth_syscall_bytes_empty = validate_parameter_bounds(
            "stealth",
            &json!({"action": "syscall_write", "pid": 42, "address": "0x1000", "bytes": []}),
        )
        .expect_err("stealth syscall_write should reject empty write payloads before dispatch");
        assert!(stealth_syscall_bytes_empty.contains("stealth(action='syscall_write')"));
        assert!(stealth_syscall_bytes_empty.contains("bytes"));
        assert!(stealth_syscall_bytes_empty.contains("byte payload must not be empty"));

        let typed = validate_parameter_bounds(
            "stealth",
            &json!({"action": "mutate_code", "intensity": "high"}),
        )
        .expect_err("bounded parameters should be unsigned integers");
        assert!(typed.contains("intensity"));
        assert!(typed.contains("unsigned integer"));

        let diagnostics_high = validate_parameter_bounds(
            "self",
            &json!({"action": "memory_diagnostics", "entropy_region_limit": 129}),
        )
        .expect_err("diagnostics entropy region limit should reject values above registry bounds");
        assert!(diagnostics_high.contains("memory_diagnostics"));
        assert!(diagnostics_high.contains("entropy_region_limit"));
        assert!(diagnostics_high.contains("<= 128"));

        let self_state_limit_high =
            validate_parameter_bounds("self", &json!({"action": "state", "limit": 501}))
                .expect_err(
                    "self state history/timeline page limit should reject oversized values",
                );
        assert!(self_state_limit_high.contains("state"));
        assert!(self_state_limit_high.contains("limit"));
        assert!(self_state_limit_high.contains("<= 500"));

        let self_diagnostics_limit_high = validate_parameter_bounds(
            "self",
            &json!({"action": "diagnostics", "recent_task_limit": 101}),
        )
        .expect_err("self diagnostics recent task limit should reject oversized values");
        assert!(self_diagnostics_limit_high.contains("diagnostics"));
        assert!(self_diagnostics_limit_high.contains("recent_task_limit"));
        assert!(self_diagnostics_limit_high.contains("<= 100"));

        let self_protect_size_zero = validate_parameter_bounds(
            "self",
            &json!({"action": "protect_encrypt", "address": "0x1000", "size": 0}),
        )
        .expect_err("self protect_encrypt should reject zero-sized memory operations");
        assert!(self_protect_size_zero.contains("protect_encrypt"));
        assert!(self_protect_size_zero.contains("size"));
        assert!(self_protect_size_zero.contains(">= 1"));

        let self_protect_size_high = validate_parameter_bounds(
            "self",
            &json!({"action": "protect_wipe", "address": "0x1000", "size": 64 * 1024 * 1024 + 1}),
        )
        .expect_err("self protect_wipe should reject oversized memory operations");
        assert!(self_protect_size_high.contains("protect_wipe"));
        assert!(self_protect_size_high.contains("size"));
        assert!(self_protect_size_high.contains("<= 67108864"));

        let ttl_high = validate_parameter_bounds(
            "memory",
            &json!({"action": "scan_new", "region_cache_ttl_secs": 301}),
        )
        .expect_err("region cache ttl seconds should reject values above registry bounds");
        assert!(ttl_high.contains("scan_new"));
        assert!(ttl_high.contains("region_cache_ttl_secs"));
        assert!(ttl_high.contains("<= 300"));

        let read_high = validate_parameter_bounds(
            "memory",
            &json!({"action": "read", "size": 64 * 1024 * 1024 + 1}),
        )
        .expect_err("memory read size should reject values above the registry maximum");
        assert!(read_high.contains("memory(action='read')"));
        assert!(read_high.contains("size"));
        assert!(read_high.contains("<= 67108864"));

        let write_empty =
            validate_parameter_bounds("memory", &json!({"action": "write", "bytes": []}))
                .expect_err("memory write should reject empty byte arrays through registry bounds");
        assert!(write_empty.contains("memory(action='write')"));
        assert!(write_empty.contains("bytes"));
        assert!(write_empty.contains("byte payload must not be empty"));

        let scan_limit_high =
            validate_parameter_bounds("memory", &json!({"action": "scan", "limit": 10001}))
                .expect_err("memory scan limit should reject values above registry bounds");
        assert!(scan_limit_high.contains("memory(action='scan')"));
        assert!(scan_limit_high.contains("limit"));
        assert!(scan_limit_high.contains("<= 10000"));

        let scan_alignment_high =
            validate_parameter_bounds("memory", &json!({"action": "scan", "alignment": 4097}))
                .expect_err("memory scan alignment should reject oversized alignment");
        assert!(scan_alignment_high.contains("memory(action='scan')"));
        assert!(scan_alignment_high.contains("alignment"));
        assert!(scan_alignment_high.contains("<= 4096"));

        let orchestrate_limit_high =
            validate_parameter_bounds("orchestrate", &json!({"action": "execute", "limit": 101}))
                .expect_err("orchestrate page limit should reject values above registry bounds");
        assert!(orchestrate_limit_high.contains("execute"));
        assert!(orchestrate_limit_high.contains("limit"));
        assert!(orchestrate_limit_high.contains("<= 100"));

        let target_wait_high =
            validate_parameter_bounds("target", &json!({"action": "windows", "wait_ms": 60001}))
                .expect_err("target windows wait should reject values above registry bounds");
        assert!(target_wait_high.contains("target(action='windows')"));
        assert!(target_wait_high.contains("wait_ms"));
        assert!(target_wait_high.contains("<= 60000"));

        let target_string_high = validate_parameter_bounds(
            "target",
            &json!({"action": "string_read", "max_len": 1024 * 1024 + 1}),
        )
        .expect_err("target string_read should reject oversized reads before opening handles");
        assert!(target_string_high.contains("target(action='string_read')"));
        assert!(target_string_high.contains("max_len"));
        assert!(target_string_high.contains("<= 1048576"));

        let kernel_enum_process_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_enum_process", "max_entries": 1025}),
        )
        .expect_err("kernel enum_process should reject requests above the driver default cap");
        assert!(kernel_enum_process_high.contains("kernel(action='driver_enum_process')"));
        assert!(kernel_enum_process_high.contains("max_entries"));
        assert!(kernel_enum_process_high.contains("<= 1024"));

        let kernel_callback_enum_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_callback_enum", "max_entries": 65}),
        )
        .expect_err("kernel callback_enum should reject requests above the response cap");
        assert!(kernel_callback_enum_high.contains("kernel(action='driver_callback_enum')"));
        assert!(kernel_callback_enum_high.contains("max_entries"));
        assert!(kernel_callback_enum_high.contains("<= 64"));

        let kernel_pool_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_memory_pool", "max_entries": 257}),
        )
        .expect_err("kernel memory_pool should reject requests above the wrapper output capacity");
        assert!(kernel_pool_high.contains("kernel(action='driver_memory_pool')"));
        assert!(kernel_pool_high.contains("max_entries"));
        assert!(kernel_pool_high.contains("<= 256"));

        let kernel_notify_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_notify_routine", "notify_action": "query", "max_events": 257}),
        )
        .expect_err("kernel notify query should reject requests above the ring buffer cap");
        assert!(kernel_notify_high.contains("kernel(action='driver_notify_routine')"));
        assert!(kernel_notify_high.contains("max_events"));
        assert!(kernel_notify_high.contains("<= 256"));

        let kernel_process_dump_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_process_dump", "max_size": 16 * 1024 * 1024 + 1}),
        )
        .expect_err("kernel process_dump should reject oversized max_size before dispatch");
        assert!(kernel_process_dump_high.contains("kernel(action='driver_process_dump')"));
        assert!(kernel_process_dump_high.contains("max_size"));
        assert!(kernel_process_dump_high.contains("<= 16777216"));

        let kernel_keylog_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_keylogger", "max_keys": 513}),
        )
        .expect_err("kernel keylogger should reject reads above the response buffer capacity");
        assert!(kernel_keylog_high.contains("kernel(action='driver_keylogger')"));
        assert!(kernel_keylog_high.contains("max_keys"));
        assert!(kernel_keylog_high.contains("<= 512"));

        let kernel_cred_high = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_cred_dump", "cred_action": "read", "size": crate::args::DEFAULT_MAX_BYTES as u64 + 1}),
        )
        .expect_err("kernel credential reads should reject IO sizes above the driver maximum");
        assert!(kernel_cred_high.contains("kernel(action='driver_cred_dump')"));
        assert!(kernel_cred_high.contains("size"));
        assert!(kernel_cred_high.contains("<= 4194304"));

        let driver_apc_size_zero = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_apc_inject", "shellcode_size": 0}),
        )
        .expect_err("kernel driver_apc_inject should reject empty shellcode size");
        assert!(driver_apc_size_zero.contains("kernel(action='driver_apc_inject')"));
        assert!(driver_apc_size_zero.contains("shellcode_size"));
        assert!(driver_apc_size_zero.contains(">= 1"));

        let kernel_apc_size_zero = validate_parameter_bounds(
            "kernel",
            &json!({"action": "driver_kernel_apc", "shellcode_size": 0}),
        )
        .expect_err("kernel APC shellcode injection should reject empty shellcode size");
        assert!(kernel_apc_size_zero.contains("kernel(action='driver_kernel_apc')"));
        assert!(kernel_apc_size_zero.contains("shellcode_size"));
        assert!(kernel_apc_size_zero.contains(">= 1"));

        let inject_variant_high =
            validate_parameter_bounds("inject", &json!({"action": "shellcode", "variant": 9}))
                .expect_err("pool_party variant should reject unsupported variants");
        assert!(inject_variant_high.contains("inject(action='shellcode')"));
        assert!(inject_variant_high.contains("variant"));
        assert!(inject_variant_high.contains("<= 8"));

        let inject_shellcode_empty =
            validate_parameter_bounds("inject", &json!({"action": "fiber", "shellcode": []}))
                .expect_err("inject fiber should reject empty shellcode before dispatch");
        assert!(inject_shellcode_empty.contains("inject(action='fiber')"));
        assert!(inject_shellcode_empty.contains("shellcode"));
        assert!(inject_shellcode_empty.contains("byte payload must not be empty"));

        let inject_spawn_payload_empty =
            validate_parameter_bounds("inject", &json!({"action": "spawn", "payload": []}))
                .expect_err("inject spawn should reject empty PE payloads before dispatch");
        assert!(inject_spawn_payload_empty.contains("inject(action='spawn')"));
        assert!(inject_spawn_payload_empty.contains("payload"));
        assert!(inject_spawn_payload_empty.contains("byte payload must not be empty"));

        let restore_empty =
            validate_parameter_bounds("hook", &json!({"action": "restore", "original_bytes": []}))
                .expect_err("hook restore should reject empty rollback bytes");
        assert!(restore_empty.contains("hook(action='restore')"));
        assert!(restore_empty.contains("original_bytes"));
        assert!(restore_empty.contains("byte payload must not be empty"));

        let too_many_hooks = vec![json!({}); 129];
        let detour_too_many = validate_parameter_bounds(
            "hook",
            &json!({"action": "detour", "hooks": too_many_hooks}),
        )
        .expect_err("hook detour should reject oversized hook batches before dispatch");
        assert!(detour_too_many.contains("hook(action='detour')"));
        assert!(detour_too_many.contains("hooks"));
        assert!(detour_too_many.contains("<= 128"));

        let cleanup_wrong_type =
            validate_parameter_bounds("payload", &json!({"action": "cleanup", "addresses": 1}))
                .expect_err("payload cleanup should require arrays for array-length bounds");
        assert!(cleanup_wrong_type.contains("payload(action='cleanup')"));
        assert!(cleanup_wrong_type.contains("addresses"));
        assert!(cleanup_wrong_type.contains("expected an array"));

        let too_large_key = vec![1; 1025];
        let key_too_large = validate_parameter_bounds(
            "payload",
            &json!({"action": "obfuscate", "payload": [0x90], "key": too_large_key}),
        )
        .expect_err("payload obfuscate should reject oversized keys before dispatch");
        assert!(key_too_large.contains("payload(action='obfuscate')"));
        assert!(key_too_large.contains("key"));
        assert!(key_too_large.contains("<= 1024"));

        let params_empty =
            validate_parameter_bounds("payload", &json!({"action": "serialize", "params": []}))
                .expect_err("payload serialize should reject empty params through registry bounds");
        assert!(params_empty.contains("payload(action='serialize')"));
        assert!(params_empty.contains("params"));
        assert!(params_empty.contains(">= 1"));
    }

    #[test]
    fn parameter_bounds_use_generated_parser_hints_for_value_shape() {
        let payload = crate::mcp::action_registry::registered_action("payload", "obfuscate")
            .expect("payload obfuscate registry action");
        let payload_hint = payload
            .parser_hints
            .iter()
            .find(|hint| hint.parameter == "payload")
            .expect("payload parser hint");
        assert_eq!(payload_hint.parser, "bytes");

        let payload_empty = validate_parameter_bounds(
            "payload",
            &json!({"action": "obfuscate", "payload": [], "key": [1]}),
        )
        .expect_err("byte parser hint should drive payload byte-length bounds");
        assert!(payload_empty.contains("payload(action='obfuscate')"));
        assert!(payload_empty.contains("payload"));
        assert!(payload_empty.contains("action registry parser hint"));
        assert!(payload_empty.contains("byte payload must not be empty"));

        let cleanup = crate::mcp::action_registry::registered_action("payload", "cleanup")
            .expect("payload cleanup registry action");
        let handles_hint = cleanup
            .parser_hints
            .iter()
            .find(|hint| hint.parameter == "thread_handles")
            .expect("thread_handles parser hint");
        assert_eq!(handles_hint.parser, "array_length");
        assert_eq!(handles_hint.array_item_parser, Some("u64"));

        let cleanup_wrong_type = validate_parameter_bounds(
            "payload",
            &json!({"action": "cleanup", "thread_handles": 1}),
        )
        .expect_err("array_length parser hint should drive cleanup item bounds");
        assert!(cleanup_wrong_type.contains("payload(action='cleanup')"));
        assert!(cleanup_wrong_type.contains("thread_handles"));
        assert!(cleanup_wrong_type.contains("action registry parser hint"));
        assert!(cleanup_wrong_type.contains("expected an array value"));

        let addresses_hint = cleanup
            .parser_hints
            .iter()
            .find(|hint| hint.parameter == "addresses")
            .expect("addresses parser hint");
        assert_eq!(addresses_hint.parser, "array_length");
        assert_eq!(addresses_hint.array_item_parser, Some("address_u64"));

        let cleanup_bad_address = validate_parser_hints(
            "payload",
            &json!({"action": "cleanup", "addresses": ["not-an-address"]}),
        )
        .expect_err("array item parser should validate cleanup address items");
        assert!(cleanup_bad_address.contains("payload(action='cleanup')"));
        assert!(cleanup_bad_address.contains("addresses[0]"));
        assert!(cleanup_bad_address.contains("address_u64"));

        let cleanup_bad_handle = validate_parser_hints(
            "payload",
            &json!({"action": "cleanup", "thread_handles": ["not-a-number"]}),
        )
        .expect_err("array item parser should validate cleanup handle items");
        assert!(cleanup_bad_handle.contains("payload(action='cleanup')"));
        assert!(cleanup_bad_handle.contains("thread_handles[0]"));
        assert!(cleanup_bad_handle.contains("u64"));

        let hook = crate::mcp::action_registry::registered_action("hook", "detour")
            .expect("hook detour registry action");
        let hooks_hint = hook
            .parser_hints
            .iter()
            .find(|hint| hint.parameter == "hooks")
            .expect("hooks parser hint");
        assert_eq!(hooks_hint.parser, "object_array");

        let hook_wrong_item = validate_parameter_bounds(
            "hook",
            &json!({"action": "detour", "pid": 42, "hooks": [42]}),
        )
        .expect_err("object_array parser hint should require object items for hook batches");
        assert!(hook_wrong_item.contains("hook(action='detour')"));
        assert!(hook_wrong_item.contains("hooks"));
        assert!(hook_wrong_item.contains("array of objects"));

        let hook_missing_item_field = validate_parser_hints(
            "hook",
            &json!({"action": "detour", "pid": 42, "hooks": [{"target_address": "0x1000"}]}),
        )
        .expect_err("object item schema should require hook_address");
        assert!(hook_missing_item_field.contains("hook(action='detour')"));
        assert!(hook_missing_item_field.contains("hooks"));
        assert!(hook_missing_item_field.contains("hook_address"));

        let hook_bad_item_field = validate_parser_hints(
            "hook",
            &json!({"action": "detour", "pid": 42, "hooks": [{
                "target_address": "not-an-address",
                "hook_address": "0x2000"
            }]}),
        )
        .expect_err("object item schema should validate hook target addresses");
        assert!(hook_bad_item_field.contains("hooks[0].target_address"));
        assert!(hook_bad_item_field.contains("address_u64"));

        let hook_dr_index = validate_parameter_bounds(
            "hook",
            &json!({"action": "install_hwbp", "tid": 42, "target_address": "0x1000", "dr_index": 4}),
        )
        .expect_err(
            "hook hardware-breakpoint dr_index should reject values above DR3 before dispatch",
        );
        assert!(hook_dr_index.contains("hook(action='install_hwbp')"));
        assert!(hook_dr_index.contains("dr_index"));
        assert!(hook_dr_index.contains("<= 3"));

        let orchestrate = crate::mcp::action_registry::registered_action("orchestrate", "plan")
            .expect("orchestrate plan registry action");
        let steps_hint = orchestrate
            .parser_hints
            .iter()
            .find(|hint| hint.parameter == "steps")
            .expect("steps parser hint");
        assert_eq!(steps_hint.parser, "object_array");

        let steps_wrong_item =
            validate_parameter_bounds("orchestrate", &json!({"action": "plan", "steps": ["bad"]}))
                .expect_err("object_array parser hint should require object plan steps");
        assert!(steps_wrong_item.contains("orchestrate(action='plan')"));
        assert!(steps_wrong_item.contains("steps"));
        assert!(steps_wrong_item.contains("array of objects"));

        let step_missing_action = validate_parser_hints(
            "orchestrate",
            &json!({"action": "plan", "steps": [{"tool": "self"}]}),
        )
        .expect_err("object item schema should require step action");
        assert!(step_missing_action.contains("orchestrate(action='plan')"));
        assert!(step_missing_action.contains("steps"));
        assert!(step_missing_action.contains("action"));

        let step_bad_dependencies = validate_parser_hints(
            "orchestrate",
            &json!({"action": "plan", "steps": [{
                "tool": "self",
                "action": "status",
                "depends_on": [1]
            }]}),
        )
        .expect_err("object item schema should validate dependency arrays");
        assert!(step_bad_dependencies.contains("steps[0].depends_on"));
        assert!(step_bad_dependencies.contains("string_array"));
    }

    #[test]
    fn unknown_registry_parser_hints_fail_closed() {
        let parser_error = validate_parser_hint_value(
            "memory",
            "read",
            "address",
            "not_a_parser",
            &json!("anything"),
            None,
            None,
        )
        .expect_err("unknown parser hints should not be silently accepted");
        assert!(parser_error.contains("memory(action='read')"));
        assert!(parser_error.contains("address"));
        assert!(parser_error.contains("unsupported action registry parser hint"));
        assert!(parser_error.contains("not_a_parser"));

        let array_item_error = validate_array_item_parser_hint(
            "payload",
            "cleanup",
            "thread_handles",
            0,
            "not_an_item_parser",
            &json!(1234),
        )
        .expect_err("unknown array item parsers should not be silently accepted");
        assert!(array_item_error.contains("payload(action='cleanup')"));
        assert!(array_item_error.contains("thread_handles[0]"));
        assert!(array_item_error.contains("unsupported action registry array item parser"));
        assert!(array_item_error.contains("not_an_item_parser"));

        let property = crate::mcp::action_registry::ObjectItemPropertyDescriptor {
            name: "target_address",
            parser: "not_an_object_item_parser",
            description: "test-only unsupported parser",
        };
        let object_item_error = validate_object_item_property_value(
            "hook",
            "detour",
            "hooks",
            0,
            &property,
            &json!("0x1000"),
        )
        .expect_err("unknown object item parsers should not be silently accepted");
        assert!(object_item_error.contains("hook(action='detour')"));
        assert!(object_item_error.contains("hooks[0].target_address"));
        assert!(object_item_error.contains("unsupported action registry object item parser"));
        assert!(object_item_error.contains("not_an_object_item_parser"));
    }

    #[test]
    fn validates_common_input_bounds_from_action_registry() {
        validate_common_input_bounds(
            "memory",
            &json!({
                "action": "read",
                "timeout_ms": "3600000",
                "artifact_retention_secs": "86400"
            }),
        )
        .expect("common input bounds should accept registry maximums");

        let zero_timeout =
            validate_common_input_bounds("memory", &json!({"action": "read", "timeout_ms": 0}))
                .expect_err("timeout_ms should honor common field minimum");
        assert!(zero_timeout.contains("memory(action='read')"));
        assert!(zero_timeout.contains("timeout_ms"));
        assert!(zero_timeout.contains(">= 1"));

        let high_retention = validate_common_input_bounds(
            "memory",
            &json!({
                "action": "read",
                "artifact_retention_secs": crate::artifact::MAX_ARTIFACT_RETENTION_SECS + 1
            }),
        )
        .expect_err("artifact retention should reject values above the registry maximum");
        assert!(high_retention.contains("memory(action='read')"));
        assert!(high_retention.contains("artifact_retention_secs"));
        assert!(high_retention.contains("<= 86400"));
    }

    #[test]
    fn validates_parser_hints_from_action_registry() {
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "write",
                "device_path": "\\\\.\\Device",
                "ioctl_code": "0x222003",
                "address": "0x1000",
                "data": "DE AD BE EF"
            }),
        )
        .expect("parser hints should accept alias-backed bytes, ioctl, and address formats");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "read",
                "device_path": "\\\\.\\Device",
                "ioctl_code": "0x222003",
                "address": "0x1000",
                "input_struct": "01 02",
                "physical": true,
                "size": 8
            }),
        )
        .expect("kernel read should accept optional boolean, bytes, and size descriptors");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_pe_dump",
                "base_address": "0x140000000",
                "output_path": "C:\\temp\\dump.bin"
            }),
        )
        .expect("driver_pe_dump should accept optional address and path descriptors");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_global_hook",
                "target_module": "ntoskrnl.exe",
                "replacement_addr": "0x1000"
            }),
        )
        .expect("driver_global_hook should accept optional module-name and address descriptors");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_kernel_exec",
                "shellcode_bytes": "90 C3",
                "alloc_address": "0xFFFF80000000"
            }),
        )
        .expect("driver_kernel_exec should accept optional bytes and address descriptors");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_auto_inject",
                "inject_flags": ["ntquery", "amsi"]
            }),
        )
        .expect("driver_auto_inject should accept array-choice string-array parser hints");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_memory_pool",
                "pool_tag": "Proc",
                "max_entries": 32
            }),
        )
        .expect("driver_memory_pool should accept ASCII pool tag parser hints");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_memory_pool",
                "pool_tag": 0x636F7250u64
            }),
        )
        .expect("driver_memory_pool should accept raw integer pool tag parser hints");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_cred_dump",
                "cred_action": "read",
                "pid": "500",
                "address": "0xFFFF800000123000",
                "size": "0x80"
            }),
        )
        .expect("driver_cred_dump should accept credential read pid/address/size parser hints");
        validate_parser_hints(
            "kernel",
            &json!({
                "action": "pte_modify",
                "device_path": "\\\\.\\Device",
                "read_ioctl": 0x222004u64,
                "write_ioctl": 0x222008u64,
                "address": "0xFFFF800000001000",
                "cr3": "0x12345000"
            }),
        )
        .expect("pte_modify should accept registry required u64/address parser hints");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "write",
                "pid": 1234,
                "address": "0x1000",
                "data": "DE AD BE EF"
            }),
        )
        .expect("parser hints should accept memory write byte aliases");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "scan_new",
                "value_type": "bytes",
                "pattern_bytes": "48 8B ?? ??"
            }),
        )
        .expect("parser hints should accept wildcard byte pattern aliases");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "scan_list",
                "cursor": "scan-results:session:1:address_asc:2",
                "summary_only": true,
                "output_path": "C:\\temp\\scan-results.json"
            }),
        )
        .expect("memory scan_list should accept optional string, boolean, and path descriptors");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "scan",
                "scan_mode": "multi",
                "values": [1, 2.5, -3],
                "delta": 4.5,
                "min": -10,
                "max": 10
            }),
        )
        .expect("memory scan should accept registry-described number and number-array descriptors");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "typed_read",
                "pid": 42,
                "address": "0x1000",
                "type": "u32",
                "allow_unaligned": false
            }),
        )
        .expect("memory typed_read should accept optional boolean descriptors");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "scan",
                "pid": 42,
                "scan_mode": "string",
                "pattern": "needle",
                "case_insensitive": true,
                "exclude_mapped": false,
                "exclude_image": true,
                "region_cache_refresh": true
            }),
        )
        .expect("memory scan should accept optional boolean descriptors");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "diagnostics",
                "pid": 42,
                "include_modules": true,
                "include_handles": false,
                "include_entropy": true
            }),
        )
        .expect("memory diagnostics should accept optional boolean descriptors");
        validate_parser_hints(
            "target",
            &json!({"action": "module_base", "pid": 42, "module": "kernel32.dll"}),
        )
        .expect("parser hints should accept alias-backed module names");
        validate_parser_hints(
            "inject",
            &json!({"action": "dll", "pid": 42, "dll_path": "C:\\temp\\payload.dll"}),
        )
        .expect("parser hints should accept path-like required fields");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "protect",
                "pid": 1234,
                "address": "0x1000",
                "protect": "PAGE_EXECUTE_READWRITE"
            }),
        )
        .expect("parser hints should accept full symbolic page protection aliases");
        validate_parser_hints(
            "memory",
            &json!({
                "action": "alloc",
                "pid": 1234,
                "size": 4096,
                "protect": 0x40
            }),
        )
        .expect("parser hints should accept numeric page protection flags");
        validate_parser_hints(
            "orchestrate",
            &json!({
                "action": "execute",
                "pid": 1234,
                "shellcode": "90 C3",
                "dry_run": false,
                "allow_live_execution": true
            }),
        )
        .expect("optional parser descriptors should validate orchestration execute inputs");
        validate_parser_hints(
            "self",
            &json!({
                "action": "next_steps",
                "result": {"isError": true},
                "doctor": {"checks": []}
            }),
        )
        .expect("optional object parser descriptors should accept self next_steps objects");
        validate_parser_hints(
            "target",
            &json!({"action": "thread_context", "tid": 42, "suspend": true}),
        )
        .expect("target thread_context should accept optional boolean descriptors");
        validate_parser_hints(
            "target",
            &json!({"action": "sam_dump", "output_dir": "C:\\temp", "dump_sam": true}),
        )
        .expect("target sam_dump should accept optional path and boolean descriptors");
        validate_parser_hints(
            "target",
            &json!({"action": "kerberos_tickets", "output_path": "C:\\temp\\tickets.json", "all_sessions": true}),
        )
        .expect("target kerberos_tickets should accept optional path and boolean descriptors");
        validate_parser_hints(
            "stealth",
            &json!({
                "action": "sentinel_start",
                "patch_etw": true,
                "patch_amsi": true,
                "unhook_ntdll": false,
                "watchdog": false
            }),
        )
        .expect("stealth sentinel_start should accept optional boolean descriptors");
        validate_parser_hints(
            "stealth",
            &json!({
                "action": "testsign_launch_hooked",
                "exe_path": "C:\\Windows\\System32\\notepad.exe",
                "args": "--safe",
                "work_dir": "C:\\Windows\\System32"
            }),
        )
        .expect("stealth testsign launch should accept optional path and string descriptors");
        validate_parser_hints(
            "stealth",
            &json!({
                "action": "spoof_ppid",
                "parent_pid": 4,
                "command": "notepad.exe"
            }),
        )
        .expect("stealth spoof_ppid should accept optional pid and string descriptors");
        validate_parser_hints(
            "stealth",
            &json!({
                "action": "firewall_add_rule",
                "program": "C:\\Windows\\System32\\notepad.exe",
                "protocol": "tcp",
                "port": "4444"
            }),
        )
        .expect("stealth firewall_add_rule should accept optional path and string descriptors");

        let pid =
            validate_parser_hints("memory", &json!({"action": "alloc", "pid": -1, "size": 8}))
                .expect_err("pid parser hints should reject negative values");
        assert!(pid.contains("memory(action='alloc')"));
        assert!(pid.contains("pid"));
        assert!(pid.contains("parser hints"));

        let address = validate_parser_hints(
            "memory",
            &json!({"action": "protect", "pid": 1234, "address": "not-an-address"}),
        )
        .expect_err("address parser hints should reject malformed addresses");
        assert!(address.contains("protect"));
        assert!(address.contains("address"));
        assert!(address.contains("parser hints"));

        let bytes = validate_parser_hints(
            "kernel",
            &json!({
                "action": "write",
                "device_path": "\\\\.\\Device",
                "ioctl_code": 1,
                "address": "0x1000",
                "bytes": [256]
            }),
        )
        .expect_err("byte parser hints should reject out-of-range byte arrays");
        assert!(bytes.contains("kernel(action='write')"));
        assert!(bytes.contains("bytes"));
        assert!(bytes.contains("parser hints"));

        let memory_bytes = validate_parser_hints(
            "memory",
            &json!({
                "action": "write",
                "pid": 1234,
                "address": "0x1000",
                "bytes": [256]
            }),
        )
        .expect_err("memory write byte parser hints should reject out-of-range bytes");
        assert!(memory_bytes.contains("memory(action='write')"));
        assert!(memory_bytes.contains("bytes"));
        assert!(memory_bytes.contains("parser hints"));

        let pattern = validate_parser_hints(
            "memory",
            &json!({
                "action": "scan_new",
                "value_type": "bytes",
                "signature": "488B??00"
            }),
        )
        .expect_err("compact wildcard byte patterns should stay explicit and space-separated");
        assert!(pattern.contains("scan_new"));
        assert!(pattern.contains("signature"));
        assert!(pattern.contains("parser hints"));

        let module_name = validate_parser_hints(
            "target",
            &json!({
                "action": "module_base",
                "pid": 42,
                "module": "C:\\Windows\\System32\\kernel32.dll"
            }),
        )
        .expect_err("module name parser hints should reject path-like values");
        assert!(module_name.contains("target(action='module_base')"));
        assert!(module_name.contains("module"));
        assert!(module_name.contains("path separators"));

        let path = validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_load",
                "driver_path": "bad\0driver.sys",
                "service_name": "memoric"
            }),
        )
        .expect_err("path parser hints should reject control characters");
        assert!(path.contains("kernel(action='driver_load')"));
        assert!(path.contains("driver_path"));
        assert!(path.contains("control characters"));

        let kernel_optional_boolean =
            validate_parser_hints("kernel", &json!({"action": "read", "physical": "true"}))
                .expect_err("kernel optional boolean descriptors should reject string booleans");
        assert!(kernel_optional_boolean.contains("kernel(action='read')"));
        assert!(kernel_optional_boolean.contains("physical"));
        assert!(kernel_optional_boolean.contains("boolean"));

        let kernel_optional_path = validate_parser_hints(
            "kernel",
            &json!({"action": "driver_pe_dump", "output_path": "bad\0path"}),
        )
        .expect_err("kernel optional path descriptors should reject control characters");
        assert!(kernel_optional_path.contains("kernel(action='driver_pe_dump')"));
        assert!(kernel_optional_path.contains("output_path"));
        assert!(kernel_optional_path.contains("control characters"));

        let kernel_optional_module = validate_parser_hints(
            "kernel",
            &json!({
                "action": "driver_global_hook",
                "target_module": "C:\\Windows\\ntoskrnl.exe"
            }),
        )
        .expect_err("kernel optional module-name descriptors should reject path-like values");
        assert!(kernel_optional_module.contains("kernel(action='driver_global_hook')"));
        assert!(kernel_optional_module.contains("target_module"));
        assert!(kernel_optional_module.contains("path separators"));

        let kernel_optional_bytes = validate_parser_hints(
            "kernel",
            &json!({"action": "driver_kernel_exec", "shellcode_bytes": [256]}),
        )
        .expect_err("kernel optional byte descriptors should reject out-of-range bytes");
        assert!(kernel_optional_bytes.contains("kernel(action='driver_kernel_exec')"));
        assert!(kernel_optional_bytes.contains("shellcode_bytes"));
        assert!(kernel_optional_bytes.contains("parser hints"));

        let kernel_array_choice_shape = validate_parser_hints(
            "kernel",
            &json!({"action": "driver_auto_inject", "inject_flags": [42]}),
        )
        .expect_err("array-choice parser hints should reject non-string items");
        assert!(kernel_array_choice_shape.contains("kernel(action='driver_auto_inject')"));
        assert!(kernel_array_choice_shape.contains("inject_flags"));
        assert!(kernel_array_choice_shape.contains("array of strings"));

        let kernel_pool_tag_long = validate_parser_hints(
            "kernel",
            &json!({"action": "driver_memory_pool", "pool_tag": "TooLong"}),
        )
        .expect_err("pool tag parser hints should reject long tag strings");
        assert!(kernel_pool_tag_long.contains("kernel(action='driver_memory_pool')"));
        assert!(kernel_pool_tag_long.contains("pool_tag"));
        assert!(kernel_pool_tag_long.contains("1-4 byte ASCII"));

        let kernel_pool_tag_unicode = validate_parser_hints(
            "kernel",
            &json!({"action": "driver_memory_pool", "pool_tag": "猫"}),
        )
        .expect_err("pool tag parser hints should reject non-ASCII tag strings");
        assert!(kernel_pool_tag_unicode.contains("pool_tag"));
        assert!(kernel_pool_tag_unicode.contains("ASCII"));

        let kernel_pool_tag_range = validate_parser_hints(
            "kernel",
            &json!({"action": "driver_memory_pool", "pool_tag": (u32::MAX as u64) + 1}),
        )
        .expect_err("pool tag parser hints should reject values above u32");
        assert!(kernel_pool_tag_range.contains("pool_tag"));
        assert!(kernel_pool_tag_range.contains("u32 range"));

        let kernel_required_u64 = validate_parser_hints(
            "kernel",
            &json!({
                "action": "pte_modify",
                "device_path": "\\\\.\\Device",
                "read_ioctl": 1,
                "write_ioctl": 2,
                "address": "0x1000",
                "cr3": "not-a-number"
            }),
        )
        .expect_err("kernel required u64 parser hints should reject malformed CR3");
        assert!(kernel_required_u64.contains("kernel(action='pte_modify')"));
        assert!(kernel_required_u64.contains("cr3"));
        assert!(kernel_required_u64.contains("unsigned integer"));

        let optional_boolean = validate_parser_hints(
            "orchestrate",
            &json!({"action": "execute", "pid": 1234, "dry_run": "false"}),
        )
        .expect_err("optional boolean descriptors should reject string booleans");
        assert!(optional_boolean.contains("orchestrate(action='execute')"));
        assert!(optional_boolean.contains("dry_run"));
        assert!(optional_boolean.contains("boolean"));

        let optional_object =
            validate_parser_hints("self", &json!({"action": "next_steps", "result": "bad"}))
                .expect_err("optional object descriptors should reject scalar values");
        assert!(optional_object.contains("self(action='next_steps')"));
        assert!(optional_object.contains("result"));
        assert!(optional_object.contains("object"));

        let memory_optional_boolean = validate_parser_hints(
            "memory",
            &json!({"action": "scan_list", "summary_only": "true"}),
        )
        .expect_err("memory optional boolean descriptors should reject string booleans");
        assert!(memory_optional_boolean.contains("memory(action='scan_list')"));
        assert!(memory_optional_boolean.contains("summary_only"));
        assert!(memory_optional_boolean.contains("boolean"));

        let memory_optional_path = validate_parser_hints(
            "memory",
            &json!({"action": "scan_list", "output_path": "bad\0path"}),
        )
        .expect_err("memory optional path descriptors should reject control characters");
        assert!(memory_optional_path.contains("memory(action='scan_list')"));
        assert!(memory_optional_path.contains("output_path"));
        assert!(memory_optional_path.contains("control characters"));

        let memory_optional_string =
            validate_parser_hints("memory", &json!({"action": "scan_list", "cursor": 42}))
                .expect_err(
                    "memory optional string descriptors should reject non-string cursor values",
                );
        assert!(memory_optional_string.contains("memory(action='scan_list')"));
        assert!(memory_optional_string.contains("cursor"));
        assert!(memory_optional_string.contains("string"));

        let memory_number = validate_parser_hints(
            "memory",
            &json!({"action": "scan", "scan_mode": "delta", "delta": "1.5"}),
        )
        .expect_err("memory number descriptors should reject string numbers before dispatch");
        assert!(memory_number.contains("memory(action='scan')"));
        assert!(memory_number.contains("delta"));
        assert!(memory_number.contains("JSON number"));

        let memory_number_array = validate_parser_hints(
            "memory",
            &json!({"action": "scan", "scan_mode": "multi", "values": [1, "2"]}),
        )
        .expect_err("memory number-array descriptors should reject non-number array items");
        assert!(memory_number_array.contains("memory(action='scan')"));
        assert!(memory_number_array.contains("values"));
        assert!(memory_number_array.contains("array of JSON numbers"));

        let target_optional_boolean = validate_parser_hints(
            "target",
            &json!({"action": "thread_context", "tid": 42, "suspend": "true"}),
        )
        .expect_err("target optional boolean descriptors should reject string booleans");
        assert!(target_optional_boolean.contains("target(action='thread_context')"));
        assert!(target_optional_boolean.contains("suspend"));
        assert!(target_optional_boolean.contains("boolean"));

        let target_optional_path = validate_parser_hints(
            "target",
            &json!({"action": "sam_dump", "output_dir": "bad\0path"}),
        )
        .expect_err("target optional path descriptors should reject control characters");
        assert!(target_optional_path.contains("target(action='sam_dump')"));
        assert!(target_optional_path.contains("output_dir"));
        assert!(target_optional_path.contains("control characters"));

        let stealth_optional_boolean = validate_parser_hints(
            "stealth",
            &json!({"action": "sentinel_start", "patch_etw": "true"}),
        )
        .expect_err("stealth optional boolean descriptors should reject string booleans");
        assert!(stealth_optional_boolean.contains("stealth(action='sentinel_start')"));
        assert!(stealth_optional_boolean.contains("patch_etw"));
        assert!(stealth_optional_boolean.contains("boolean"));

        let stealth_optional_path = validate_parser_hints(
            "stealth",
            &json!({"action": "testsign_launch_hooked", "exe_path": "bad\0path"}),
        )
        .expect_err("stealth optional path descriptors should reject control characters");
        assert!(stealth_optional_path.contains("stealth(action='testsign_launch_hooked')"));
        assert!(stealth_optional_path.contains("exe_path"));
        assert!(stealth_optional_path.contains("control characters"));

        let stealth_optional_pid = validate_parser_hints(
            "stealth",
            &json!({"action": "spoof_ppid", "parent_pid": -1}),
        )
        .expect_err("stealth optional pid descriptors should reject negative values");
        assert!(stealth_optional_pid.contains("stealth(action='spoof_ppid')"));
        assert!(stealth_optional_pid.contains("parent_pid"));
        assert!(stealth_optional_pid.contains("parser hints"));

        let protection = validate_parser_hints(
            "memory",
            &json!({
                "action": "protect",
                "pid": 1234,
                "address": "0x1000",
                "protect": "execute everything"
            }),
        )
        .expect_err("protection parser hints should reject unsupported symbolic aliases");
        assert!(protection.contains("memory(action='protect')"));
        assert!(protection.contains("protect"));
        assert!(protection.contains("parser hints"));
    }

    #[test]
    fn validates_u32_param_bounds() {
        assert_eq!(
            require_u32_param(&json!({"pid": "0xFFFF_FFFF"}), "pid", "kernel", "vad_hide").unwrap(),
            u32::MAX
        );
        assert!(require_u32_param(
            &json!({"pid": 4_294_967_296u64}),
            "pid",
            "kernel",
            "vad_hide"
        )
        .is_err());
    }

    #[test]
    fn validates_byte_array_param() {
        assert_eq!(
            require_byte_array_param(&json!({"bytes": "DE AD BE EF"}), "bytes", "kernel", "write")
                .unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(
            require_byte_array_param(&json!({"bytes": []}), "bytes", "kernel", "write").is_err()
        );
        assert!(
            require_byte_array_param(&json!({"bytes": [256]}), "bytes", "kernel", "write").is_err()
        );
    }
}
