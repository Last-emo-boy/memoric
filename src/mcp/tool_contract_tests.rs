use super::*;
use crate::mcp::tool_call::call_tool;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn expected_schema_for_parser_name(parser: &str) -> Value {
    match parser {
        "address_u64" | "pid_u32" | "tid_u32" | "u64" => json!({ "type": ["integer", "string"] }),
        "number" => json!({ "type": "number" }),
        "boolean" => json!({ "type": "boolean" }),
        "object" => json!({ "type": "object" }),
        "string_array" => json!({ "type": "array", "items": { "type": "string" } }),
        "number_array" => json!({ "type": "array", "items": { "type": "number" } }),
        "string" | _ => json!({ "type": "string" }),
    }
}

fn expected_action_parameter_condition(tool: &str, action: &str) -> Option<Value> {
    let required_parameters = crate::mcp::action_registry::required_parameters(tool, action);
    let conditional_required_parameters =
        crate::mcp::action_registry::conditional_required_parameters(tool, action);
    let alternative_required_parameters =
        crate::mcp::action_registry::alternative_required_parameters(tool, action);
    let choices = crate::mcp::action_registry::choice_parameters(tool, action);
    let array_choices = crate::mcp::action_registry::array_choice_parameters(tool, action);
    let bounds = crate::mcp::action_registry::parameter_bounds(tool, action);
    let parser_hints = crate::mcp::action_registry::parser_hints(tool, action);

    if required_parameters.is_empty()
        && conditional_required_parameters.is_empty()
        && alternative_required_parameters.is_empty()
        && choices.is_empty()
        && array_choices.is_empty()
        && bounds.is_empty()
    {
        return None;
    }

    let mut then = serde_json::Map::new();
    if !required_parameters.is_empty() {
        let mut required = Vec::with_capacity(required_parameters.len() + 1);
        required.push("action");
        for parameter in required_parameters {
            if !required.contains(parameter) {
                required.push(parameter);
            }
        }
        then.insert("required".to_string(), json!(required));
    }

    let mut properties = serde_json::Map::new();
    let mut nested_conditions = Vec::new();
    for condition in conditional_required_parameters {
        let mut conditional_required = Vec::with_capacity(condition.parameters.len() + 1);
        conditional_required.push(condition.when_parameter);
        for parameter in condition.parameters {
            if !conditional_required.contains(parameter) {
                conditional_required.push(parameter);
            }
        }
        let mut when_values = condition.when_values.to_vec();
        if condition.default_applies {
            when_values.push("");
        }
        nested_conditions.push(json!({
            "if": {
                "properties": {
                    condition.when_parameter: {
                        "enum": when_values
                    }
                }
            },
            "then": {
                "required": conditional_required
            },
            "description": condition.description,
        }));
    }
    for alternative in alternative_required_parameters {
        let alternatives = alternative
            .parameters
            .iter()
            .map(|parameter| json!({ "required": [*parameter] }))
            .collect::<Vec<_>>();
        let then_schema = json!({
            "anyOf": alternatives,
            "description": alternative.description,
        });
        if let Some(when_parameter) = alternative.when_parameter {
            let mut when_values = alternative.when_values.to_vec();
            if alternative.default_applies {
                when_values.push("");
            }
            nested_conditions.push(json!({
                "if": {
                    "properties": {
                        when_parameter: {
                            "enum": when_values
                        }
                    }
                },
                "then": then_schema,
                "description": alternative.description,
            }));
        } else {
            nested_conditions.push(then_schema);
        }
    }
    for choice in choices {
        properties.insert(
            choice.parameter.to_string(),
            json!({ "enum": choice.values }),
        );
    }
    for choice in array_choices {
        properties.insert(
            choice.parameter.to_string(),
            json!({
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": choice.values,
                }
            }),
        );
    }
    for bound in bounds {
        let parameter_schema = properties
            .entry(bound.parameter.to_string())
            .or_insert_with(|| json!({}));
        if let Some(parameter_schema_object) = parameter_schema.as_object_mut() {
            let parser = parser_hints
                .iter()
                .find(|hint| hint.parameter == bound.parameter)
                .map(|hint| hint.parser)
                .unwrap_or("u64");
            if matches!(
                parser,
                "array_length" | "object_array" | "bytes" | "byte_pattern"
            ) {
                if let Some(minimum) = bound.minimum {
                    parameter_schema_object.insert("minItems".to_string(), json!(minimum));
                }
                if let Some(maximum) = bound.maximum {
                    parameter_schema_object.insert("maxItems".to_string(), json!(maximum));
                }
                if matches!(parser, "bytes" | "byte_pattern") {
                    parameter_schema_object.insert(
                        "x-memoric-byteLengthMinimum".to_string(),
                        json!(bound.minimum),
                    );
                    parameter_schema_object.insert(
                        "x-memoric-byteLengthMaximum".to_string(),
                        json!(bound.maximum),
                    );
                }
                if let Some(item_parser) = parser_hints
                    .iter()
                    .find(|hint| hint.parameter == bound.parameter)
                    .and_then(|hint| hint.array_item_parser)
                {
                    parameter_schema_object.insert(
                        "items".to_string(),
                        expected_schema_for_parser_name(item_parser),
                    );
                }
            } else {
                if let Some(minimum) = bound.minimum {
                    parameter_schema_object.insert("minimum".to_string(), json!(minimum));
                }
                if let Some(maximum) = bound.maximum {
                    parameter_schema_object.insert("maximum".to_string(), json!(maximum));
                }
            }
        }
    }
    if !properties.is_empty() {
        then.insert("properties".to_string(), Value::Object(properties));
    }
    if !nested_conditions.is_empty() {
        then.insert("allOf".to_string(), json!(nested_conditions));
    }

    Some(json!({
        "if": {
            "properties": {
                "action": { "const": action }
            },
            "required": ["action"]
        },
        "then": Value::Object(then)
    }))
}

#[test]
fn registered_tools_have_modern_metadata() {
    let tools = register_tools();
    assert_eq!(tools.len(), crate::mcp::action_registry::tool_names().len());

    for tool in &tools {
        let name = tool["name"].as_str().expect("tool name");
        assert!(
            tool.get("inputSchema").is_some(),
            "{} missing inputSchema",
            name
        );
        assert!(
            tool.get("outputSchema").is_some(),
            "{} missing outputSchema",
            name
        );
        assert!(
            tool.get("annotations").is_some(),
            "{} missing annotations",
            name
        );
        assert_eq!(
            tool["execution"]["taskSupport"], "optional",
            "{} missing optional task support metadata",
            name
        );
        assert!(
            tool.get("x-memoric-actions").is_some(),
            "{} missing action metadata",
            name
        );
        assert!(
            tool.get("x-memoric-data-classification").is_some(),
            "{} missing data classification metadata",
            name
        );
        assert!(
            tool.get("x-memoric-display").is_some(),
            "{} missing display metadata",
            name
        );

        let properties = &tool["inputSchema"]["properties"];
        assert!(
            properties.get("dry_run").is_some(),
            "{} missing dry_run common field",
            name
        );
        assert!(
            properties.get("purpose").is_some(),
            "{} missing purpose common field",
            name
        );
        assert!(
            properties.get("request_id").is_some(),
            "{} missing request_id common field",
            name
        );
        assert!(
            properties.get("redaction").is_some(),
            "{} missing redaction common field",
            name
        );
        assert!(
            properties.get("timeout_ms").is_some(),
            "{} missing timeout_ms common field",
            name
        );
        let timeout_ms = properties.get("timeout_ms").expect("timeout_ms field");
        assert_eq!(
            timeout_ms["minimum"],
            json!(1),
            "{} timeout_ms missing registry minimum",
            name
        );
        assert_eq!(
            timeout_ms["maximum"],
            json!(crate::runtime::MAX_TIMEOUT_MS),
            "{} timeout_ms missing registry maximum",
            name
        );
        if name == "inject" {
            assert_eq!(
                    timeout_ms["default"],
                    json!(30000),
                    "inject timeout_ms should preserve its explicit default while inheriting registry bounds"
                );
        }
        assert!(
            properties.get("artifact_retention_secs").is_some(),
            "{} missing artifact_retention_secs common field",
            name
        );
        let artifact_retention_secs = properties
            .get("artifact_retention_secs")
            .expect("artifact_retention_secs field");
        assert_eq!(
            artifact_retention_secs["default"],
            json!(crate::artifact::DEFAULT_ARTIFACT_RETENTION_SECS),
            "{} artifact_retention_secs missing registry default",
            name
        );
        assert_eq!(
            artifact_retention_secs["minimum"],
            json!(1),
            "{} artifact_retention_secs missing registry minimum",
            name
        );
        assert_eq!(
            artifact_retention_secs["maximum"],
            json!(crate::artifact::MAX_ARTIFACT_RETENTION_SECS),
            "{} artifact_retention_secs missing registry maximum",
            name
        );
        assert!(
            properties.get("task_id").is_some(),
            "{} missing task_id common field",
            name
        );

        let meta = tool.get("_meta").expect("tool _meta");
        assert!(
            crate::mcp::meta::validate_extension_keys(&json!({"_meta": meta})).is_empty(),
            "{} has ungoverned _meta keys",
            name
        );
        assert_eq!(
            meta["openai/widgetAccessible"], false,
            "{} should not allow widget tool calls by default",
            name
        );
        if let Some(uri) = meta["ui"]["resourceUri"].as_str() {
            assert_eq!(
                meta["openai/outputTemplate"], uri,
                "{} should expose Apps SDK outputTemplate compatibility metadata",
                name
            );
            assert_eq!(meta["io.memoric/ui"]["resourceUri"], uri);
        }
    }
}

#[test]
fn tool_metadata_rejects_prompt_injection_language() {
    let tools = register_tools();
    let mut findings = Vec::new();

    for (index, tool) in tools.iter().enumerate() {
        collect_unsafe_metadata_strings(
            &format!(
                "tools[{}].{}",
                index,
                tool["name"].as_str().unwrap_or("<unknown>")
            ),
            tool,
            &mut findings,
        );
    }

    collect_unsafe_metadata_strings(
        "guide.default",
        &crate::mcp::guide::memoric_guide(&json!({})).expect("default guide"),
        &mut findings,
    );
    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        collect_unsafe_metadata_strings(
            &format!("guide.{}", tool),
            &crate::mcp::guide::memoric_guide(&json!({"domain": tool})).expect("domain guide"),
            &mut findings,
        );
    }

    collect_unsafe_doc_lines(
        "docs/tool-reference.md",
        include_str!("../../docs/tool-reference.md"),
        &mut findings,
    );
    collect_unsafe_doc_lines(
        "docs/tool-catalog.json",
        include_str!("../../docs/tool-catalog.json"),
        &mut findings,
    );
    collect_unsafe_doc_lines(
        "docs/server-manifest.json",
        include_str!("../../docs/server-manifest.json"),
        &mut findings,
    );

    assert!(
        findings.is_empty(),
        "tool metadata contains prompt-injection language:\n{}",
        findings.join("\n")
    );
}

#[test]
fn committed_tool_catalog_matches_registered_tools_snapshot() {
    let catalog: Value = serde_json::from_str(include_str!("../../docs/tool-catalog.json"))
        .expect("committed tool catalog should be valid JSON");
    let runtime_tools = register_tools();
    let runtime_resources = crate::mcp::resources::list();
    let runtime_resource_templates = crate::mcp::resources::templates_list();
    let catalog_tools = catalog["tools"]
        .as_array()
        .expect("catalog tools should be an array");
    let catalog_resources = catalog["resources"]
        .as_array()
        .expect("catalog resources should be an array");
    let catalog_resource_templates = catalog["resourceTemplates"]
        .as_array()
        .expect("catalog resource templates should be an array");
    let runtime_resources = runtime_resources["resources"]
        .as_array()
        .expect("runtime resources should be an array");
    let runtime_resource_templates = runtime_resource_templates["resourceTemplates"]
        .as_array()
        .expect("runtime resource templates should be an array");

    assert_eq!(
        catalog["generatedAt"], "deterministic-runtime-tools-list",
        "tool catalog should use deterministic generated marker"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "required_policy"),
        "tool catalog should declare action policy coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "typed_action_ref"),
        "tool catalog should declare typed action reference coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "descriptor_backed_action_ref"),
        "tool catalog should declare descriptor-backed action reference coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "required_parameters"),
        "tool catalog should declare required parameter coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "required_parameter_hints"),
        "tool catalog should declare required parameter parser hint coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "planner_warnings"),
        "tool catalog should declare planner warning coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "parameter_aliases"),
        "tool catalog should declare parameter alias coverage"
    );
    assert!(
        catalog["metadataCoverage"]["actions"]
            .as_array()
            .expect("metadata coverage actions")
            .iter()
            .any(|field| field == "array_choice_parameters"),
        "tool catalog should declare array choice parameter coverage"
    );
    assert!(
        catalog["metadataCoverage"]["tools"]
            .as_array()
            .expect("metadata coverage tools")
            .iter()
            .any(|field| field == "x-memoric-data-classification"),
        "tool catalog should declare redaction classification coverage"
    );
    assert!(
        catalog["metadataCoverage"]["tools"]
            .as_array()
            .expect("metadata coverage tools")
            .iter()
            .any(|field| field == "x-memoric-display"),
        "tool catalog should declare display metadata coverage"
    );
    assert!(
        catalog["metadataCoverage"]["display"]
            .as_array()
            .expect("metadata coverage display")
            .iter()
            .any(|field| field == "selection_hint"),
        "tool catalog should declare display selection hint coverage"
    );
    assert!(
        catalog["metadataCoverage"]["tasks"]
            .as_array()
            .expect("metadata coverage tasks")
            .iter()
            .any(|field| field == "execution.taskSupport"),
        "tool catalog should declare task metadata coverage"
    );
    assert!(
        catalog["metadataCoverage"]["appResources"]
            .as_array()
            .expect("metadata coverage appResources")
            .iter()
            .any(|field| field == "uri"),
        "tool catalog should declare resource/app metadata coverage"
    );
    assert!(
        catalog["metadataCoverage"]["tools"]
            .as_array()
            .expect("metadata coverage tools")
            .iter()
            .any(|field| field == "_meta.ui"),
        "tool catalog should declare UI metadata coverage"
    );
    assert!(
        catalog["metadataCoverage"]["tools"]
            .as_array()
            .expect("metadata coverage tools")
            .iter()
            .any(|field| field == "inputSchema.properties.minimum"),
        "tool catalog should declare input field minimum coverage"
    );
    assert!(
        catalog["metadataCoverage"]["tools"]
            .as_array()
            .expect("metadata coverage tools")
            .iter()
            .any(|field| field == "inputSchema.properties.maximum"),
        "tool catalog should declare input field maximum coverage"
    );
    assert_eq!(catalog["toolCount"], runtime_tools.len());
    assert_eq!(catalog["resourceCount"], runtime_resources.len());
    assert_eq!(
        catalog["resourceTemplateCount"],
        runtime_resource_templates.len()
    );
    assert_eq!(
        tool_schema_snapshot(catalog_tools),
        tool_schema_snapshot(&runtime_tools),
        "tool schema drift detected; run `python scripts\\generate_tool_catalog.py`"
    );
    assert_eq!(
        resource_schema_snapshot(catalog_resources),
        resource_schema_snapshot(runtime_resources),
        "resource metadata drift detected; run `python scripts\\generate_tool_catalog.py`"
    );
    assert_eq!(
        resource_template_schema_snapshot(catalog_resource_templates),
        resource_template_schema_snapshot(runtime_resource_templates),
        "resource template metadata drift detected; run `python scripts\\generate_tool_catalog.py`"
    );

    let reference = include_str!("../../docs/tool-reference.md");
    assert!(
        reference.contains("Parameter Aliases"),
        "tool reference should expose parameter alias metadata"
    );
    assert!(
        reference.contains("Required Parameters"),
        "tool reference should expose required parameter metadata"
    );
    assert!(
        reference.contains("`pid`, `dll_path`"),
        "tool reference should expose representative registry-driven required parameters"
    );
    assert!(
        reference.contains("`pattern_bytes` -> `signature`"),
        "tool reference should expose representative registry-driven parameter aliases"
    );
    assert!(
        reference.contains("| Field | Type | Required | Default | Bounds | Description | Enum |"),
        "tool reference should expose input field bounds"
    );
    assert!(
        reference.contains("`>= 1; <= 3600000`"),
        "tool reference should expose timeout_ms registry bounds"
    );
    assert!(
        reference.contains("`>= 1; <= 86400`"),
        "tool reference should expose artifact retention registry bounds"
    );
}

#[test]
fn mcp_runtime_surfaces_use_governed_meta_extension_keys() {
    let mut findings = Vec::new();
    for (label, value) in [
        ("tools/list", json!({ "tools": register_tools() })),
        ("resources/list", crate::mcp::resources::list()),
        (
            "resources/templates/list",
            crate::mcp::resources::templates_list(),
        ),
        (
            "tool/error",
            crate::mcp::protocol::tool_error_content(
                "memory",
                &json!({"action": "write"}),
                "policy_denied: memory(action='write') blocked by policy",
            ),
        ),
    ] {
        findings.extend(
            crate::mcp::meta::validate_extension_keys(&value)
                .into_iter()
                .map(|finding| format!("{}: {}", label, finding)),
        );
    }

    assert!(
        findings.is_empty(),
        "MCP _meta extension key governance drift:\n{}",
        findings.join("\n")
    );
}

#[test]
fn committed_server_manifest_matches_runtime_surfaces() {
    let manifest: Value = serde_json::from_str(include_str!("../../docs/server-manifest.json"))
        .expect("committed server manifest should be valid JSON");
    let catalog: Value = serde_json::from_str(include_str!("../../docs/tool-catalog.json"))
        .expect("committed tool catalog should be valid JSON");
    let runtime_tools = register_tools();
    let runtime_resources = crate::mcp::resources::list();
    let runtime_resource_templates = crate::mcp::resources::templates_list();
    let runtime_resources = runtime_resources["resources"]
        .as_array()
        .expect("runtime resources should be an array");
    let runtime_resource_templates = runtime_resource_templates["resourceTemplates"]
        .as_array()
        .expect("runtime resource templates should be an array");
    let initialize = crate::mcp::protocol::initialize_result("memoric");

    assert_eq!(
        manifest["generatedAt"], "deterministic-runtime-server-manifest",
        "server manifest should use deterministic generated marker"
    );
    assert_eq!(manifest["machineStateIncluded"], false);
    assert_eq!(manifest["server"]["name"], "memoric");
    assert_eq!(manifest["server"]["package"], env!("CARGO_PKG_NAME"));
    assert_eq!(manifest["server"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        manifest["server"]["protocolVersion"],
        crate::mcp::protocol::PROTOCOL_VERSION
    );
    assert_eq!(
        manifest["capabilities"], initialize["capabilities"],
        "server manifest capabilities drifted from initialize result"
    );
    assert_eq!(manifest["counts"]["tools"], runtime_tools.len());
    assert_eq!(manifest["counts"]["resources"], runtime_resources.len());
    assert_eq!(
        manifest["counts"]["resourceTemplates"],
        runtime_resource_templates.len()
    );
    assert_eq!(manifest["toolCatalog"]["path"], "docs/tool-catalog.json");
    assert_eq!(
        manifest["toolCatalog"]["generatedAt"],
        "deterministic-runtime-tools-list"
    );
    assert_eq!(manifest["toolCatalog"]["toolCount"], catalog["toolCount"]);
    assert_eq!(
        manifest["toolCatalog"]["resourceCount"],
        catalog["resourceCount"]
    );
    assert_eq!(
        manifest["toolCatalog"]["sha256"],
        crate::artifact::sha256_bytes(include_str!("../../docs/tool-catalog.json").as_bytes()),
        "server manifest catalog hash drifted; run `python scripts\\generate_tool_catalog.py`"
    );

    let manifest_resources = manifest["resources"]
        .as_array()
        .expect("manifest resources should be an array");
    let manifest_resource_templates = manifest["resourceTemplates"]
        .as_array()
        .expect("manifest resource templates should be an array");
    assert_eq!(
        resource_schema_snapshot(manifest_resources),
        resource_schema_snapshot(runtime_resources),
        "server manifest resource summary drifted from resources/list"
    );
    assert_eq!(
        resource_template_schema_snapshot(manifest_resource_templates),
        resource_template_schema_snapshot(runtime_resource_templates),
        "server manifest resource template summary drifted from resources/templates/list"
    );

    let docs = manifest["docs"]
        .as_array()
        .expect("manifest docs should be an array");
    for expected_path in [
        "docs/invocation-contract.md",
        "docs/compatibility.md",
        "docs/tool-reference.md",
        "docs/tool-catalog.json",
        "docs/server-manifest.json",
    ] {
        assert!(
            docs.iter().any(|entry| entry["path"] == expected_path),
            "server manifest missing docs entry for {}",
            expected_path
        );
    }

    let runtime_requests = manifest["provenance"]["runtimeRequests"]
        .as_array()
        .expect("manifest runtimeRequests should be an array");
    assert!(runtime_requests.iter().any(|value| value == "initialize"));
    assert!(runtime_requests.iter().any(|value| value == "tools/list"));
    assert!(runtime_requests
        .iter()
        .any(|value| value == "resources/list"));
    assert_eq!(manifest["provenance"]["deterministic"], true);
}

#[test]
fn tool_schema_actions_match_registry_metadata() {
    let tools = register_tools();

    for tool in &tools {
        let name = tool["name"].as_str().expect("tool name");
        let expected_actions = crate::mcp::action_registry::tool_actions(name)
            .expect("registered tool should have registry actions");

        let properties = tool["inputSchema"]["properties"]
            .as_object()
            .expect("schema properties");
        let action_enum = properties
            .get("action")
            .and_then(|action| action.get("enum"))
            .and_then(|values| values.as_array())
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().expect("string action").to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                expected_actions
                    .iter()
                    .map(|action| action.to_string())
                    .collect()
            });
        let mut sorted_action_enum = action_enum.clone();
        sorted_action_enum.sort();
        let mut sorted_expected_actions = expected_actions
            .iter()
            .map(|action| action.to_string())
            .collect::<Vec<_>>();
        sorted_expected_actions.sort();

        assert_eq!(
            sorted_action_enum, sorted_expected_actions,
            "{} schema action enum is out of sync with action registry",
            name
        );

        let metadata = tool["x-memoric-actions"]
            .as_array()
            .expect("action metadata array");
        assert_eq!(
            metadata.len(),
            expected_actions.len(),
            "{} action metadata count is out of sync",
            name
        );

        for (entry, expected_action) in metadata.iter().zip(expected_actions.iter()) {
            assert_eq!(
                entry["action"], *expected_action,
                "{} action metadata order changed",
                name
            );
            let traits = crate::mcp::action_registry::classify_action(name, expected_action);
            assert_eq!(
                entry["read_only"], traits.read_only,
                "{} {}",
                name, expected_action
            );
            assert_eq!(
                entry["state_changing"], traits.state_changing,
                "{} {}",
                name, expected_action
            );
            assert_eq!(
                entry["required_policy"],
                traits.required_policy.as_str(),
                "{} {}",
                name,
                expected_action
            );
            assert_eq!(
                entry["risk"],
                traits.risk.as_str(),
                "{} {}",
                name,
                expected_action
            );
            assert_eq!(
                entry["data_classification"]["redaction"], "classification-aware",
                "{} {}",
                name, expected_action
            );

            let expected_required_parameters =
                crate::mcp::action_registry::required_parameters(name, expected_action);
            assert_eq!(
                entry["required_parameters"],
                json!(expected_required_parameters),
                "{} {} required parameter metadata is out of sync",
                name,
                expected_action
            );
            let expected_required_parameter_hints =
                crate::mcp::action_registry::required_parameter_hints(name, expected_action)
                    .into_iter()
                    .map(|hint| {
                        json!({
                            "parameter": hint.parameter,
                            "parser": hint.parser,
                            "array_item_parser": hint.array_item_parser,
                            "required": hint.required,
                            "aliases": hint.aliases,
                            "choices": hint.choices,
                            "minimum": hint.minimum,
                            "maximum": hint.maximum,
                            "object_item_schema": hint.object_item_schema.map(|schema| schema.to_json()),
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["required_parameter_hints"],
                json!(expected_required_parameter_hints),
                "{} {} required parameter parser hint metadata is out of sync",
                name,
                expected_action
            );
            let expected_conditional_required_parameters =
                crate::mcp::action_registry::conditional_required_parameters(name, expected_action)
                    .into_iter()
                    .map(|condition| {
                        json!({
                            "when_parameter": condition.when_parameter,
                            "when_values": condition.when_values,
                            "parameters": condition.parameters,
                            "default_applies": condition.default_applies,
                            "description": condition.description,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["conditional_required_parameters"],
                json!(expected_conditional_required_parameters),
                "{} {} conditional required parameter metadata is out of sync",
                name,
                expected_action
            );
            let expected_alternative_required_parameters =
                crate::mcp::action_registry::alternative_required_parameters(name, expected_action)
                    .into_iter()
                    .map(|alternative| {
                        json!({
                            "when_parameter": alternative.when_parameter,
                            "when_values": alternative.when_values,
                            "parameters": alternative.parameters,
                            "default_applies": alternative.default_applies,
                            "description": alternative.description,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["alternative_required_parameters"],
                json!(expected_alternative_required_parameters),
                "{} {} alternative required parameter metadata is out of sync",
                name,
                expected_action
            );
            let expected_planner_warnings =
                crate::mcp::action_registry::planner_warnings(name, expected_action)
                    .into_iter()
                    .map(|warning| {
                        json!({
                            "condition": warning.condition.as_str(),
                            "parameter": warning.parameter,
                            "unless_parameter": warning.unless_parameter,
                            "unless_values": warning.unless_values,
                            "message": warning.message,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["planner_warnings"],
                json!(expected_planner_warnings),
                "{} {} planner warning metadata is out of sync",
                name,
                expected_action
            );
            if let Some(expected_action_schema) =
                expected_action_parameter_condition(name, expected_action)
            {
                let all_of = tool["inputSchema"]["allOf"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{} schema should expose allOf conditions", name));
                assert!(
                    all_of
                        .iter()
                        .any(|condition| condition == &expected_action_schema),
                    "{} {} registry descriptors are not reflected in conditional input schema",
                    name,
                    expected_action
                );
            }
            for parameter in expected_required_parameters {
                assert!(
                    properties.contains_key(*parameter),
                    "{} {} required parameter '{}' is missing from the input schema",
                    name,
                    expected_action,
                    parameter
                );
            }

            let expected_aliases =
                crate::mcp::action_registry::parameter_aliases(name, expected_action)
                    .into_iter()
                    .map(|alias| {
                        json!({
                            "canonical": alias.canonical,
                            "alias": alias.alias,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["parameter_aliases"],
                json!(expected_aliases),
                "{} {} parameter alias metadata is out of sync",
                name,
                expected_action
            );

            let expected_choices =
                crate::mcp::action_registry::choice_parameters(name, expected_action)
                    .into_iter()
                    .map(|choice| {
                        json!({
                            "parameter": choice.parameter,
                            "values": choice.values,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["choice_parameters"],
                json!(expected_choices),
                "{} {} choice parameter metadata is out of sync",
                name,
                expected_action
            );
            let expected_array_choices =
                crate::mcp::action_registry::array_choice_parameters(name, expected_action)
                    .into_iter()
                    .map(|choice| {
                        json!({
                            "parameter": choice.parameter,
                            "values": choice.values,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["array_choice_parameters"],
                json!(expected_array_choices),
                "{} {} array choice parameter metadata is out of sync",
                name,
                expected_action
            );
            let expected_bounds =
                crate::mcp::action_registry::parameter_bounds(name, expected_action)
                    .into_iter()
                    .map(|bounds| {
                        json!({
                            "parameter": bounds.parameter,
                            "minimum": bounds.minimum,
                            "maximum": bounds.maximum,
                        })
                    })
                    .collect::<Vec<_>>();
            assert_eq!(
                entry["parameter_bounds"],
                json!(expected_bounds),
                "{} {} parameter bounds metadata is out of sync",
                name,
                expected_action
            );
            let expected_parser_hints = crate::mcp::action_registry::parser_hints(
                name,
                expected_action,
            )
            .into_iter()
            .map(|hint| {
                json!({
                    "parameter": hint.parameter,
                    "parser": hint.parser,
                    "array_item_parser": hint.array_item_parser,
                    "required": hint.required,
                    "aliases": hint.aliases,
                    "choices": hint.choices,
                    "minimum": hint.minimum,
                    "maximum": hint.maximum,
                    "object_item_schema": hint.object_item_schema.map(|schema| schema.to_json()),
                })
            })
            .collect::<Vec<_>>();
            assert_eq!(
                entry["parser_hints"],
                json!(expected_parser_hints),
                "{} {} parser hint metadata is out of sync",
                name,
                expected_action
            );
            for choice in crate::mcp::action_registry::choice_parameters(name, expected_action) {
                let Some(parameter_schema) = properties.get(choice.parameter) else {
                    panic!(
                        "{} {} choice parameter '{}' is missing from the input schema",
                        name, expected_action, choice.parameter
                    );
                };
                let schema_values = parameter_schema["enum"].as_array().unwrap_or_else(|| {
                    panic!(
                        "{} {} choice parameter '{}' schema should have enum values",
                        name, expected_action, choice.parameter
                    )
                });
                for value in choice.values {
                    assert!(
                        schema_values
                            .iter()
                            .any(|schema_value| schema_value == value),
                        "{} {} choice parameter '{}' schema enum is missing '{}'",
                        name,
                        expected_action,
                        choice.parameter,
                        value
                    );
                }
            }
            for choice in
                crate::mcp::action_registry::array_choice_parameters(name, expected_action)
            {
                let Some(parameter_schema) = properties.get(choice.parameter) else {
                    panic!(
                        "{} {} array choice parameter '{}' is missing from the input schema",
                        name, expected_action, choice.parameter
                    );
                };
                let schema_values = parameter_schema["items"]["enum"]
                    .as_array()
                    .unwrap_or_else(|| {
                        panic!(
                            "{} {} array choice parameter '{}' items schema should have enum values",
                            name, expected_action, choice.parameter
                        )
                    });
                for value in choice.values {
                    assert!(
                        schema_values
                            .iter()
                            .any(|schema_value| schema_value == value),
                        "{} {} array choice parameter '{}' schema enum is missing '{}'",
                        name,
                        expected_action,
                        choice.parameter,
                        value
                    );
                }
            }
            for bounds in crate::mcp::action_registry::parameter_bounds(name, expected_action) {
                let Some(parameter_schema) = properties.get(bounds.parameter) else {
                    panic!(
                        "{} {} bounded parameter '{}' is missing from the input schema",
                        name, expected_action, bounds.parameter
                    );
                };
                let tool_bounds = crate::mcp::action_registry::all_parameter_bounds()
                    .iter()
                    .copied()
                    .filter(|candidate| {
                        candidate.tool == name && candidate.parameter == bounds.parameter
                    })
                    .collect::<Vec<_>>();
                let schema_minimum = tool_bounds.iter().try_fold(u64::MAX, |current, candidate| {
                    candidate.minimum.map(|minimum| current.min(minimum))
                });
                let schema_maximum = tool_bounds.iter().try_fold(0u64, |current, candidate| {
                    candidate.maximum.map(|maximum| current.max(maximum))
                });
                let parser = crate::mcp::action_registry::tool_actions(name)
                    .unwrap_or(&[])
                    .iter()
                    .flat_map(|action| crate::mcp::action_registry::parser_hints(name, action))
                    .find(|hint| hint.parameter == bounds.parameter)
                    .map(|hint| hint.parser)
                    .unwrap_or("u64");
                if matches!(
                    parser,
                    "array_length" | "object_array" | "bytes" | "byte_pattern"
                ) {
                    if let Some(minimum) = schema_minimum {
                        assert_eq!(
                            parameter_schema["minItems"],
                            json!(minimum),
                            "{} bounded parameter '{}' schema minItems should be the registry union",
                            name,
                            bounds.parameter
                        );
                    } else {
                        assert!(
                            parameter_schema.get("minItems").is_none(),
                            "{} bounded parameter '{}' schema should not expose minItems when one action is unbounded",
                            name,
                            bounds.parameter
                        );
                    }
                    if let Some(maximum) = schema_maximum {
                        assert_eq!(
                            parameter_schema["maxItems"],
                            json!(maximum),
                            "{} bounded parameter '{}' schema maxItems should be the registry union",
                            name,
                            bounds.parameter
                        );
                    } else {
                        assert!(
                            parameter_schema.get("maxItems").is_none(),
                            "{} bounded parameter '{}' schema should not expose maxItems when one action is unbounded",
                            name,
                            bounds.parameter
                        );
                    }
                } else {
                    if let Some(minimum) = schema_minimum {
                        assert_eq!(
                            parameter_schema["minimum"],
                            json!(minimum),
                            "{} bounded parameter '{}' schema minimum should be the registry union",
                            name,
                            bounds.parameter
                        );
                    } else {
                        assert!(
                            parameter_schema.get("minimum").is_none(),
                            "{} bounded parameter '{}' schema should not expose a minimum when one action is unbounded",
                            name,
                            bounds.parameter
                        );
                    }
                    if let Some(maximum) = schema_maximum {
                        assert_eq!(
                            parameter_schema["maximum"],
                            json!(maximum),
                            "{} bounded parameter '{}' schema maximum should be the registry union",
                            name,
                            bounds.parameter
                        );
                    } else {
                        assert!(
                            parameter_schema.get("maximum").is_none(),
                            "{} bounded parameter '{}' schema should not expose a maximum when one action is unbounded",
                            name,
                            bounds.parameter
                        );
                    }
                }
            }
        }

        let mut expected_choice_unions = std::collections::BTreeMap::<&str, Vec<&str>>::new();
        for action in expected_actions {
            for choice in crate::mcp::action_registry::choice_parameters(name, action) {
                let values = expected_choice_unions.entry(choice.parameter).or_default();
                for value in choice.values {
                    if !values.contains(value) {
                        values.push(value);
                    }
                }
            }
        }
        for (parameter, values) in expected_choice_unions {
            let Some(parameter_schema) = properties.get(parameter) else {
                panic!(
                    "{} choice parameter '{}' is missing from the input schema",
                    name, parameter
                );
            };
            assert_eq!(
                parameter_schema["enum"],
                json!(values),
                "{} choice parameter '{}' schema enum should be the registry union",
                name,
                parameter
            );
        }
        let mut expected_array_choice_unions = std::collections::BTreeMap::<&str, Vec<&str>>::new();
        for action in expected_actions {
            for choice in crate::mcp::action_registry::array_choice_parameters(name, action) {
                let values = expected_array_choice_unions
                    .entry(choice.parameter)
                    .or_default();
                for value in choice.values {
                    if !values.contains(value) {
                        values.push(value);
                    }
                }
            }
        }
        for (parameter, values) in expected_array_choice_unions {
            let Some(parameter_schema) = properties.get(parameter) else {
                panic!(
                    "{} array choice parameter '{}' is missing from the input schema",
                    name, parameter
                );
            };
            assert_eq!(
                parameter_schema["items"]["enum"],
                json!(values),
                "{} array choice parameter '{}' schema items enum should be the registry union",
                name,
                parameter
            );
        }

        let classification = tool["x-memoric-data-classification"]
            .as_array()
            .expect("data classification metadata array");
        assert!(
            classification.iter().any(|entry| {
                entry["path"] == "artifacts[].path"
                    && entry["classification"] == "artifact-reference"
            }),
            "{} missing common artifact classification",
            name
        );
    }
}

#[test]
fn guide_actions_match_registry_actions() {
    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let guide = crate::mcp::guide::memoric_guide(&json!({"domain": tool})).expect("guide");
        let guide_actions = guide["actions"]
            .as_array()
            .unwrap_or_else(|| panic!("{} guide actions must be an array", tool))
            .iter()
            .map(|value| value.as_str().expect("guide action").to_string())
            .collect::<Vec<_>>();
        let expected_actions = crate::mcp::action_registry::tool_actions(tool)
            .expect("registry actions")
            .iter()
            .map(|action| action.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            guide_actions, expected_actions,
            "{} guide actions are out of sync with registry actions",
            tool
        );
    }
}

#[test]
fn missing_action_errors_use_registry_action_lists() {
    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let error = crate::mcp::tool_dispatch::dispatch(tool, &json!({}))
            .expect_err("missing action should fail before handler side effects");
        let available = crate::mcp::action_registry::actions_csv(tool);

        assert!(
            !available.is_empty(),
            "{} should have registered actions",
            tool
        );
        assert!(
            error.contains("requires 'action'") && error.contains(&available),
            "{} missing-action error should use registry actions; got: {}",
            tool,
            error
        );
    }
}

#[test]
fn registry_actions_have_dispatch_branches() {
    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let body = typed_action_dispatch_body(handler_source(tool), tool);
        for action in crate::mcp::action_registry::tool_actions(tool).expect("actions") {
            let enum_name = typed_action_enum_name(tool);
            let variant = typed_action_variant_for(tool, action);
            let branch = format!("{}::{}", enum_name, variant);
            assert!(
                body.contains(&branch),
                "{} action '{}' maps to {} but is missing from the typed handler dispatch",
                tool,
                action,
                branch
            );
        }
    }
}

#[test]
fn handlers_resolve_actions_through_typed_registry_refs() {
    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let source = handler_source(tool);
        assert!(
            source.contains("require_typed_action(args,"),
            "{} handler should bind its action through a typed registry reference",
            tool
        );
        assert!(
            !source.contains("require_registered_action(args,"),
            "{} handler should not dispatch from a bare registered-action string",
            tool
        );
    }
}

#[test]
fn direct_handler_required_params_are_declared_in_registry() {
    let mut missing = Vec::new();

    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let source = handler_source(tool);
        let production_source = source.split("\n#[cfg(test)]").next().unwrap_or(source);
        for requirement in direct_handler_requirements(production_source) {
            if requirement.tool != tool {
                missing.push(format!(
                    "{} handler declares a direct requirement for {}(action='{}') parameter '{}'",
                    tool, requirement.tool, requirement.action, requirement.parameter
                ));
                continue;
            }
            if !crate::mcp::action_registry::is_known_tool_action(
                &requirement.tool,
                &requirement.action,
            ) {
                missing.push(format!(
                    "{} handler requires parameter '{}' for unknown registry action '{}'",
                    requirement.tool, requirement.parameter, requirement.action
                ));
                continue;
            }
            if !registry_declares_required_parameter(
                &requirement.tool,
                &requirement.action,
                &requirement.parameter,
            ) {
                missing.push(format!(
                    "{}(action='{}') handler-only required parameter '{}' is missing from registry descriptors",
                    requirement.tool, requirement.action, requirement.parameter
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "direct handler requirements must be reflected in action_registry:\n{}",
        missing.join("\n")
    );
}

#[test]
fn nonzero_handler_params_have_registry_minimum_bounds() {
    let mut missing = Vec::new();

    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let source = handler_source(tool);
        let production_source = source.split("\n#[cfg(test)]").next().unwrap_or(source);
        for requirement in
            direct_handler_helper_requirements(production_source, "require_nonzero_usize_param(")
        {
            if requirement.tool != tool {
                missing.push(format!(
                    "{} handler declares a non-zero requirement for {}(action='{}') parameter '{}'",
                    tool, requirement.tool, requirement.action, requirement.parameter
                ));
                continue;
            }
            if !crate::mcp::action_registry::is_known_tool_action(
                &requirement.tool,
                &requirement.action,
            ) {
                missing.push(format!(
                    "{} handler requires non-zero parameter '{}' for unknown registry action '{}'",
                    requirement.tool, requirement.parameter, requirement.action
                ));
                continue;
            }
            if !registry_declares_minimum_bound(
                &requirement.tool,
                &requirement.action,
                &requirement.parameter,
                1,
            ) {
                missing.push(format!(
                    "{}(action='{}') handler non-zero parameter '{}' is missing a registry minimum >= 1",
                    requirement.tool, requirement.action, requirement.parameter
                ));
            }
            if !registry_declares_maximum_bound(
                &requirement.tool,
                &requirement.action,
                &requirement.parameter,
            ) {
                missing.push(format!(
                    "{}(action='{}') handler non-zero parameter '{}' is missing a registry maximum consumed by the shared parser",
                    requirement.tool, requirement.action, requirement.parameter
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "direct handler non-zero requirements must be reflected in action_registry bounds:\n{}",
        missing.join("\n")
    );
}

#[test]
fn optional_bounded_handler_params_have_registry_bounds() {
    let mut missing = Vec::new();

    for tool in crate::mcp::action_registry::tool_names()
        .iter()
        .copied()
        .filter(|tool| *tool != "memoric")
    {
        let source = handler_source(tool);
        let production_source = source.split("\n#[cfg(test)]").next().unwrap_or(source);
        for requirement in
            direct_handler_helper_requirements(production_source, "optional_bounded_u64_param(")
        {
            if requirement.tool != tool {
                missing.push(format!(
                    "{} handler declares an optional bounded parameter for {}(action='{}') parameter '{}'",
                    tool, requirement.tool, requirement.action, requirement.parameter
                ));
                continue;
            }
            if !crate::mcp::action_registry::is_known_tool_action(
                &requirement.tool,
                &requirement.action,
            ) {
                missing.push(format!(
                    "{} handler bounds optional parameter '{}' for unknown registry action '{}'",
                    requirement.tool, requirement.parameter, requirement.action
                ));
                continue;
            }
            if !registry_declares_any_bound(
                &requirement.tool,
                &requirement.action,
                &requirement.parameter,
            ) {
                missing.push(format!(
                    "{}(action='{}') optional bounded parameter '{}' is missing registry bounds consumed by the shared parser",
                    requirement.tool, requirement.action, requirement.parameter
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "direct handler optional bounded parameters must be reflected in action_registry bounds:\n{}",
        missing.join("\n")
    );
}

#[test]
fn migrated_handlers_dispatch_on_typed_action_enums() {
    for tool in [
        "payload",
        "detect",
        "orchestrate",
        "privilege",
        "target",
        "self",
        "memory",
        "hook",
        "inject",
        "stealth",
        "kernel",
    ] {
        let source = handler_source(tool);
        assert!(
            source.contains("::try_from(&action)"),
            "{} handler should convert RegisteredAction into a domain typed enum",
            tool
        );
        assert!(
            !source.contains("match action.as_str()"),
            "{} handler should not branch on raw action strings after typed enum migration",
            tool
        );
    }
}

#[test]
fn registered_action_refs_expose_descriptor_backed_metadata() {
    let action = crate::mcp::action_registry::registered_action("memory", "write")
        .expect("memory write action");

    assert_eq!(action.tool, "memory");
    assert_eq!(action.as_str(), "write");
    assert!(action.traits.state_changing);
    assert_eq!(action.required_parameters, &["pid", "address"]);
    assert!(action
        .alternative_required_parameters
        .iter()
        .any(|alternative| alternative.parameters == &["bytes", "text"]));
    assert!(action
        .parameter_aliases
        .iter()
        .any(|alias| alias.canonical == "bytes" && alias.alias == "data"));
    assert!(action
        .parameter_bounds
        .iter()
        .any(|bound| bound.parameter == "bytes"));
    assert!(action
        .parser_hints
        .iter()
        .any(|hint| hint.parameter == "bytes" && hint.parser == "bytes"));
    assert_eq!(action.metadata_json()["action"], "write");
    assert_eq!(action.metadata_json()["typed_action_ref"], true);
    assert_eq!(action.metadata_json()["descriptor_backed_action_ref"], true);
    assert_eq!(
        action.metadata_json()["registry_source"],
        "src/mcp/action_registry.rs"
    );
    assert!(crate::mcp::action_registry::registered_action("memory", "not_real").is_none());
}

#[test]
fn preflight_validation_consumes_typed_action_refs() {
    let source = include_str!("tool_args.rs");
    let validators = [
        "validate_required_parameters",
        "validate_choice_parameters",
        "validate_parameter_bounds",
        "validate_common_input_bounds",
        "validate_parser_hints",
    ];

    for validator in validators {
        let body = function_body(source, validator);
        assert!(
            body.contains("require_typed_action(args, tool)"),
            "{} should resolve a RegisteredAction before reading action descriptors",
            validator
        );
        assert!(
            !body.contains("require_registered_action(args, tool)"),
            "{} should not validate from a bare action string",
            validator
        );
    }
}

fn handler_source(tool: &str) -> &'static str {
    match tool {
        "target" => include_str!("target_tool.rs"),
        "memory" => include_str!("memory_tool.rs"),
        "inject" => include_str!("inject_tool.rs"),
        "payload" => include_str!("payload_tool.rs"),
        "hook" => include_str!("hook_tool.rs"),
        "stealth" => include_str!("stealth_tool.rs"),
        "detect" => include_str!("detect_tool.rs"),
        "privilege" => include_str!("privilege_tool.rs"),
        "kernel" => include_str!("kernel_tool.rs"),
        "self" => include_str!("self_tool.rs"),
        "orchestrate" => include_str!("orchestrate.rs"),
        _ => panic!("missing handler source for {}", tool),
    }
}

fn typed_action_enum_name(tool: &str) -> &'static str {
    match tool {
        "target" => "TargetAction",
        "memory" => "MemoryAction",
        "inject" => "InjectAction",
        "payload" => "PayloadAction",
        "hook" => "HookAction",
        "stealth" => "StealthAction",
        "detect" => "DetectAction",
        "privilege" => "PrivilegeAction",
        "kernel" => "KernelAction",
        "self" => "SelfAction",
        "orchestrate" => "OrchestrateAction",
        _ => panic!("missing typed action enum name for {}", tool),
    }
}

fn typed_action_variant_for(tool: &str, action: &str) -> String {
    let source = include_str!("action_registry.rs");
    let enum_name = typed_action_enum_name(tool);
    let marker = format!("impl TryFrom<&RegisteredAction> for {}", enum_name);
    let impl_start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("missing TryFrom impl for {}", enum_name));
    let open_index = source[impl_start..]
        .find('{')
        .map(|offset| impl_start + offset)
        .unwrap_or_else(|| panic!("missing TryFrom body for {}", enum_name));
    let close_index = matching_brace(source, open_index)
        .unwrap_or_else(|| panic!("unterminated TryFrom body for {}", enum_name));
    let body = &source[open_index..=close_index];
    let action_marker = format!("\"{}\" => Ok(Self::", action);
    let variant_start = body.find(&action_marker).unwrap_or_else(|| {
        panic!(
            "{} action '{}' is registered but missing from the typed action mapping",
            tool, action
        )
    }) + action_marker.len();
    let variant_tail = &body[variant_start..];
    let variant_end = variant_tail
        .find(')')
        .unwrap_or_else(|| panic!("unterminated variant mapping for {} '{}'", tool, action));
    variant_tail[..variant_end].to_string()
}

fn function_body<'a>(source: &'a str, function: &str) -> &'a str {
    let marker = format!("fn {}(", function);
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("missing function {}", function));
    let rest = &source[start..];
    let body_start = rest
        .find('{')
        .unwrap_or_else(|| panic!("missing function body for {}", function));
    let mut depth = 0usize;
    let mut end = None;
    for (index, ch) in rest[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(body_start + index + 1);
                    break;
                }
            }
            _ => {}
        }
    }

    &rest[..end.unwrap_or_else(|| panic!("unterminated function body for {}", function))]
}

#[test]
fn legacy_aliases_map_to_known_registered_actions() {
    let cases = [
        ("ps", json!({}), "target"),
        ("ps", json!({"action": "find"}), "target"),
        ("modules", json!({}), "target"),
        ("threads", json!({}), "target"),
        ("threads", json!({"tid": 1}), "target"),
        ("suspend_thread", json!({}), "target"),
        ("resume_thread", json!({}), "target"),
        ("read", json!({}), "memory"),
        ("write", json!({}), "memory"),
        ("scan", json!({}), "memory"),
        ("regions", json!({}), "memory"),
        ("alloc", json!({}), "memory"),
        ("free", json!({}), "memory"),
        ("protect", json!({}), "memory"),
        ("inject_dll", json!({}), "inject"),
        ("spawn", json!({}), "inject"),
        ("hijack", json!({}), "inject"),
        ("pe_parse", json!({}), "payload"),
        ("obfuscate", json!({}), "payload"),
        ("inject_ctl", json!({}), "payload"),
        ("unhook", json!({}), "stealth"),
        ("patch", json!({"target": "etw"}), "stealth"),
        ("syscall", json!({"op": "read"}), "stealth"),
        ("cloak", json!({"action": "hide_module"}), "stealth"),
        ("edr", json!({}), "detect"),
        ("edr", json!({"action": "quick"}), "detect"),
        ("vm_detect", json!({}), "detect"),
        ("anti_forensics", json!({}), "detect"),
        ("elevate", json!({}), "privilege"),
        ("token", json!({}), "privilege"),
        ("debug_priv", json!({}), "privilege"),
        ("check_admin", json!({}), "privilege"),
        ("driver", json!({"action": "load"}), "kernel"),
        ("kernel_read", json!({}), "kernel"),
        ("kernel_write", json!({}), "kernel"),
        ("kernel_op", json!({"op": "pte_modify"}), "kernel"),
        ("bruteforce", json!({"action": "sniff_start"}), "kernel"),
        ("sniff", json!({"action": "start"}), "kernel"),
        ("self_protect", json!({"action": "encrypt"}), "self"),
        ("peb", json!({}), "self"),
        ("heap", json!({}), "self"),
        ("self_test", json!({}), "self"),
        ("status", json!({}), "self"),
    ];

    for (legacy_name, args, expected_tool) in cases {
        let (tool, resolved_args) = crate::mcp::legacy_tools::resolve(legacy_name, args)
            .expect("legacy alias should resolve");
        assert_eq!(tool, expected_tool, "{}", legacy_name);

        let action = resolved_args["action"]
            .as_str()
            .unwrap_or_else(|| panic!("{} did not resolve an action", legacy_name));
        assert!(
            crate::mcp::action_registry::is_known_tool_action(&tool, action),
            "{} resolved to unknown {} action '{}'",
            legacy_name,
            tool,
            action
        );
    }
}

fn handler_body<'a>(source: &'a str, tool: &str) -> &'a str {
    let needle = format!("fn handle_{}(", tool);
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("missing handler for {}", tool));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("handler body start");
    let body_end = matching_brace(source, body_start).expect("handler body end");
    &source[body_start..=body_end]
}

fn typed_action_dispatch_body<'a>(source: &'a str, tool: &str) -> &'a str {
    let marker = "match typed_action";
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing typed action dispatch for {}", tool));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("typed action dispatch body start");
    let body_end = matching_brace(source, body_start).expect("typed action dispatch body end");
    &source[body_start..=body_end]
}

fn matching_brace(source: &str, open_index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HandlerRequirement {
    tool: String,
    action: String,
    parameter: String,
}

fn direct_handler_requirements(source: &str) -> BTreeSet<HandlerRequirement> {
    let helpers = [
        "require_u64_param(",
        "require_u32_param(",
        "require_byte_array_param(",
        "require_nonzero_usize_param(",
        "require_module_name_param(",
        "require_str_param(",
    ];
    let mut requirements = BTreeSet::new();

    for helper in helpers {
        let mut search_from = 0;
        while let Some(relative_start) = source[search_from..].find(helper) {
            let start = search_from + relative_start;
            let open_index = start + helper.len() - 1;
            let Some(close_index) = matching_call_paren(source, open_index) else {
                search_from = open_index + 1;
                continue;
            };
            let call = &source[open_index + 1..close_index];
            let arguments = split_call_arguments(call);
            if arguments.len() >= 4 {
                let (Some(parameter), Some(tool), Some(action)) = (
                    string_literal_argument(arguments[1]),
                    string_literal_argument(arguments[2]),
                    string_literal_argument(arguments[3]),
                ) else {
                    search_from = close_index + 1;
                    continue;
                };
                if is_presence_guarded(source, start, &parameter) {
                    search_from = close_index + 1;
                    continue;
                }
                requirements.insert(HandlerRequirement {
                    parameter,
                    tool,
                    action,
                });
            }
            search_from = close_index + 1;
        }
    }

    requirements
}

fn direct_handler_helper_requirements(source: &str, helper: &str) -> BTreeSet<HandlerRequirement> {
    let mut requirements = BTreeSet::new();
    let mut search_from = 0;

    while let Some(relative_start) = source[search_from..].find(helper) {
        let start = search_from + relative_start;
        let open_index = start + helper.len() - 1;
        let Some(close_index) = matching_call_paren(source, open_index) else {
            search_from = open_index + 1;
            continue;
        };
        let call = &source[open_index + 1..close_index];
        let arguments = split_call_arguments(call);
        if arguments.len() >= 4 {
            let (Some(parameter), Some(tool), Some(action)) = (
                string_literal_argument(arguments[1]),
                string_literal_argument(arguments[2]),
                string_literal_argument(arguments[3]),
            ) else {
                search_from = close_index + 1;
                continue;
            };
            requirements.insert(HandlerRequirement {
                parameter,
                tool,
                action,
            });
        }
        search_from = close_index + 1;
    }

    requirements
}

fn matching_call_paren(source: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in source
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_call_arguments(source: &str) -> Vec<&str> {
    let mut arguments = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for (index, ch) in source.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                arguments.push(source[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }

    arguments.push(source[start..].trim());
    arguments
}

fn string_literal_argument(source: &str) -> Option<String> {
    let source = source.trim();
    if !source.starts_with('"') || !source.ends_with('"') {
        return None;
    }

    let inner = &source[1..source.len().saturating_sub(1)];
    let mut value = String::new();
    let mut escape = false;
    for ch in inner.chars() {
        if escape {
            value.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else {
            value.push(ch);
        }
    }
    Some(value)
}

fn is_presence_guarded(source: &str, call_start: usize, parameter: &str) -> bool {
    let prefix_start = call_start.saturating_sub(240);
    let prefix = &source[prefix_start..call_start];
    [
        format!(".get(\"{}\").is_some()", parameter),
        format!("if let Some(_) = args.get(\"{}\")", parameter),
    ]
    .iter()
    .any(|needle| prefix.contains(needle))
}

fn registry_declares_required_parameter(tool: &str, action: &str, parameter: &str) -> bool {
    registry_parameter_candidates(tool, action, parameter)
        .iter()
        .any(|candidate| {
            crate::mcp::action_registry::required_parameters(tool, action).contains(candidate)
                || crate::mcp::action_registry::conditional_required_parameters(tool, action)
                    .iter()
                    .any(|condition| condition.parameters.contains(candidate))
                || crate::mcp::action_registry::alternative_required_parameters(tool, action)
                    .iter()
                    .any(|alternative| alternative.parameters.contains(candidate))
        })
}

fn registry_declares_minimum_bound(
    tool: &str,
    action: &str,
    parameter: &str,
    minimum: u64,
) -> bool {
    let candidates = registry_parameter_candidates(tool, action, parameter);
    crate::mcp::action_registry::parameter_bounds(tool, action)
        .iter()
        .any(|bound| candidates.contains(&bound.parameter) && bound.minimum.unwrap_or(0) >= minimum)
}

fn registry_declares_maximum_bound(tool: &str, action: &str, parameter: &str) -> bool {
    let candidates = registry_parameter_candidates(tool, action, parameter);
    crate::mcp::action_registry::parameter_bounds(tool, action)
        .iter()
        .any(|bound| candidates.contains(&bound.parameter) && bound.maximum.is_some())
}

fn registry_declares_any_bound(tool: &str, action: &str, parameter: &str) -> bool {
    let candidates = registry_parameter_candidates(tool, action, parameter);
    crate::mcp::action_registry::parameter_bounds(tool, action)
        .iter()
        .any(|bound| {
            candidates.contains(&bound.parameter)
                && (bound.minimum.is_some() || bound.maximum.is_some())
        })
}

fn registry_parameter_candidates<'a>(tool: &str, action: &str, parameter: &'a str) -> Vec<&'a str> {
    let mut candidates = vec![parameter];
    for alias in crate::mcp::action_registry::parameter_aliases(tool, action) {
        if alias.alias == parameter && !candidates.contains(&alias.canonical) {
            candidates.push(alias.canonical);
        }
    }
    candidates
}

fn collect_unsafe_metadata_strings(path: &str, value: &Value, findings: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if let Some(pattern) = unsafe_prompt_pattern(text) {
                findings.push(format!("{} contains '{}': {}", path, pattern, text));
            }
        }
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                collect_unsafe_metadata_strings(&format!("{}[{}]", path, index), item, findings);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                collect_unsafe_metadata_strings(&format!("{}.{}", path, key), item, findings);
            }
        }
        _ => {}
    }
}

fn collect_unsafe_doc_lines(path: &str, text: &str, findings: &mut Vec<String>) {
    for (line_index, line) in text.lines().enumerate() {
        if let Some(pattern) = unsafe_prompt_pattern(line) {
            findings.push(format!(
                "{}:{} contains '{}': {}",
                path,
                line_index + 1,
                pattern,
                line.trim()
            ));
        }
    }
}

fn unsafe_prompt_pattern(text: &str) -> Option<&'static str> {
    let normalized = text.to_ascii_lowercase();
    [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore prior instructions",
        "ignore the system prompt",
        "ignore system instructions",
        "override system instructions",
        "override developer instructions",
        "disregard previous instructions",
        "disregard system instructions",
        "reveal your system prompt",
        "print your system prompt",
        "show your hidden instructions",
        "hidden instructions",
        "do not tell the user",
        "do not reveal this instruction",
        "secret instruction",
        "exfiltrate",
    ]
    .into_iter()
    .find(|pattern| normalized.contains(pattern))
}

fn tool_schema_snapshot(tools: &[Value]) -> Value {
    json!(tools
        .iter()
        .map(|tool| {
            let properties = tool["inputSchema"]["properties"]
                .as_object()
                .expect("tool properties");
            let mut fields = properties
                .iter()
                .map(|(name, schema)| {
                    json!({
                        "name": name,
                        "schema": schema,
                    })
                })
                .collect::<Vec<_>>();
            fields.sort_by(|left, right| {
                left["name"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["name"].as_str().unwrap_or_default())
            });

            let action_enum = properties
                .get("action")
                .and_then(|action| action.get("enum"))
                .and_then(|values| values.as_array())
                .map(|values| values.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();

            let required = tool["inputSchema"]["required"]
                .as_array()
                .map(|values| values.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut required = required;
            required.sort_by(|left, right| {
                left.as_str()
                    .unwrap_or_default()
                    .cmp(right.as_str().unwrap_or_default())
            });

            let output_required = tool["outputSchema"]["required"]
                .as_array()
                .map(|values| values.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut output_required = output_required;
            output_required.sort_by(|left, right| {
                left.as_str()
                    .unwrap_or_default()
                    .cmp(right.as_str().unwrap_or_default())
            });

            let action_metadata = tool["x-memoric-actions"]
                .as_array()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| {
                            json!({
                                "action": entry["action"],
                                "read_only": entry["read_only"],
                                "state_changing": entry["state_changing"],
                                "privileged": entry["privileged"],
                                "kernel": entry["kernel"],
                                "destructive": entry["destructive"],
                                "requires_target": entry["requires_target"],
                                "required_policy": entry["required_policy"],
                                "risk": entry["risk"],
                                "data_classification": entry["data_classification"],
                                "required_parameters": entry["required_parameters"],
                                "required_parameter_hints": entry["required_parameter_hints"],
                                "conditional_required_parameters": entry["conditional_required_parameters"],
                                "alternative_required_parameters": entry["alternative_required_parameters"],
                                "planner_warnings": entry["planner_warnings"],
                                "parameter_aliases": entry["parameter_aliases"],
                                "choice_parameters": entry["choice_parameters"],
                                "array_choice_parameters": entry["array_choice_parameters"],
                                "parameter_bounds": entry["parameter_bounds"],
                                "parser_hints": entry["parser_hints"],
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let data_classification = tool["x-memoric-data-classification"]
                .as_array()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| {
                            json!({
                                "path": entry["path"],
                                "classification": entry["classification"],
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let display = tool["x-memoric-display"].clone();

            json!({
                "name": tool["name"],
                "description": tool["description"],
                "annotations": tool["annotations"],
                "display": display,
                "execution": tool["execution"],
                "input_type": tool["inputSchema"]["type"],
                "fields": fields,
                "required": required,
                "actions": action_enum,
                "action_metadata": action_metadata,
                "data_classification": data_classification,
                "output_schema": tool["outputSchema"],
                "output_required": output_required,
            })
        })
        .collect::<Vec<_>>())
}

fn resource_schema_snapshot(resources: &[Value]) -> Value {
    let mut entries = resources
        .iter()
        .map(|resource| {
            json!({
                "uri": resource["uri"],
                "name": resource["name"],
                "description": resource["description"],
                "mimeType": resource["mimeType"],
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["uri"].as_str().unwrap_or_default())
    });
    json!(entries)
}

fn resource_template_schema_snapshot(templates: &[Value]) -> Value {
    let mut entries = templates
        .iter()
        .map(|template| {
            json!({
                "uriTemplate": template["uriTemplate"],
                "name": template["name"],
                "description": template["description"],
                "mimeType": template["mimeType"],
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left["uriTemplate"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["uriTemplate"].as_str().unwrap_or_default())
    });
    json!(entries)
}

#[test]
fn tool_display_metadata_is_complete_and_ergonomic() {
    let tools = register_tools();
    let mut findings = Vec::new();

    for tool in &tools {
        let name = tool["name"].as_str().expect("tool name");
        let description = tool["description"].as_str().unwrap_or_default();
        let display = &tool["x-memoric-display"];
        let title = display["title"].as_str().unwrap_or_default();
        let icon = display["icon"].as_str().unwrap_or_default();
        let selection_hint = display["selection_hint"].as_str().unwrap_or_default();

        if description.trim().is_empty() || description.chars().count() > 180 {
            findings.push(format!(
                "{} description must be non-empty and <= 180 chars",
                name
            ));
        }
        if title.trim().is_empty() || title.chars().count() > 32 {
            findings.push(format!("{} display title must be 1..32 chars", name));
        }
        if icon.trim().is_empty()
            || !icon
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            findings.push(format!("{} icon hint must be kebab-case ascii", name));
        }
        if selection_hint.trim().is_empty() || selection_hint.chars().count() > 140 {
            findings.push(format!(
                "{} selection hint must be non-empty and <= 140 chars",
                name
            ));
        }
        let normalized_hint = selection_hint.to_ascii_lowercase();
        for forbidden in [
            "ignore ",
            "hidden",
            "bypass policy",
            "disable policy",
            "must always",
            "preferred for everything",
        ] {
            if normalized_hint.contains(forbidden) {
                findings.push(format!(
                    "{} selection hint contains unsafe or ambiguous phrase '{}'",
                    name, forbidden
                ));
            }
        }
        assert_eq!(
            tool["annotations"]["memoric"]["title"], display["title"],
            "{} display title should match annotations.memoric.title",
            name
        );
        assert_eq!(
            tool["annotations"]["memoric"]["selection_hint"], display["selection_hint"],
            "{} display hint should match annotations.memoric.selection_hint",
            name
        );
    }

    assert!(
        findings.is_empty(),
        "tool ergonomics metadata findings:\n{}",
        findings.join("\n")
    );
}

#[test]
fn self_schema_exposes_diagnostics_recovery_actions() {
    let tools = register_tools();
    let self_tool = tools
        .iter()
        .find(|tool| tool["name"] == "self")
        .expect("self tool");
    let actions = self_tool["inputSchema"]["properties"]["action"]["enum"]
        .as_array()
        .expect("action enum");

    assert!(actions.iter().any(|value| value == "doctor"));
    assert!(actions.iter().any(|value| value == "diagnostics"));
    assert!(actions.iter().any(|value| value == "explain_error"));
    assert!(actions.iter().any(|value| value == "capability_diff"));
    assert!(actions.iter().any(|value| value == "next_steps"));
    assert!(self_tool["inputSchema"]["properties"]
        .get("baseline")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("baseline_path")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("recent_task_limit")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("output_dir")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"].get("code").is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("result")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("doctor")
        .is_some());
    let sub_actions = self_tool["inputSchema"]["properties"]["sub_action"]["enum"]
        .as_array()
        .expect("sub_action enum");
    assert!(sub_actions.iter().any(|value| value == "replay"));
    assert!(sub_actions.iter().any(|value| value == "timeline"));
    assert!(self_tool["inputSchema"]["properties"]
        .get("correlation_id")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("artifact_uri")
        .is_some());
    assert!(self_tool["inputSchema"]["properties"]
        .get("audit_path")
        .is_some());
}

#[test]
fn self_diagnostics_returns_operator_bundle_artifact() {
    let result = crate::capability::diagnostics_bundle_json(
        &json!({"limit": 1, "artifact_retention_secs": 60}),
    );

    assert_eq!(result["success"], true);
    assert!(result["artifact"]["uri"]
        .as_str()
        .is_some_and(crate::artifact::is_artifact_uri));
    assert_eq!(result["bundle"]["safe_for_operator_review"], true);

    let payload = tool_success_payload(
        "self",
        &json!({"action": "diagnostics", "artifact_retention_secs": 60}),
        &result,
    );
    let uri = payload["artifacts"][0]["uri"]
        .as_str()
        .expect("artifact uri");
    assert!(crate::artifact::is_artifact_uri(uri));
    let content = crate::artifact::read_resource_content(uri).expect("artifact content");
    let text = content["text"].as_str().expect("artifact text");
    let parsed: Value = serde_json::from_str(text).expect("bundle JSON");
    assert_eq!(parsed["profile"], "operator-safe-diagnostics");
    assert_eq!(parsed["tasks"]["result_payloads_included"], false);
    assert!(parsed["policy"]["hash"]["sha256"].as_str().is_some());
    assert!(parsed["catalog"]["sha256"].as_str().is_some());
    assert!(parsed["docs"]["compatibility"]["sha256"].as_str().is_some());
    assert!(!text.contains("\"result\":"));
    assert!(!text.contains("progress_token"));

    let _ = crate::artifact::forget(uri);
}

#[test]
fn memory_schema_and_guide_expose_diagnostics() {
    let tools = register_tools();
    let memory_tool = tools
        .iter()
        .find(|tool| tool["name"] == "memory")
        .expect("memory tool");
    let actions = memory_tool["inputSchema"]["properties"]["action"]["enum"]
        .as_array()
        .expect("memory action enum");

    assert!(actions.iter().any(|value| value == "diagnostics"));
    assert!(memory_tool["inputSchema"]["properties"]
        .get("entropy_sample_bytes")
        .is_some());

    let metadata = memory_tool["x-memoric-actions"].as_array().unwrap();
    let diagnostics = metadata
        .iter()
        .find(|entry| entry["action"] == "diagnostics")
        .expect("diagnostics metadata");
    assert_eq!(diagnostics["read_only"], true);
    assert_eq!(diagnostics["required_policy"], "research");

    let guide =
        crate::mcp::guide::memoric_guide(&json!({"domain": "memory"})).expect("memory guide");
    assert!(guide["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "diagnostics"));
    assert_eq!(
            guide["scan_mode_details"]["diagnostics"],
            "Read-only defensive memory profile: layout, modules, handles, suspicious regions, and bounded entropy without returning raw bytes"
        );
}

#[test]
fn memory_schema_and_handler_expose_typed_read_write_contract() {
    let tools = register_tools();
    let memory_tool = tools
        .iter()
        .find(|tool| tool["name"] == "memory")
        .expect("memory tool");
    let actions = memory_tool["inputSchema"]["properties"]["action"]["enum"]
        .as_array()
        .expect("memory action enum");

    assert!(actions.iter().any(|value| value == "typed_read"));
    assert!(actions.iter().any(|value| value == "typed_write"));
    assert!(memory_tool["inputSchema"]["properties"]
        .get("type")
        .is_some());
    assert!(memory_tool["inputSchema"]["properties"]
        .get("endian")
        .is_some());
    assert!(memory_tool["inputSchema"]["properties"]
        .get("allow_unaligned")
        .is_some());

    let metadata = memory_tool["x-memoric-actions"].as_array().unwrap();
    let typed_read = metadata
        .iter()
        .find(|entry| entry["action"] == "typed_read")
        .expect("typed_read metadata");
    assert_eq!(typed_read["read_only"], true);
    assert_eq!(typed_read["state_changing"], false);

    let typed_write = metadata
        .iter()
        .find(|entry| entry["action"] == "typed_write")
        .expect("typed_write metadata");
    assert_eq!(typed_write["read_only"], false);
    assert_eq!(typed_write["state_changing"], true);

    let mut buffer = [0u8; 8];
    let address = buffer.as_mut_ptr() as u64;
    crate::mcp::memory_tool::handle_memory(&json!({
        "action": "typed_write",
        "pid": std::process::id(),
        "address": address,
        "type": "u32",
        "endian": "big",
        "value": 0xAABBCCDDu64
    }))
    .expect("typed_write should update current process buffer");
    assert_eq!(&buffer[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);

    let read = crate::mcp::memory_tool::handle_memory(&json!({
        "action": "typed_read",
        "pid": std::process::id(),
        "address": address,
        "type": "u32",
        "endian": "big"
    }))
    .expect("typed_read should read current process buffer");
    assert_eq!(read["value"], json!(0xAABBCCDDu64));
    assert_eq!(read["alignment"]["aligned"], true);

    let guide =
        crate::mcp::guide::memoric_guide(&json!({"domain": "memory"})).expect("memory guide");
    assert!(guide["scan_mode_details"]["typed_read"]
        .as_str()
        .unwrap_or_default()
        .contains("endian"));
}

#[test]
fn kernel_status_is_read_only_probe_and_exposed_in_schema() {
    let tools = register_tools();
    let kernel_tool = tools
        .iter()
        .find(|tool| tool["name"] == "kernel")
        .expect("kernel tool");
    let actions = kernel_tool["inputSchema"]["properties"]["action"]["enum"]
        .as_array()
        .expect("kernel action enum");

    assert!(actions.iter().any(|value| value == "status"));

    let metadata = kernel_tool["x-memoric-actions"].as_array().unwrap();
    let status = metadata
        .iter()
        .find(|entry| entry["action"] == "status")
        .expect("kernel status metadata");
    assert_eq!(status["read_only"], true);
    assert_eq!(status["state_changing"], false);
    assert_eq!(status["kernel"], true);

    let result =
        crate::mcp::kernel_tool::handle_kernel(&json!({"action": "status", "build_number": 26100}))
            .expect("kernel status should be read-only");
    assert_eq!(result["success"], true);
    assert_eq!(result["probe_only"], true);
    assert_eq!(result["driver_auto_installed"], false);
    assert_eq!(result["offset_profile"]["build_number"], 26100);
    assert_eq!(
        result["offset_profile"]["callback_offsets"]["known_build"],
        true
    );
    assert!(result["offset_profile"]["supported_profiles"]
        .as_array()
        .is_some_and(|profiles| !profiles.is_empty()));

    let guide =
        crate::mcp::guide::memoric_guide(&json!({"domain": "kernel"})).expect("kernel guide");
    assert!(guide["readiness_flow"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step
            .as_str()
            .unwrap_or_default()
            .contains("kernel(action='status')")));
}

#[test]
fn orchestrate_execute_dry_run_uses_preview_path() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");
    let result = call_tool(
        "orchestrate",
        json!({
            "action": "execute",
            "pid": 999999,
            "dry_run": true
        }),
    )
    .expect("orchestrate dry run preview should be allowed");

    assert_eq!(result["success"], true);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["would_execute"], false);
    assert_eq!(result["tool"], "orchestrate");
    assert_eq!(result["action"], "execute");
    assert!(result["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "workflow_task"));
    assert!(result["required_privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "step-dependent privileges"));
    assert_eq!(
        result["message"],
        "dry_run=true returned a preview and skipped the live handler"
    );
    assert!(result["side_effects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "multi-step workflow side effects"));
}

#[test]
fn orchestrate_schema_and_templates_expose_lab_validation() {
    let tools = register_tools();
    let orchestrate = tools
        .iter()
        .find(|tool| tool["name"] == "orchestrate")
        .expect("orchestrate tool");
    let properties = &orchestrate["inputSchema"]["properties"];
    assert!(properties.get("template").is_some());
    assert!(properties.get("benign_pid").is_some());
    assert!(properties.get("marker_address").is_some());
    assert!(properties.get("counter_address").is_some());

    let templates = crate::mcp::orchestrate::handle_orchestrate(&json!({"action": "templates"}))
        .expect("templates");
    assert!(templates["templates"]
        .as_array()
        .unwrap()
        .iter()
        .any(|template| template["id"] == "lab_validation"));

    let guide = crate::mcp::guide::memoric_guide(&json!({"domain": "orchestrate"})).expect("guide");
    assert!(guide["new_actions"]["templates"]
        .as_str()
        .unwrap()
        .contains("lab_validation"));
}

#[test]
fn success_payload_has_common_envelope() {
    let payload = tool_success_payload(
        "self",
        &json!({"action": "doctor", "request_id": "abc"}),
        &json!({"message": "doctor completed"}),
    );

    assert_eq!(payload["success"], true);
    assert_eq!(payload["code"], "ok");
    assert_eq!(payload["context"]["tool"], "self");
    assert_eq!(payload["context"]["action"], "doctor");
    assert_eq!(payload["context"]["request_id"], "abc");
    assert_eq!(payload["integrity"]["algorithm"], "sha256");
    assert!(payload["integrity"]["result_sha256"].as_str().is_some());
    assert_eq!(payload["metadata"]["redaction"]["profile"], "standard");
    assert_eq!(
        payload["metadata"]["data_classification"]["redaction"],
        "classification-aware"
    );
}

#[test]
fn strict_redaction_removes_raw_bytes_from_success_payload() {
    let payload = tool_success_payload(
        "memory",
        &json!({"action": "read", "redaction": "strict"}),
        &json!({"message": "read ok", "bytes": [1, 2, 3, 4], "hex": "01020304"}),
    );

    assert_eq!(payload["success"], true);
    assert_eq!(payload["data"]["bytes"]["redacted"], true);
    assert_eq!(payload["data"]["bytes"]["classification"], "raw-memory");
    assert_eq!(payload["data"]["hex"]["redacted"], true);
    assert_eq!(payload["data"]["hex"]["classification"], "raw-memory");
    assert_eq!(payload["metadata"]["redaction"]["profile"], "strict");
}

#[test]
fn strict_redaction_uses_schema_classification_for_non_obvious_fields() {
    let payload = tool_success_payload(
        "memory",
        &json!({"action": "scan", "redaction": "strict"}),
        &json!({
            "message": "scan ok",
            "results": [
                {
                    "address": "0x1000",
                    "matched_hex": "DE AD BE EF",
                    "context_hex": "00 DE AD BE EF 00"
                }
            ]
        }),
    );

    assert_eq!(payload["success"], true);
    assert_eq!(
        payload["data"]["results"][0]["matched_hex"]["classification"],
        "raw-memory"
    );
    assert_eq!(
        payload["data"]["results"][0]["context_hex"]["classification"],
        "raw-memory"
    );
}

#[test]
fn tool_error_payload_uses_shared_taxonomy() {
    let payload = tool_error_payload(
        "memory",
        &json!({
            "action": "write",
            "pid": 1234,
            "address": "0x1000"
        }),
        "policy_denied: memory(action='write') blocked by policy",
    );

    assert_eq!(payload["success"], false);
    assert_eq!(payload["code"], "policy_denied");
    assert_eq!(payload["context"]["tool"], "memory");
    assert_eq!(payload["context"]["action"], "write");
    assert_eq!(payload["context"]["pid"], 1234);
    assert_eq!(payload["context"]["address"], "0x0000000000001000");
    assert!(payload["hint"].as_str().unwrap().contains("policy"));
}

#[test]
fn explain_error_uses_shared_taxonomy_next_steps() {
    let timeout = call_tool(
        "self",
        json!({
            "action": "explain_error",
            "error": "timeout: operation exceeded timeout_ms=5"
        }),
    )
    .expect("explain timeout");

    assert_eq!(timeout["code"], "timeout");
    assert!(timeout["next_diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("timeout_ms")));

    let driver = call_tool(
        "self",
        json!({
            "action": "explain_error",
            "error": "driver_unavailable: memoric.sys device is not reachable"
        }),
    )
    .expect("explain driver");

    assert_eq!(driver["code"], "driver_unavailable");
    assert!(driver["next_diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("driver readiness")));
}

#[test]
fn dry_run_state_changing_action_returns_preview_without_policy_error() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");
    let result = call_tool(
        "memory",
        json!({
            "action": "write",
            "pid": 999999,
            "address": "0x1000",
            "bytes": [1, 2, 3],
            "dry_run": true
        }),
    )
    .expect("dry run preview should be allowed");

    assert_eq!(result["success"], true);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["would_execute"], false);
    assert_eq!(result["required_policy"], "lab-write");
    assert!(result["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "process"
            && value["access"]
                .as_str()
                .unwrap_or_default()
                .contains("PROCESS_VM_WRITE")));
    assert!(result["required_privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "target_allowlist"));
}

#[test]
fn dry_run_preview_includes_structured_rollback_metadata() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");
    let result = call_tool(
        "memory",
        json!({
            "action": "protect",
            "pid": 999999,
            "address": "0x1000",
            "size": 4096,
            "dry_run": true
        }),
    )
    .expect("dry run preview should be allowed");

    assert_eq!(result["success"], true);
    assert_eq!(result["dry_run"], true);
    assert!(result["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "memory_region" && value["access"] == "change protection"));
    assert!(result["required_privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "process_vm_write_access"));
    assert_eq!(result["rollback"]["available"], "partial");
    assert_eq!(
        result["rollback"]["strategy"],
        "restore_previous_protection"
    );
    assert!(result["rollback"]["captured_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "old_protection"));
    assert!(result["rollback"]["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("restored"));
}

#[test]
fn dry_run_preview_describes_driver_load_handles_and_privileges() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");
    let result = call_tool(
        "kernel",
        json!({
            "action": "driver_load",
            "driver_path": "C:\\lab\\memoric.sys",
            "service_name": "MemoricLab",
            "dry_run": true
        }),
    )
    .expect("kernel driver_load dry run preview should be allowed");

    assert_eq!(result["success"], true);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["required_policy"], "kernel");
    assert!(result["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "service"));
    assert!(result["required_privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "SeLoadDriverPrivilege"));
    assert!(result["side_effects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "kernel driver, kernel memory, or system state mutation"));
}

#[test]
fn dry_run_preview_describes_less_common_state_changing_surfaces() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");

    let payload = call_tool(
        "payload",
        json!({
            "action": "cleanup",
            "pid": 999999,
            "dry_run": true
        }),
    )
    .expect("payload cleanup dry run should return preview");
    assert_eq!(payload["dry_run"], true);
    assert!(payload["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "memory_region"));
    assert_eq!(payload["rollback"]["available"], false);
    assert_eq!(payload["rollback"]["reason"], "irreversible_cleanup");

    let detect = call_tool(
        "detect",
        json!({
            "action": "edr_suspend",
            "target": "ExampleEDR",
            "dry_run": true
        }),
    )
    .expect("detect edr_suspend dry run should return preview");
    assert_eq!(detect["dry_run"], true);
    assert!(detect["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "process"
            && value["access"]
                .as_str()
                .unwrap_or_default()
                .contains("PROCESS_SUSPEND_RESUME")));
    assert_eq!(detect["rollback"]["strategy"], "resume_suspended_processes");
    assert!(detect["required_privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "process_suspend_resume_access"));
}

#[test]
fn dry_run_preview_describes_hook_and_hijack_rollback_precision() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");

    let hook = call_tool(
        "hook",
        json!({
            "action": "detour",
            "pid": 999999,
            "hooks": [{
                "target_address": "0x1000",
                "hook_address": "0x2000"
            }],
            "dry_run": true
        }),
    )
    .expect("hook detour dry run should return preview");
    assert_eq!(hook["dry_run"], true);
    assert!(hook["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "memory_region"
            && value["access"]
                .as_str()
                .unwrap_or_default()
                .contains("code patch")));
    assert_eq!(
        hook["rollback"]["strategy"],
        "restore_original_bytes_or_pointer"
    );
    assert!(hook["rollback"]["captured_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "hooks"));

    let hijack = call_tool(
        "inject",
        json!({
            "action": "hijack_redirect",
            "tid": 999999,
            "dry_run": true
        }),
    )
    .expect("inject hijack_redirect dry run should return preview");
    assert_eq!(hijack["dry_run"], true);
    assert!(hijack["planned_handles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["kind"] == "thread"));
    assert_eq!(hijack["rollback"]["strategy"], "restore_thread_context");
    assert!(hijack["rollback"]["captured_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "original_context"));
}

#[test]
fn dry_run_preview_describes_kernel_callback_and_hook_rollback_precision() {
    let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var("MEMORIC_POLICY");

    let callback = call_tool(
        "kernel",
        json!({
            "action": "driver_callback_remove",
            "callback_type": "process",
            "index": 2,
            "dry_run": true
        }),
    )
    .expect("kernel callback remove dry run should return preview");
    assert_eq!(callback["dry_run"], true);
    assert_eq!(
        callback["rollback"]["strategy"],
        "restore_removed_callback_pointer"
    );
    assert!(callback["rollback"]["captured_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "callback_address"));

    let infhook = call_tool(
        "kernel",
        json!({
            "action": "driver_infinity_hook",
            "infhook_action": "enable",
            "syscall_number": 80,
            "handler_address": "0x180012340",
            "dry_run": true
        }),
    )
    .expect("kernel infinity hook dry run should return preview");
    assert_eq!(infhook["dry_run"], true);
    assert_eq!(infhook["rollback"]["strategy"], "disable_infinity_hook");
    assert!(infhook["rollback"]["captured_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "original_handler"));
}
