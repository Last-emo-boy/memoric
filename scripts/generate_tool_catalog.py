#!/usr/bin/env python3
"""Generate caller-facing tool reference docs from the runtime MCP surface.

This script does not parse Rust source directly. It starts the local memoric binary
through `cargo run --quiet`, performs a minimal MCP bootstrap, and captures the
runtime `tools/list` and `resources/list` responses as the source of truth for
generated docs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import hashlib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
CATALOG_JSON = DOCS_DIR / "tool-catalog.json"
REFERENCE_MD = DOCS_DIR / "tool-reference.md"
SERVER_MANIFEST_JSON = DOCS_DIR / "server-manifest.json"
GENERATED_MARKER = "deterministic-runtime-tools-list"
MANIFEST_MARKER = "deterministic-runtime-server-manifest"


def type_repr(schema: dict[str, Any]) -> str:
    value = schema.get("type")
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    if value is None:
        for compound_key in ("oneOf", "anyOf"):
            alternatives = schema.get(compound_key)
            if isinstance(alternatives, list) and alternatives:
                rendered = [
                    type_repr(alternative)
                    for alternative in alternatives
                    if isinstance(alternative, dict)
                ]
                rendered = [item for item in rendered if item and item != "any"]
                if rendered:
                    return " | ".join(dict.fromkeys(rendered))
        return "any"
    return str(value)


def format_enum(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return ", ".join(str(value) for value in values)


def format_bounds(schema: dict[str, Any]) -> str:
    parts: list[str] = []
    if "minimum" in schema:
        parts.append(f">= {schema.get('minimum')}")
    if "maximum" in schema:
        parts.append(f"<= {schema.get('maximum')}")
    return "; ".join(parts)


def format_parameter_aliases(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    aliases: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        alias = value.get("alias")
        canonical = value.get("canonical")
        if alias and canonical:
            aliases.append(f"`{alias}` -> `{canonical}`")
    return "; ".join(aliases)


def format_choice_parameters(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    choices: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        parameter = value.get("parameter")
        raw_values = value.get("values")
        if not parameter or not isinstance(raw_values, list):
            continue
        joined = ", ".join(f"`{item}`" for item in raw_values)
        choices.append(f"`{parameter}`: {joined}")
    return "; ".join(choices)


def format_array_choice_parameters(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    choices: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        parameter = value.get("parameter")
        raw_values = value.get("values")
        if not parameter or not isinstance(raw_values, list):
            continue
        joined = ", ".join(f"`{item}`" for item in raw_values)
        choices.append(f"`{parameter}[]`: {joined}")
    return "; ".join(choices)


def format_parameter_bounds(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    bounds: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        parameter = value.get("parameter")
        if not parameter:
            continue
        parts: list[str] = []
        if value.get("minimum") is not None:
            parts.append(f">= `{value.get('minimum')}`")
        if value.get("maximum") is not None:
            parts.append(f"<= `{value.get('maximum')}`")
        if parts:
            bounds.append(f"`{parameter}`: {'; '.join(parts)}")
    return "; ".join(bounds)


def format_parser_hints(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    hints: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        parameter = value.get("parameter")
        parser = value.get("parser")
        if not parameter or not parser:
            continue
        parts = [f"`{parameter}`: `{parser}`"]
        aliases = value.get("aliases")
        if isinstance(aliases, list) and aliases:
            parts.append("aliases " + ", ".join(f"`{item}`" for item in aliases))
        choices = value.get("choices")
        if isinstance(choices, list) and choices:
            parts.append("choices " + ", ".join(f"`{item}`" for item in choices))
        bounds: list[str] = []
        if value.get("minimum") is not None:
            bounds.append(f">= `{value.get('minimum')}`")
        if value.get("maximum") is not None:
            bounds.append(f"<= `{value.get('maximum')}`")
        if bounds:
            parts.append("; ".join(bounds))
        item_schema = value.get("object_item_schema")
        if isinstance(item_schema, dict):
            required = item_schema.get("required")
            if isinstance(required, list) and required:
                parts.append("item required " + ", ".join(f"`{item}`" for item in required))
            properties = item_schema.get("properties")
            if isinstance(properties, dict) and properties:
                parts.append(
                    "item fields "
                    + ", ".join(f"`{name}`" for name in sorted(properties.keys()))
                )
        hints.append(" ".join(parts))
    return "; ".join(hints)


def format_required_parameters(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return ", ".join(f"`{value}`" for value in values)


def format_conditional_required_parameters(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    conditions: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        parameters = value.get("parameters")
        if not isinstance(parameters, list) or not parameters:
            continue

        parts = [", ".join(f"`{item}`" for item in parameters)]
        when_parameter = value.get("when_parameter")
        when_values = value.get("when_values")
        if when_parameter and isinstance(when_values, list) and when_values:
            joined = ", ".join(f"`{item}`" for item in when_values)
            parts.append(f"when `{when_parameter}` is {joined}")
        elif when_parameter:
            parts.append(f"when `{when_parameter}` condition applies")
        if value.get("default_applies") is True:
            parts.append("default applies")
        description = value.get("description")
        if isinstance(description, str) and description:
            parts.append(description)
        conditions.append(" ".join(parts))
    return "; ".join(conditions)


def format_alternative_required_parameters(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    alternatives: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        parameters = value.get("parameters")
        if not isinstance(parameters, list) or not parameters:
            continue

        parts = [" or ".join(f"`{item}`" for item in parameters)]
        when_parameter = value.get("when_parameter")
        when_values = value.get("when_values")
        if when_parameter and isinstance(when_values, list) and when_values:
            joined = ", ".join(f"`{item}`" for item in when_values)
            parts.append(f"when `{when_parameter}` is {joined}")
        elif when_parameter:
            parts.append(f"when `{when_parameter}` condition applies")
        if value.get("default_applies") is True:
            parts.append("default applies")
        description = value.get("description")
        if isinstance(description, str) and description:
            parts.append(description)
        alternatives.append(" ".join(parts))
    return "; ".join(alternatives)


def format_planner_warnings(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    warnings: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        message = value.get("message")
        if not isinstance(message, str) or not message:
            continue
        parts = [message]
        condition = value.get("condition")
        parameter = value.get("parameter")
        if condition:
            parts.append(f"condition `{condition}`")
        if parameter:
            parts.append(f"parameter `{parameter}`")
        unless_parameter = value.get("unless_parameter")
        unless_values = value.get("unless_values")
        if unless_parameter and isinstance(unless_values, list) and unless_values:
            joined = ", ".join(f"`{item}`" for item in unless_values)
            parts.append(f"unless `{unless_parameter}` is {joined}")
        warnings.append(" ".join(parts))
    return "; ".join(warnings)


def format_required_privileges(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    privileges: list[str] = []
    for value in values:
        if isinstance(value, str):
            privileges.append(f"`{value}`")
            continue
        if not isinstance(value, dict):
            continue
        privilege = value.get("privilege")
        if not isinstance(privilege, str) or not privilege:
            continue
        description = value.get("description")
        if isinstance(description, str) and description:
            privileges.append(f"`{privilege}`: {description}")
        else:
            privileges.append(f"`{privilege}`")
    return "; ".join(privileges)


def format_side_effects(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    effects: list[str] = []
    for value in values:
        if isinstance(value, str):
            effects.append(f"`{value}`")
            continue
        if not isinstance(value, dict):
            continue
        effect = value.get("effect")
        if not isinstance(effect, str) or not effect:
            continue
        description = value.get("description")
        if isinstance(description, str) and description:
            effects.append(f"`{effect}`: {description}")
        else:
            effects.append(f"`{effect}`")
    return "; ".join(effects)


def format_planned_handles(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""

    handles: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        kind = value.get("kind")
        if not isinstance(kind, str) or not kind:
            continue
        target = value.get("target")
        access = value.get("access")
        parts = [f"`{kind}`"]
        if isinstance(target, str) and target:
            parts.append(target)
        if isinstance(access, str) and access:
            parts.append(f"access `{access}`")
        handles.append(": ".join([parts[0], " ".join(parts[1:])]) if len(parts) > 1 else parts[0])
    return "; ".join(handles)


def format_rollback_preview(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return ""

    parts: list[str] = []
    if "available" in value:
        parts.append(f"available `{value.get('available')}`")
    strategy = value.get("strategy")
    if isinstance(strategy, str) and strategy:
        parts.append(f"strategy `{strategy}`")
    captured_fields = value.get("captured_fields")
    if isinstance(captured_fields, list) and captured_fields:
        parts.append("captures " + ", ".join(f"`{item}`" for item in captured_fields))
    reason = value.get("reason")
    if isinstance(reason, str) and reason:
        parts.append(f"reason `{reason}`")
    detail = value.get("detail")
    if isinstance(detail, str) and detail:
        parts.append(detail)
    return "; ".join(parts)


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def fetch_runtime_catalog() -> dict[str, Any]:
    requests = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "resources/templates/list", "params": {}}),
            "",
        ]
    )

    env = os.environ.copy()
    env.setdefault("RUST_LOG", "error")

    result = subprocess.run(
        ["cargo", "run", "--quiet"],
        cwd=ROOT,
        input=requests,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=300,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Failed to query runtime tools/list.\n"
            f"exit={result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    responses: list[dict[str, Any]] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            responses.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    initialize: dict[str, Any] | None = None
    tools: list[dict[str, Any]] | None = None
    resources: list[dict[str, Any]] | None = None
    resource_templates: list[dict[str, Any]] | None = None

    for response in responses:
        if response.get("id") == 1:
            value = response.get("result")
            if isinstance(value, dict):
                initialize = value
        elif response.get("id") == 2:
            value = response.get("result", {}).get("tools")
            if isinstance(value, list):
                tools = value
        elif response.get("id") == 3:
            value = response.get("result", {}).get("resources")
            if isinstance(value, list):
                resources = value
        elif response.get("id") == 4:
            value = response.get("result", {}).get("resourceTemplates")
            if isinstance(value, list):
                resource_templates = value

    if (
        initialize is not None
        and tools is not None
        and resources is not None
        and resource_templates is not None
    ):
        return {
            "initialize": initialize,
            "tools": tools,
            "resources": resources,
            "resourceTemplates": resource_templates,
        }

    raise RuntimeError(
        "Runtime initialize, tools/list, resources/list, or resources/templates/list response not found.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def read_package_metadata() -> dict[str, str]:
    metadata: dict[str, str] = {}
    in_package = False
    for raw_line in (ROOT / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_package = line == "[package]"
            continue
        if not in_package or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        value = raw_value.strip().strip('"')
        if key in {"name", "version", "description", "license"}:
            metadata[key] = value
    return metadata


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def metadata_coverage() -> dict[str, list[str]]:
    return {
        "tools": [
            "annotations",
            "_meta.ui",
            "execution",
            "inputSchema.properties",
            "inputSchema.required",
            "inputSchema.properties.minimum",
            "inputSchema.properties.maximum",
            "outputSchema",
            "x-memoric-actions",
            "x-memoric-data-classification",
            "x-memoric-display",
        ],
        "tasks": [
            "execution.taskSupport",
            "execution.memoric.background_eligibility",
            "inputSchema.properties.as_task",
            "inputSchema.properties.task_id",
        ],
        "actions": [
            "read_only",
            "state_changing",
            "privileged",
            "kernel",
            "destructive",
            "requires_target",
            "risk",
            "required_policy",
            "typed_action_ref",
            "descriptor_backed_action_ref",
            "registry_source",
            "data_classification",
            "required_parameters",
            "required_parameter_hints",
            "conditional_required_parameters",
            "alternative_required_parameters",
            "planner_warnings",
            "required_privileges",
            "side_effects",
            "planned_handles",
            "rollback",
            "parameter_aliases",
            "choice_parameters",
            "array_choice_parameters",
            "parameter_bounds",
            "parser_hints",
        ],
        "display": [
            "title",
            "icon",
            "selection_hint",
        ],
        "appResources": [
            "uri",
            "name",
            "description",
            "mimeType",
            "_meta.ui",
        ],
        "resourceTemplates": [
            "uriTemplate",
            "name",
            "description",
            "mimeType",
            "_meta.ui",
        ],
    }


def write_catalog_json(
    tools: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    resource_templates: list[dict[str, Any]],
) -> None:
    payload = {
        "generatedAt": GENERATED_MARKER,
        "generatedFrom": "runtime initialize, tools/list, resources/list, resources/templates/list via cargo run --quiet",
        "metadataCoverage": metadata_coverage(),
        "toolCount": len(tools),
        "resourceCount": len(resources),
        "resourceTemplateCount": len(resource_templates),
        "tools": tools,
        "resources": resources,
        "resourceTemplates": resource_templates,
    }
    CATALOG_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_server_manifest(
    initialize: dict[str, Any],
    tools: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    resource_templates: list[dict[str, Any]],
) -> None:
    catalog_content = CATALOG_JSON.read_bytes()
    package = read_package_metadata()
    server_info = initialize.get("serverInfo", {}) if isinstance(initialize, dict) else {}
    protocol_version = initialize.get("protocolVersion")
    manifest = {
        "generatedAt": MANIFEST_MARKER,
        "generatedFrom": "runtime initialize, tools/list, resources/list via cargo run --quiet plus Cargo.toml package metadata",
        "machineStateIncluded": False,
        "server": {
            "name": server_info.get("name", package.get("name", "memoric")),
            "package": package.get("name", "memoric"),
            "version": server_info.get("version", package.get("version", "")),
            "description": package.get("description", ""),
            "license": package.get("license", ""),
            "protocolVersion": protocol_version,
        },
        "capabilities": initialize.get("capabilities", {}),
        "counts": {
            "tools": len(tools),
            "resources": len(resources),
            "resourceTemplates": len(resource_templates),
        },
        "toolCatalog": {
            "path": "docs/tool-catalog.json",
            "generatedAt": GENERATED_MARKER,
            "sha256": sha256_bytes(catalog_content),
            "toolCount": len(tools),
            "resourceCount": len(resources),
            "resourceTemplateCount": len(resource_templates),
        },
        "resources": [
            {
                "uri": resource.get("uri"),
                "name": resource.get("name"),
                "description": resource.get("description"),
                "mimeType": resource.get("mimeType"),
            }
            for resource in resources
        ],
        "resourceTemplates": [
            {
                "uriTemplate": template.get("uriTemplate"),
                "name": template.get("name"),
                "description": template.get("description"),
                "mimeType": template.get("mimeType"),
            }
            for template in resource_templates
        ],
        "docs": [
            {"path": "docs/invocation-contract.md", "kind": "contract"},
            {"path": "docs/compatibility.md", "kind": "compatibility"},
            {"path": "docs/tool-reference.md", "kind": "tool-reference"},
            {"path": "docs/tool-catalog.json", "kind": "tool-catalog"},
            {"path": "docs/server-manifest.json", "kind": "server-manifest"},
        ],
        "provenance": {
            "source": "generated",
            "deterministic": True,
            "runtimeRequests": [
                "initialize",
                "tools/list",
                "resources/list",
                "resources/templates/list",
            ],
        },
    }
    SERVER_MANIFEST_JSON.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def write_reference_markdown(
    tools: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    resource_templates: list[dict[str, Any]],
) -> None:
    lines: list[str] = []

    lines.append("# Memoric Tool Reference")
    lines.append("")
    lines.append("Generated from the runtime `tools/list`, `resources/list`, and `resources/templates/list` surfaces. Do not hand-edit this file.")
    lines.append("")
    lines.append(f"- Generated: `{GENERATED_MARKER}`")
    lines.append("- Source: `cargo run --quiet` -> `initialize` -> `tools/list` + `resources/list` + `resources/templates/list`")
    lines.append(f"- Tool count: `{len(tools)}`")
    lines.append(f"- Resource count: `{len(resources)}`")
    lines.append(f"- Resource template count: `{len(resource_templates)}`")
    lines.append("- Drift gate coverage: `annotations`, `_meta.ui.resourceUri`, display metadata, `execution`, action policy traits, parameter aliases, redaction classification, input/output schemas, resources, and resource templates")
    lines.append("")
    lines.append("## Tool Index")
    lines.append("")
    for tool in tools:
        name = str(tool.get("name", "unknown"))
        description = str(tool.get("description", "")).strip()
        lines.append(f"- [`{name}`](#{name})")
        if description:
            lines.append(f"  - {description}")
    lines.append("")

    if resources:
        lines.append("## Resource Index")
        lines.append("")
        lines.append("| URI | Name | MIME Type | Description |")
        lines.append("|---|---|---|---|")
        for resource in resources:
            uri = markdown_escape(str(resource.get("uri", "")))
            name = markdown_escape(str(resource.get("name", "")))
            mime_type = markdown_escape(str(resource.get("mimeType", "")))
            description = markdown_escape(str(resource.get("description", "")))
            lines.append(f"| `{uri}` | {name} | `{mime_type}` | {description} |")
        lines.append("")

    if resource_templates:
        lines.append("## Resource Template Index")
        lines.append("")
        lines.append("| URI Template | Name | MIME Type | Description |")
        lines.append("|---|---|---|---|")
        for template in resource_templates:
            uri_template = markdown_escape(str(template.get("uriTemplate", "")))
            name = markdown_escape(str(template.get("name", "")))
            mime_type = markdown_escape(str(template.get("mimeType", "")))
            description = markdown_escape(str(template.get("description", "")))
            lines.append(f"| `{uri_template}` | {name} | `{mime_type}` | {description} |")
        lines.append("")

    for tool in tools:
        name = str(tool.get("name", "unknown"))
        description = str(tool.get("description", "")).strip()
        schema = tool.get("inputSchema", {}) or {}
        output_schema = tool.get("outputSchema", {}) or {}
        annotations = tool.get("annotations", {}) or {}
        execution = tool.get("execution", {}) or {}
        meta = tool.get("_meta", {}) or {}
        display = tool.get("x-memoric-display", {}) or {}
        action_metadata = tool.get("x-memoric-actions", []) or []
        data_classification = tool.get("x-memoric-data-classification", []) or []
        properties = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        action_enum = (
            properties.get("action", {}).get("enum")
            if isinstance(properties.get("action"), dict)
            else None
        )

        lines.append(f"## {name}")
        lines.append("")
        if description:
            lines.append(description)
            lines.append("")

        lines.append(f"- Property count: `{len(properties)}`")
        lines.append(f"- Required fields: `{', '.join(sorted(required)) if required else 'none'}`")
        if annotations:
            mem_meta = annotations.get("memoric", {}) if isinstance(annotations, dict) else {}
            lines.append(f"- Read-only hint: `{annotations.get('readOnlyHint', '')}`")
            lines.append(f"- Destructive hint: `{annotations.get('destructiveHint', '')}`")
            if isinstance(mem_meta, dict) and mem_meta:
                lines.append(f"- Highest policy: `{mem_meta.get('highest_required_policy', '')}`")
        if isinstance(display, dict) and display:
            lines.append(f"- Display title: `{display.get('title', '')}`")
            lines.append(f"- Icon hint: `{display.get('icon', '')}`")
            lines.append(f"- Selection hint: {markdown_escape(str(display.get('selection_hint', '')))}")
        if output_schema:
            output_required = output_schema.get("required", []) or []
            lines.append(f"- Output required fields: `{', '.join(output_required) if output_required else 'none'}`")
        if isinstance(execution, dict) and execution:
            lines.append(f"- Task support: `{execution.get('taskSupport', '')}`")
        if isinstance(meta, dict):
            ui_meta = meta.get("ui", {}) or {}
            if isinstance(ui_meta, dict) and ui_meta.get("resourceUri"):
                lines.append(f"- UI resource: `{ui_meta.get('resourceUri')}`")
                lines.append(f"- UI visibility: `{ui_meta.get('visibility', '')}`")
                if ui_meta.get("htmlCapable") is not None:
                    lines.append(f"- UI HTML capable: `{ui_meta.get('htmlCapable')}`")
        if isinstance(data_classification, list) and data_classification:
            class_names = sorted(
                {
                    str(entry.get("classification", ""))
                    for entry in data_classification
                    if isinstance(entry, dict) and entry.get("classification")
                }
            )
            lines.append(f"- Data classifications: `{', '.join(class_names)}`")
        lines.append("")

        if isinstance(action_enum, list) and action_enum:
            lines.append("### Actions")
            lines.append("")
            lines.append(", ".join(f"`{value}`" for value in action_enum))
            lines.append("")

        if isinstance(action_metadata, list) and action_metadata:
            lines.append("### Action Metadata")
            lines.append("")
            lines.append("| Action | Read-only | State-changing | Privileged | Kernel | Destructive | Risk | Required Policy | Required Parameters | Required Parameter Hints | Conditional Required | Alternative Required | Planner Warnings | Required Privileges | Side Effects | Planned Handles | Rollback | Parameter Aliases | Choice Parameters | Array Choice Parameters | Parameter Bounds | Parser Hints | Data Classes |")
            lines.append("|---|---:|---:|---:|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
            for entry in action_metadata:
                if not isinstance(entry, dict):
                    continue
                entry_classes = ""
                entry_classification = entry.get("data_classification", {})
                if isinstance(entry_classification, dict):
                    output_classes = entry_classification.get("output", [])
                    if isinstance(output_classes, list):
                        entry_classes = ", ".join(str(value) for value in output_classes)
                parameter_aliases = format_parameter_aliases(entry.get("parameter_aliases"))
                required_parameters = format_required_parameters(entry.get("required_parameters"))
                required_parameter_hints = format_parser_hints(entry.get("required_parameter_hints"))
                conditional_required_parameters = format_conditional_required_parameters(
                    entry.get("conditional_required_parameters")
                )
                alternative_required_parameters = format_alternative_required_parameters(
                    entry.get("alternative_required_parameters")
                )
                planner_warnings = format_planner_warnings(entry.get("planner_warnings"))
                required_privileges = format_required_privileges(entry.get("required_privileges"))
                side_effects = format_side_effects(entry.get("side_effects"))
                planned_handles = format_planned_handles(entry.get("planned_handles"))
                rollback_preview = format_rollback_preview(entry.get("rollback"))
                choice_parameters = format_choice_parameters(entry.get("choice_parameters"))
                array_choice_parameters = format_array_choice_parameters(entry.get("array_choice_parameters"))
                parameter_bounds = format_parameter_bounds(entry.get("parameter_bounds"))
                parser_hints = format_parser_hints(entry.get("parser_hints"))
                lines.append(
                    "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | `{}` |".format(
                        markdown_escape(str(entry.get("action", ""))),
                        entry.get("read_only", ""),
                        entry.get("state_changing", ""),
                        entry.get("privileged", ""),
                        entry.get("kernel", ""),
                        entry.get("destructive", ""),
                        markdown_escape(str(entry.get("risk", ""))),
                        markdown_escape(str(entry.get("required_policy", ""))),
                        markdown_escape(required_parameters),
                        markdown_escape(required_parameter_hints),
                        markdown_escape(conditional_required_parameters),
                        markdown_escape(alternative_required_parameters),
                        markdown_escape(planner_warnings),
                        markdown_escape(required_privileges),
                        markdown_escape(side_effects),
                        markdown_escape(planned_handles),
                        markdown_escape(rollback_preview),
                        markdown_escape(parameter_aliases),
                        markdown_escape(choice_parameters),
                        markdown_escape(array_choice_parameters),
                        markdown_escape(parameter_bounds),
                        markdown_escape(parser_hints),
                        markdown_escape(entry_classes),
                    )
                )
            lines.append("")

        if isinstance(data_classification, list) and data_classification:
            lines.append("### Data Classification")
            lines.append("")
            lines.append("| Output Path | Classification |")
            lines.append("|---|---|")
            for entry in data_classification:
                if not isinstance(entry, dict):
                    continue
                lines.append(
                    "| `{}` | `{}` |".format(
                        markdown_escape(str(entry.get("path", ""))),
                        markdown_escape(str(entry.get("classification", ""))),
                    )
                )
            lines.append("")

        lines.append("### Fields")
        lines.append("")
        lines.append("| Field | Type | Required | Default | Bounds | Description | Enum |")
        lines.append("|---|---|---|---|---|---|---|")

        for field_name in sorted(properties.keys()):
            field = properties[field_name] or {}
            field_type = markdown_escape(type_repr(field))
            is_required = "yes" if field_name in required else "no"
            default = markdown_escape(json.dumps(field.get("default"))) if "default" in field else ""
            bounds_value = markdown_escape(format_bounds(field)) if isinstance(field, dict) else ""
            description_value = markdown_escape(str(field.get("description", "")))
            enum_value = markdown_escape(format_enum(field.get("enum")))
            lines.append(
                f"| `{field_name}` | `{field_type}` | {is_required} | `{default}` | `{bounds_value}` | {description_value} | {enum_value} |"
            )

        lines.append("")

    REFERENCE_MD.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    catalog = fetch_runtime_catalog()
    initialize = catalog["initialize"]
    tools = catalog["tools"]
    resources = catalog["resources"]
    resource_templates = catalog["resourceTemplates"]
    write_catalog_json(tools, resources, resource_templates)
    write_reference_markdown(tools, resources, resource_templates)
    write_server_manifest(initialize, tools, resources, resource_templates)
    print(
        f"Generated {CATALOG_JSON.relative_to(ROOT)}, {REFERENCE_MD.relative_to(ROOT)}, "
        f"and {SERVER_MANIFEST_JSON.relative_to(ROOT)} "
        "from runtime initialize, tools/list, resources/list, and resources/templates/list"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
