#!/usr/bin/env python3
"""Generate caller-facing tool reference docs from the runtime tools/list surface.

This script does not parse Rust source directly. It starts the local memoric binary
through `cargo run --quiet`, performs a minimal MCP bootstrap, and captures the
runtime `tools/list` response as the source of truth for generated docs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
CATALOG_JSON = DOCS_DIR / "tool-catalog.json"
REFERENCE_MD = DOCS_DIR / "tool-reference.md"


def type_repr(schema: dict[str, Any]) -> str:
    value = schema.get("type")
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    if value is None:
        return "any"
    return str(value)


def format_enum(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return ", ".join(str(value) for value in values)


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def fetch_runtime_tools() -> list[dict[str, Any]]:
    requests = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
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

    for response in responses:
        if response.get("id") == 2:
            tools = response.get("result", {}).get("tools")
            if isinstance(tools, list):
                return tools

    raise RuntimeError(
        "Runtime tools/list response not found.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def write_catalog_json(tools: list[dict[str, Any]]) -> None:
    payload = {
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "generatedFrom": "runtime tools/list via cargo run --quiet",
        "toolCount": len(tools),
        "tools": tools,
    }
    CATALOG_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_reference_markdown(tools: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("# Memoric Tool Reference")
    lines.append("")
    lines.append("Generated from the runtime `tools/list` surface. Do not hand-edit this file.")
    lines.append("")
    lines.append(f"- Generated: `{generated_at}`")
    lines.append("- Source: `cargo run --quiet` -> `initialize` -> `tools/list`")
    lines.append(f"- Tool count: `{len(tools)}`")
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

    for tool in tools:
        name = str(tool.get("name", "unknown"))
        description = str(tool.get("description", "")).strip()
        schema = tool.get("inputSchema", {}) or {}
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
        lines.append("")

        if isinstance(action_enum, list) and action_enum:
            lines.append("### Actions")
            lines.append("")
            lines.append(", ".join(f"`{value}`" for value in action_enum))
            lines.append("")

        lines.append("### Fields")
        lines.append("")
        lines.append("| Field | Type | Required | Default | Description | Enum |")
        lines.append("|---|---|---|---|---|---|")

        for field_name in sorted(properties.keys()):
            field = properties[field_name] or {}
            field_type = markdown_escape(type_repr(field))
            is_required = "yes" if field_name in required else "no"
            default = markdown_escape(json.dumps(field.get("default"))) if "default" in field else ""
            description_value = markdown_escape(str(field.get("description", "")))
            enum_value = markdown_escape(format_enum(field.get("enum")))
            lines.append(
                f"| `{field_name}` | `{field_type}` | {is_required} | `{default}` | {description_value} | {enum_value} |"
            )

        lines.append("")

    REFERENCE_MD.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    tools = fetch_runtime_tools()
    write_catalog_json(tools)
    write_reference_markdown(tools)
    print(f"Generated {CATALOG_JSON.relative_to(ROOT)} and {REFERENCE_MD.relative_to(ROOT)} from runtime tools/list")
    return 0


if __name__ == "__main__":
    sys.exit(main())
