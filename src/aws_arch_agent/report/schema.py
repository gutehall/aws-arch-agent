"""JSON Schema for aws-arch-agent report output."""
from __future__ import annotations

import json

REPORT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AWS Arch Agent Report",
    "type": "object",
    "required": ["context", "findings"],
    "properties": {
        "context": {
            "type": "object",
            "required": ["repo_path", "language"],
            "properties": {
                "repo_path": {"type": "string"},
                "language": {"type": "string", "enum": ["typescript", "python", "unknown"]},
                "files_scanned": {"type": "integer", "minimum": 0},
                "key_files": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "object"},
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "title", "severity", "category", "recommendation"],
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["High", "Medium", "Low"]},
                    "category": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "line": {"type": ["integer", "null"]},
                    "evidence": {"type": ["string", "null"]},
                    "recommendation": {"type": "string"},
                    "suggested_code": {"type": ["string", "null"]},
                },
            },
        },
        "warnings": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
}


def schema_json() -> str:
    return json.dumps(REPORT_SCHEMA, indent=2)
