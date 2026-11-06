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
                "source": {
                    "type": "string",
                    "enum": ["cdk", "cloudformation", "terraform", "mixed"],
                },
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
                    "monthly_cost_usd": {
                        "type": ["number", "null"],
                        "minimum": 0,
                        "description": "Estimated on-demand cost per month in USD (730 hours). "
                        "Null when the finding has too little to price.",
                    },
                    "monthly_savings_usd": {
                        "type": ["number", "null"],
                        "minimum": 0,
                        "description": "Estimated saving per month in USD if the recommendation "
                        "is applied. A separate number: never subtracted from monthly_cost_usd.",
                    },
                    "estimate_basis": {
                        "type": ["string", "null"],
                        "description": "How the estimate was worked out: quantities, unit "
                        "prices, region, price list date, and what it excludes.",
                    },
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
