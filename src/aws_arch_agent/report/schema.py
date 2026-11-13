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
                    "environment": {
                        "type": ["string", "null"],
                        "enum": ["prod", "staging", "dev", "unknown", None],
                        "description": "The environment of the stack the finding came from. "
                        "unknown is judged as prod. Null for findings not tied to a template.",
                    },
                    "effort": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "How much work the fix is: low = one property changed "
                        "in place; high = the resource is replaced or redesigned.",
                    },
                    "estimate_basis": {
                        "type": ["string", "null"],
                        "description": "How the estimate was worked out: quantities, unit "
                        "prices, region, price list date, and what it excludes.",
                    },
                    "question": {
                        "type": ["string", "null"],
                        "description": "The Well-Architected question the rule answers, such "
                        "as SEC 8. Null for an id no rule defines.",
                    },
                    "best_practices": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "The Well-Architected best practices the rule checks, "
                        "such as SEC08-BP02.",
                    },
                    "verdict": {
                        "type": "object",
                        "description": "The model's opinion of this finding. It labels the "
                        "finding and changes nothing else: not the severity, the exit code, "
                        "the baseline, or SARIF. Absent unless llm.status is ok.",
                        "required": ["verdict", "why"],
                        "properties": {
                            "verdict": {
                                "type": "string",
                                "enum": ["confirm", "false_positive", "unsure"],
                            },
                            "why": {"type": "string"},
                        },
                    },
                },
            },
        },
        "summary": {
            "type": "object",
            "description": "Opening summary built from the findings: top fixes (one rule "
            "each, ranked by severity, then saving, then resources covered), one row per "
            "pillar, and quick wins. Pillar counts and savings add up to the findings.",
            "properties": {
                "findings": {"type": "integer", "minimum": 0},
                "by_severity": {"type": "object"},
                "monthly_savings_usd": {"type": "number", "minimum": 0},
                "top_fixes": {"type": "array", "items": {"type": "object"}},
                "pillars": {"type": "array", "items": {"type": "object"}},
                "quick_wins": {"type": "array", "items": {"type": "object"}},
            },
        },
        "answers": {
            "type": "array",
            "description": "One answer per Well-Architected question, in framework order, "
            "computed from the findings. met means every best practice of the question has a "
            "rule and no finding falls under it. Nobody is asked, and the LLM does not change it.",
            "items": {
                "type": "object",
                "required": ["question", "pillar", "title", "status", "findings", "not_checked"],
                "properties": {
                    "question": {"type": "string"},
                    "pillar": {"type": "string"},
                    "title": {"type": "string"},
                    "status": {"type": "string", "enum": ["met", "not met"]},
                    "findings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "The rule id of each finding under the question.",
                    },
                    "not_checked": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Best practices of the question that this scan did not "
                        "check: no rule checks them, or their rules did not run.",
                    },
                    "needs_org": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "The part of not_checked whose rules are all "
                        "account-level and off unless rules.org is true.",
                    },
                },
            },
        },
        "llm": {
            "type": "object",
            "description": "What the verdict calls did. A connection failure is fallback, and "
            "no finding then has a verdict.",
            "properties": {
                "status": {"type": "string", "enum": ["ok", "fallback", "skipped", "invalid"]},
                "provider": {"type": ["string", "null"]},
                "model": {"type": ["string", "null"]},
                "reason": {"type": ["string", "null"]},
            },
        },
        "hypotheses_llm": {
            "type": "object",
            "description": "What the hypothesis call did, apart from llm. Absent when no call "
            "was made.",
            "properties": {
                "status": {"type": "string", "enum": ["ok", "fallback", "skipped", "invalid"]},
                "provider": {"type": ["string", "null"]},
                "model": {"type": ["string", "null"]},
                "reason": {"type": ["string", "null"]},
            },
        },
        "hypotheses": {
            "type": "array",
            "description": "Catalog rules the model named in files with no finding. Each cites "
            "a catalog rule id and is unverified: no check confirmed it. They are not findings "
            "and do not affect the exit code, the baseline, or SARIF. Absent when there are none.",
            "items": {
                "type": "object",
                "required": ["rule_id", "title", "file", "line", "why", "unverified"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "title": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 1},
                    "why": {"type": "string"},
                    "unverified": {"const": True},
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
