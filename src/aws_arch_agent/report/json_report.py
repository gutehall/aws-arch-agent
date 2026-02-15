"""JSON report renderer for CI and tooling (context + findings)."""
from __future__ import annotations

import json
from aws_arch_agent.models import Finding, RepoContext


def render_json(ctx: RepoContext, findings: list[Finding]) -> str:
    """Serialize context and findings to JSON (Pydantic model_dump)."""
    data = {
        "context": ctx.model_dump(),
        "findings": [f.model_dump() for f in findings],
    }
    return json.dumps(data, indent=2)
