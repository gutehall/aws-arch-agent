"""Tests for SARIF report output."""
import json

from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.sarif import render_sarif


def test_render_sarif_valid_json() -> None:
    ctx = RepoContext(repo_path="/repo", language="typescript")
    findings = [
        Finding(id="SEC-001", title="IAM", severity="High", recommendation="Fix it.", file="lib/a.ts", line=10),
    ]
    out = render_sarif(ctx, findings, warnings=["Rule X failed"])
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    results = data["runs"][0]["results"]
    assert any(r["ruleId"] == "SEC-001" for r in results)
    assert any(r["ruleId"] == "AWS-ARCH-AGENT-WARNING" for r in results)
