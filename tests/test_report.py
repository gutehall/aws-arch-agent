"""Tests for report rendering (markdown and JSON)."""
import json

from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.markdown import render_markdown


def test_render_markdown_shape() -> None:
    """Markdown report contains title, repo info, and severity sections."""
    ctx = RepoContext(repo_path="/repo", language="typescript", files_scanned=10)
    findings = [
        Finding(
            id="SEC-001",
            title="IAM wildcard",
            severity="High",
            category="Security",
            recommendation="Use least privilege.",
        ),
    ]
    out = render_markdown(ctx, findings)
    assert "# AWS Architecture Review Report" in out
    assert "repo_path" in out or "/repo" in out
    assert "typescript" in out
    assert "SEC-001" in out
    assert "High" in out


def test_render_markdown_no_findings() -> None:
    """Markdown with no findings still has structure."""
    ctx = RepoContext(repo_path="/repo", language="python")
    out = render_markdown(ctx, [])
    assert "AWS Architecture Review Report" in out
    assert "Suggested Next Actions" in out


def test_render_json_shape() -> None:
    """JSON report has context and findings keys and is valid JSON."""
    ctx = RepoContext(repo_path="/repo", language="typescript")
    findings = [
        Finding(id="OPS-001", title="CloudTrail", severity="Medium", recommendation="Enable it."),
    ]
    out = render_json(ctx, findings)
    data = json.loads(out)
    assert "context" in data
    assert "findings" in data
    assert data["context"]["repo_path"] == "/repo"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "OPS-001"
