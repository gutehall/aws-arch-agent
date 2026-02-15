"""Integration test for V2 graph (no LLM)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v2_graph import analyze_v2


def test_v2_returns_report_and_findings(tmp_path: Path) -> None:
    """V2 with --no-llm returns report string, ctx, and findings."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    report, ctx, findings = analyze_v2(tmp_path, use_llm=False)
    assert "AWS Architecture Review Report" in report or "Architecture Review" in report
    assert ctx.repo_path == str(tmp_path)
    assert ctx.language in ("typescript", "python", "unknown")
    # May have SEC-005 or other findings
    assert isinstance(findings, list)
    assert all(hasattr(f, "id") and hasattr(f, "severity") for f in findings)
