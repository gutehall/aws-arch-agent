"""Integration test for V2 graph (no LLM)."""
import json
from pathlib import Path

from aws_arch_agent.agent.v2_graph import analyze_v2


def test_v2_returns_report_and_findings(tmp_path: Path) -> None:
    """V2 with --no-llm returns report string, ctx, and findings."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    report, ctx, findings, warnings = analyze_v2(tmp_path, use_llm=False)
    assert "AWS Architecture Review Report" in report or "Architecture Review" in report
    assert ctx.repo_path == str(tmp_path)
    assert ctx.language in ("typescript", "python", "unknown")
    # May have SEC-005 or other findings
    assert isinstance(findings, list)
    assert all(hasattr(f, "id") and hasattr(f, "severity") for f in findings)


def test_v2_with_templates_path_runs_cf_rules(tmp_path: Path) -> None:
    """V2 with templates_path skips synth and runs CF rules on provided templates."""
    template = {
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {},
            }
        }
    }
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "stack.template.json").write_text(
        json.dumps(template), encoding="utf-8"
    )
    report, ctx, findings, warnings = analyze_v2(
        tmp_path,
        use_llm=False,
        templates_path=str(tmp_path / "templates"),
        skip_synth=False,
    )
    assert "Templates: provided" in report or "provided (no synth)" in report
    assert any(f.id == "CF-S3-001" for f in findings)


def test_v2_with_no_synth_static_only(tmp_path: Path) -> None:
    """V2 with skip_synth and no templates runs static analysis only."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    report, ctx, findings, warnings = analyze_v2(tmp_path, use_llm=False, skip_synth=True)
    assert "CDK synth: skipped" in report or "Synth skipped" in report
    assert isinstance(findings, list)
