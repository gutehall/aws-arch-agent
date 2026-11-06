"""Opening summary: top fixes, one line per pillar, quick wins (DM3-550)."""
import json
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent.cli import app
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.html import render_html
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.report.schema import REPORT_SCHEMA
from aws_arch_agent.report.summary import build_summary
from aws_arch_agent.rules.effort import effort_of

ROOT = Path(__file__).resolve().parents[1]


def _f(rule: str, severity: str, category: str, saving: float | None = None, code: str | None = None,
       effort: str = "medium", file: str = "t.yaml", evidence: str = "R") -> Finding:
    return Finding(id=rule, title=f"title {rule}", severity=severity, category=category, file=file,
                   evidence=evidence, recommendation="r", monthly_savings_usd=saving, suggested_code=code,
                   effort=effort)


FINDINGS = [
    _f("CF-SG-001", "High", "Security", evidence="Sg1"),
    _f("CF-SG-001", "High", "Security", evidence="Sg2"),
    _f("CF-RDS-004", "High", "Security"),
    _f("CF-PERF-003", "Low", "Performance Efficiency", saving=300.0),
    _f("CF-EBS-002", "Low", "Cost Optimization", saving=2.0, code="x", effort="low", evidence="V1"),
    _f("CF-EBS-002", "Low", "Cost Optimization", saving=3.5, code="x", effort="low", evidence="V2"),
    _f("CF-EIP-001", "Low", "Cost Optimization", saving=3.65, code="x", effort="low"),
    _f("CF-S3-003", "Medium", "Reliability", code="x", effort="low"),
    _f("CF-RDS-001", "High", "Security", code="x", effort="high"),
]


def test_summary_is_stable_and_adds_up() -> None:
    first = build_summary(FINDINGS)
    assert build_summary(list(reversed(FINDINGS))) == first  # same on every run, any order
    assert first["findings"] == len(FINDINGS)
    assert sum(row["findings"] for row in first["pillars"]) == len(FINDINGS)
    assert first["by_severity"] == {"High": 4, "Medium": 1, "Low": 4}
    total = round(sum(f.monthly_savings_usd or 0 for f in FINDINGS), 2)
    assert first["monthly_savings_usd"] == total
    assert round(sum(row["monthly_savings_usd"] for row in first["pillars"]), 2) == total


def test_top_fixes_rank_by_severity_then_saving_then_coverage() -> None:
    top = build_summary(FINDINGS)["top_fixes"]
    # High first: SG covers 2 resources, then RDS-001 and RDS-004 (1 each, by id); then Medium.
    assert [x["id"] for x in top] == ["CF-SG-001", "CF-RDS-001", "CF-RDS-004", "CF-S3-003", "CF-PERF-003"]
    assert top[0]["findings"] == 2
    low = [x for x in build_summary(FINDINGS[3:])["top_fixes"] if x["severity"] == "Low"]
    assert [x["id"] for x in low] == ["CF-PERF-003", "CF-EBS-002", "CF-EIP-001"]  # by saving
    assert low[1]["monthly_savings_usd"] == 5.5


def test_quick_wins_are_low_effort_with_code() -> None:
    quick = build_summary(FINDINGS)["quick_wins"]
    assert [x["id"] for x in quick] == ["CF-EBS-002", "CF-EIP-001", "CF-S3-003"]


def test_pillar_lines() -> None:
    md = render_markdown(RepoContext(repo_path="/r"), FINDINGS)
    assert md.index("## Summary") < md.index("## Executive Summary")
    assert "- Cost Optimization: 3 findings (3 Low), about $9.15/month possible savings (estimate)" in md
    assert "- Security: 4 findings (4 High)" in md
    assert "1. [CF-SG-001] title CF-SG-001 (High, 2 resources, medium effort), e.g. t.yaml" in md
    assert "**Quick wins** (low effort, with suggested code):" in md


def test_no_findings_no_summary() -> None:
    assert "## Summary" not in render_markdown(RepoContext(repo_path="/r"), [])
    assert build_summary([])["top_fixes"] == []


def test_json_and_html_carry_the_summary() -> None:
    ctx = RepoContext(repo_path="/r")
    data = json.loads(render_json(ctx, FINDINGS))
    assert data["summary"] == build_summary(FINDINGS)
    assert data["findings"][0]["effort"] == "medium"
    html = render_html(ctx, FINDINGS)
    assert "<h2>Summary</h2>" in html and "Cost Optimization: 3 findings" in html
    assert "Quick wins" in html


def test_effort_map() -> None:
    assert effort_of("CF-EBS-002") == "low"
    assert effort_of("CF-RDS-001") == "high"  # encrypting an existing database replaces it
    assert effort_of("SEC-005") == "medium"


def test_schema_documents_summary_and_effort() -> None:
    assert "summary" in REPORT_SCHEMA["properties"]
    assert "effort" in REPORT_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert json.loads((ROOT / "docs" / "report-schema.json").read_text(encoding="utf-8")) == REPORT_SCHEMA


STACK = {
    "Data": {"Type": "AWS::EC2::Volume", "Properties": {
        "AvailabilityZone": "us-east-1a", "Size": 100, "VolumeType": "gp2", "Encrypted": True}},
    "Open": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "x", "SecurityGroupIngress": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}},
    "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
}


def test_scan_summary_matches_its_findings_every_run(tmp_path: Path) -> None:
    (tmp_path / "stack.json").write_text(
        json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": STACK}), encoding="utf-8")
    runs = []
    for i in range(2):
        out = tmp_path / f"r{i}.json"
        result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "json",
                                          "--out", str(out)])
        assert result.exit_code == 0, result.output
        runs.append(json.loads(out.read_text()))
    assert runs[0]["summary"] == runs[1]["summary"]
    data = runs[0]
    summary, findings = data["summary"], data["findings"]
    assert summary["findings"] == len(findings)
    # High fixes lead; equal severity, saving and coverage break by rule id.
    highs = [x["id"] for x in summary["top_fixes"] if x["severity"] == "High"]
    assert highs == sorted(highs) and {"CF-S3-001", "CF-SG-001"} <= set(highs)
    assert summary["top_fixes"][: len(highs)] == [x for x in summary["top_fixes"] if x["severity"] == "High"]
    assert round(sum(f["monthly_savings_usd"] or 0 for f in findings), 2) == summary["monthly_savings_usd"]
    gp2 = next(f for f in findings if f["id"] == "CF-EBS-002")
    assert gp2["effort"] == "low"
    assert any(x["id"] == "CF-EBS-002" for x in summary["quick_wins"])
