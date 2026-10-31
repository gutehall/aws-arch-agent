"""Integration test for V2 graph (no LLM)."""
import json
import subprocess
from pathlib import Path

from aws_arch_agent.agent.v2_graph import analyze_v2, node_synth
from aws_arch_agent.models import Finding


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


def test_synth_timeout_is_a_warning(tmp_path: Path, monkeypatch) -> None:
    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["npx", "cdk", "synth"], timeout=180)

    monkeypatch.setattr("aws_arch_agent.agent.v2_graph.run_cdk_synth", timed_out)
    out = node_synth({"repo_path": str(tmp_path), "rule_warnings": ["kept"]})
    assert out["synth_ok"] is False
    assert "kept" in out["rule_warnings"]
    assert any("timed out" in warning for warning in out["rule_warnings"])


def _finding(rule_id: str) -> Finding:
    return Finding(id=rule_id, title=rule_id, recommendation="fix")


_BUCKET_AND_VPC = {
    "Resources": {
        "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
        "Disabled": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketEncryption": {
                    "ServerSideEncryptionConfiguration": [
                        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "UNENCRYPTED"}}
                    ]
                }
            },
        },
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
    }
}


def test_templates_drop_static_rules_cf_already_reported(tmp_path: Path) -> None:
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "stack.template.json").write_text(json.dumps(_BUCKET_AND_VPC), encoding="utf-8")
    out = node_synth(
        {
            "repo_path": str(tmp_path),
            "templates_path": str(templates),
            "raw_findings": [
                _finding("SEC-005"),
                _finding("SEC-006"),
                _finding("SEC-022"),
                _finding("OPS-002"),
                _finding("SEC-001"),
            ],
            "rule_warnings": [],
        }
    )
    ids = {finding.id for finding in out["raw_findings"]}
    assert {"SEC-005", "SEC-006", "SEC-022", "OPS-002"}.isdisjoint(ids)
    assert "SEC-001" in ids
    assert {"CF-S3-001", "CF-S3-002", "CF-VPC-001", "CF-FL-001"} <= ids


def test_synth_success_drops_static_rule_cf_already_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_arch_agent.agent.v2_graph.run_cdk_synth",
        lambda *_args, **_kwargs: (0, "ok", ""),
    )
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(_BUCKET_AND_VPC), encoding="utf-8")
    out = node_synth(
        {
            "repo_path": str(tmp_path),
            "raw_findings": [_finding("SEC-005"), _finding("SEC-001")],
            "rule_warnings": [],
        }
    )
    ids = {finding.id for finding in out["raw_findings"]}
    assert "SEC-005" not in ids
    assert "SEC-001" in ids
    assert "CF-S3-001" in ids


def _bucket_repo(root: Path) -> None:
    (root / "package.json").write_text("{}", encoding="utf-8")
    lib = root / "lib"
    lib.mkdir()
    (lib / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")


def test_skipped_synth_keeps_static_s3_finding(tmp_path: Path) -> None:
    _bucket_repo(tmp_path)
    _report, _ctx, findings, _warnings = analyze_v2(tmp_path, use_llm=False, skip_synth=True)
    assert any(finding.id == "SEC-005" for finding in findings)


def test_failed_synth_keeps_static_s3_finding(tmp_path: Path, monkeypatch) -> None:
    _bucket_repo(tmp_path)
    monkeypatch.setattr(
        "aws_arch_agent.agent.v2_graph.run_cdk_synth",
        lambda *_args, **_kwargs: (1, "", "synth failed"),
    )
    _report, _ctx, findings, warnings = analyze_v2(tmp_path, use_llm=False)
    assert any(finding.id == "SEC-005" for finding in findings)
    assert not any(finding.id == "CF-S3-001" for finding in findings)
    assert any("exited 1" in warning for warning in warnings)
