"""Locked V1 output for one CDK, one CloudFormation, and one Terraform fixture.

A change that moves any finding (id, severity, file, line, evidence) fails here.

The CloudFormation and Terraform fixture files end in `.fixture` so that scanning this
repo itself (CI dogfood, pre-commit) does not detect them as IaC sources. Tests copy
them to a temp dir under their real names.

After an intended change, regenerate with:

    UPDATE_SNAPSHOTS=1 pytest tests/test_source_regression.py
"""
import json
import os
import shutil
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1, detect_source
from aws_arch_agent.models import Finding
from aws_arch_agent.tools import cdk_synth
from aws_arch_agent.tools.files import iter_files

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOTS = FIXTURES / "snapshots"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"


def _rows(findings: list[Finding]) -> list[dict]:
    rows = [
        {"id": f.id, "severity": f.severity, "file": f.file, "line": f.line, "evidence": f.evidence}
        for f in findings
    ]
    return sorted(rows, key=lambda r: (r["id"], r["file"] or "", r["line"] or 0, r["evidence"] or ""))


def _scan(repo: Path) -> tuple[str, list[dict], list[str]]:
    _report, ctx, findings, warnings = analyze_v1(repo, use_llm=False)
    return ctx.source, _rows(findings), warnings


def _check_snapshot(name: str, rows: list[dict]) -> None:
    path = SNAPSHOTS / f"{name}.json"
    if os.environ.get("CI") and (UPDATE or not path.exists()):
        pytest.fail(f"Snapshot {path.name} is missing or UPDATE_SNAPSHOTS is set in CI.")
    if UPDATE or not path.exists():
        path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        if not UPDATE:
            pytest.fail(f"Wrote missing snapshot {path.name}; review and commit it.")
    assert rows == json.loads(path.read_text(encoding="utf-8"))


def _materialize(name: str, dest: Path) -> Path:
    """Copy fixtures/<name> to dest, dropping the .fixture suffix."""
    src = FIXTURES / name
    for path in src.rglob("*.fixture"):
        target = dest / path.relative_to(src).with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    return dest


@pytest.fixture
def cf_repo(tmp_path: Path) -> Path:
    return _materialize("cloudformation", tmp_path / "cloudformation")


@pytest.fixture
def tf_repo(tmp_path: Path) -> Path:
    return _materialize("terraform", tmp_path / "terraform")


def _copy_cdk_app(dest: Path) -> Path:
    src = FIXTURES / "minimal-cdk"
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("node_modules", "cdk.out"))
    return dest


def test_cdk_fixture_report_is_unchanged(tmp_path: Path) -> None:
    # Scan a copy without the gitignored node_modules/cdk.out so local and CI agree.
    source, rows, warnings = _scan(_copy_cdk_app(tmp_path / "app"))
    assert source == "cdk"
    assert warnings == []
    _check_snapshot("minimal-cdk", rows)


def test_workflow_yaml_does_not_switch_a_cdk_repo(tmp_path: Path) -> None:
    repo = _copy_cdk_app(tmp_path / "app")
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "deploy.yml").write_text(
        "name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: npx cdk deploy\n",
        encoding="utf-8",
    )
    # Root-level YAML that mentions an AWS:: type but is not a template.
    (repo / "buildspec.yml").write_text(
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - echo AWS::S3::Bucket\n",
        encoding="utf-8",
    )
    source, rows, _warnings = _scan(repo)
    assert source == "cdk"
    snapshot = json.loads((SNAPSHOTS / "minimal-cdk.json").read_text(encoding="utf-8"))
    # The workflow is a CI pipeline, so REPO-002 goes away. REPO-009 and REPO-017 still fire
    # (neither build scans dependencies or runs a load test), but their evidence now names
    # the builds they searched.
    named = ("REPO-009", "REPO-017")
    # The workflow deploys with no test before it, so REPO-021 fires on it. It deploys the
    # stack, so REPO-025 goes away, and with no smoke or resiliency test after the deploy
    # REPO-024 and REPO-026 fire on it.
    deploy_rules = ("REPO-021", "REPO-024", "REPO-026")
    for rule_id in deploy_rules:
        (row,) = [r for r in rows if r["id"] == rule_id]
        assert row["file"] == ".github/workflows/deploy.yml"
    (gate,) = [r for r in rows if r["id"] == "REPO-021"]
    assert gate["line"] == 7
    assert [r for r in rows if r["id"] not in (*named, *deploy_rules)] == [
        r for r in snapshot if r["id"] not in ("REPO-002", "REPO-025", *named)
    ]
    for rule_id in named:
        (row,) = [r for r in rows if r["id"] == rule_id]
        assert row["evidence"].startswith(
            "Searched the build configs (.github/workflows/deploy.yml, buildspec.yml)"
        )


def test_cloudformation_fixture_runs_template_checks_without_synth(
    cf_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_synth(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cdk synth must not run for a CloudFormation repo")

    monkeypatch.setattr(cdk_synth, "run_cdk_synth", no_synth)
    source, rows, warnings = _scan(cf_repo)
    assert source == "cloudformation"
    assert warnings == []
    checks = [r for r in rows if not r["id"].startswith("REPO-")]  # repo-level: no file
    assert checks and all(r["id"].startswith("CF-") for r in checks)
    assert {r["file"] for r in checks} == {"stack.yaml"}  # deploy.yml is not a template
    _check_snapshot("cloudformation", rows)


def test_terraform_fixture_reports_controls_at_hcl_lines(tf_repo: Path) -> None:
    source, rows, warnings = _scan(tf_repo)
    assert source == "terraform"
    assert warnings == []
    checks = [r for r in rows if not r["id"].startswith("REPO-")]  # repo-level: no file
    assert all(r["line"] for r in checks)
    assert not any(r["file"].startswith("modules/") for r in checks)  # child module not read
    _check_snapshot("terraform", rows)


def test_cloudformation_and_terraform_fixtures_report_the_same_controls(
    cf_repo: Path, tf_repo: Path
) -> None:
    cf_ids = sorted(r["id"] for r in _scan(cf_repo)[1])
    tf_ids = sorted(r["id"] for r in _scan(tf_repo)[1])
    assert cf_ids == tf_ids


@pytest.mark.parametrize("fixture", ["cloudformation", "terraform"])
def test_unresolved_values_are_not_findings(fixture: str, tmp_path: Path) -> None:
    """Backup days, the jobs queue redrive policy, and Lambda architectures are unresolved."""
    rows = _scan(_materialize(fixture, tmp_path / fixture))[1]
    ids = {r["id"] for r in rows}
    assert "CF-RDS-002" not in ids
    assert "CF-PERF-001" not in ids
    sqs = [r["evidence"] for r in rows if r["id"] == "CF-SQS-002"]
    assert len(sqs) == 1 and "jobs" not in sqs[0].lower()


def test_fixtures_are_invisible_to_a_scan_of_this_repo() -> None:
    """The committed fixtures do not make tests/fixtures (or the repo) look like CF/TF."""
    for name in ("cloudformation", "terraform"):
        files = [p for p in (FIXTURES / name).rglob("*") if p.is_file()]
        assert files and all(p.suffix == ".fixture" for p in files)
    assert detect_source(FIXTURES, iter_files(FIXTURES, max_files=100_000)) == "cdk"
