"""Inline suppressions, template Metadata suppressions, and rules.exclude_paths."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent import suppressions
from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.models import Finding, Suppression
from aws_arch_agent.report.html import render_html
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.models import RepoContext

runner = CliRunner()
TODAY = date(2026, 11, 22)

BUCKET_YAML = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
{comment}  Bucket:
    Type: AWS::S3::Bucket
"""


def _finding(rule_id: str, file: str, line: int) -> Finding:
    return Finding(id=rule_id, title="t", recommendation="r", file=file, line=line)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _cdk_ts_repo(root: Path, comment: str = "") -> None:
    _write(root, "package.json", "{}")
    _write(
        root,
        "lib/stack.ts",
        'import * as s3 from "aws-cdk-lib/aws-s3";\n' + comment + 'new s3.Bucket(this, "B");\n',
    )


def _by_id(findings: list[Finding], rule_id: str) -> Finding:
    return next(f for f in findings if f.id == rule_id)


# --- directive parsing ---------------------------------------------------------------------


def test_parse_directive_full() -> None:
    rule = suppressions.parse_directive(
        '  # aws-arch-agent: ignore CF-S3-001, cf-s3-003 reason="logs, only" expires=2027-01-31'
    )
    assert not isinstance(rule, str) and rule is not None
    assert rule.ids == {"CF-S3-001", "CF-S3-003"}
    assert rule.reason == "logs, only"
    assert rule.expires == date(2027, 1, 31)


@pytest.mark.parametrize(
    "line, error",
    [
        ("// aws-arch-agent: ignore", "no rule IDs"),
        ('# aws-arch-agent: ignore reason="x"', "no rule IDs"),
        ("# aws-arch-agent: ignore SEC-005 expires=2027-13-01", "expires must be a date"),
        ("# aws-arch-agent: ignore SEC-005 expires=tomorrow", "expires must be a date"),
        ("# aws-arch-agent: ignore SEC-005 because=!!", "not a rule ID"),
    ],
)
def test_parse_directive_malformed(line: str, error: str) -> None:
    result = suppressions.parse_directive(line)
    assert isinstance(result, str) and error in result


def test_parse_directive_none() -> None:
    assert suppressions.parse_directive("const x = 1; // a comment") is None
    assert suppressions.parse_directive("# aws-arch-agent: ignored-by-humans") is None


# --- each IaC format, end to end ---------------------------------------------------------------


def test_cdk_typescript_comment_above(tmp_path: Path) -> None:
    _cdk_ts_repo(tmp_path, '// aws-arch-agent: ignore SEC-005 reason="public site"\n')
    _md, _ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False)
    sec = _by_id(findings, "SEC-005")
    assert sec.suppression == Suppression(kind="inline", reason="public site")
    assert _by_id(findings, "REL-031").suppression is None
    assert not [w for w in warnings if "aws-arch-agent" in w]


def test_cdk_typescript_same_line(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", "{}")
    _write(
        tmp_path,
        "lib/stack.ts",
        'new s3.Bucket(this, "B"); // aws-arch-agent: ignore SEC-005, REL-031\n',
    )
    _md, _ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    assert _by_id(findings, "SEC-005").suppression is not None
    assert _by_id(findings, "REL-031").suppression is not None


def test_cdk_python_comment(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "aws-cdk-lib\n")
    _write(tmp_path, "cdk.json", '{"app": "python3 app.py"}')
    source = "from aws_cdk import aws_s3 as s3\n\n\ndef build(self):\n    s3.Bucket(self, \"B\")\n"
    _write(tmp_path, "app.py", source)
    _md, _ctx, plain, _w = analyze_v1(tmp_path, use_llm=False)
    located = [f for f in plain if f.file == "app.py" and f.line]
    assert located, "the fixture needs a finding with a line in app.py"
    target = located[0]
    lines = source.splitlines()
    lines.insert(target.line - 1, f"    # aws-arch-agent: ignore {target.id}")
    _write(tmp_path, "app.py", "\n".join(lines) + "\n")
    _md, _ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    hit = [f for f in findings if f.id == target.id and f.file == "app.py"]
    assert hit and all(f.suppression is not None for f in hit)


def test_terraform_hash_and_slash_comments(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "main.tf",
        '# aws-arch-agent: ignore CF-S3-001 reason="tf"\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        '// aws-arch-agent: ignore CF-S3-005\n'
        'resource "aws_s3_bucket" "c" {\n  bucket = "y"\n}\n',
    )
    _md, _ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, iac="terraform")
    by_line = {(f.id, f.line): f for f in findings if f.file == "main.tf"}
    assert by_line[("CF-S3-001", 2)].suppression == Suppression(kind="inline", reason="tf")
    assert by_line[("CF-S3-005", 2)].suppression is None
    assert by_line[("CF-S3-005", 6)].suppression is not None
    assert by_line[("CF-S3-001", 6)].suppression is None


def test_cloudformation_yaml_comment_above_logical_id(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "stack.yaml",
        BUCKET_YAML.format(comment="  # aws-arch-agent: ignore CF-S3-001, CF-DEL-001\n"),
    )
    _md, _ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, iac="cloudformation")
    assert _by_id(findings, "CF-S3-001").suppression is not None
    assert _by_id(findings, "CF-DEL-001").suppression is not None
    assert _by_id(findings, "CF-S3-005").suppression is None


def test_cloudformation_json_metadata(tmp_path: Path) -> None:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Metadata": {
                    "aws-arch-agent": {
                        "ignore": [
                            "CF-S3-001",
                            {"id": "CF-S3-005", "reason": "public", "expires": "2099-01-01"},
                            {"id": "CF-DEL-001", "expires": "2000-01-01"},
                        ]
                    }
                },
            }
        },
    }
    _write(tmp_path, "stack.json", json.dumps(template, indent=2))
    _md, _ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False, iac="cloudformation")
    assert _by_id(findings, "CF-S3-001").suppression == Suppression(kind="metadata")
    assert _by_id(findings, "CF-S3-005").suppression == Suppression(
        kind="metadata", reason="public", expires="2099-01-01"
    )
    assert _by_id(findings, "CF-DEL-001").suppression is None
    assert any("CF-DEL-001" in w and "expired on 2000-01-01" in w for w in warnings)


def test_cloudformation_yaml_metadata_with_yaml_date(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "stack.yaml",
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Metadata:\n      aws-arch-agent:\n"
        "        ignore:\n          - {id: CF-S3-001, expires: 2099-01-01}\n",
    )
    _md, _ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, iac="cloudformation")
    assert _by_id(findings, "CF-S3-001").suppression == Suppression(
        kind="metadata", expires="2099-01-01"
    )


# --- expiry and malformed input ------------------------------------------------------------------


def test_expiry_active_through_its_day_then_warns(tmp_path: Path) -> None:
    _write(tmp_path, "main.tf", "# aws-arch-agent: ignore CF-S3-001 expires=2026-11-22\nresource\n")
    finding = _finding("CF-S3-001", "main.tf", 2)
    assert suppressions.apply([finding], tmp_path, today=TODAY) == []
    assert finding.suppression == Suppression(kind="inline", expires="2026-11-22")

    warnings = suppressions.apply([finding], tmp_path, today=date(2026, 11, 23))
    assert finding.suppression is None
    assert warnings == [
        "Suppression of CF-S3-001 at main.tf:1 expired on 2026-11-22; the finding is reported again."
    ]


def test_malformed_directive_warns_and_does_not_suppress(tmp_path: Path) -> None:
    _write(tmp_path, "main.tf", "# aws-arch-agent: ignore CF-S3-001 expires=2026-02-30\nresource\n")
    finding = _finding("CF-S3-001", "main.tf", 2)
    warnings = suppressions.apply([finding, _finding("CF-S3-003", "main.tf", 2)], tmp_path, today=TODAY)
    assert finding.suppression is None
    assert len(warnings) == 1
    assert "Malformed aws-arch-agent ignore directive at main.tf:1" in warnings[0]


def test_unknown_rule_ids_and_missing_files_do_not_crash(tmp_path: Path) -> None:
    _write(tmp_path, "main.tf", "# aws-arch-agent: ignore NOPE-999\nresource\n")
    findings = [
        _finding("CF-S3-001", "main.tf", 2),
        _finding("CF-S3-001", "gone.tf", 3),
        _finding("CF-S3-001", "main.tf", 1),
        Finding(id="REPO-001", title="t", recommendation="r"),
    ]
    assert suppressions.apply(findings, tmp_path, today=TODAY) == []
    assert all(f.suppression is None for f in findings)


@pytest.mark.parametrize(
    "ignore, error",
    [
        ('"CF-S3-001"', "must be a mapping with an ignore list"),
        ('{"ignore": [42]}', "ignore entry must be a rule ID"),
        ('{"ignore": [{"reason": "x"}]}', "needs id"),
        ('{"ignore": [{"id": "CF-S3-001", "expires": "soon"}]}', "expires of CF-S3-001"),
        ('{"ignore": [{"id": "CF-S3-001", "reason": 3}]}', "reason of CF-S3-001"),
    ],
)
def test_malformed_metadata_warns(tmp_path: Path, ignore: str, error: str) -> None:
    text = (
        '{\n  "Resources": {\n    "Bucket": {\n      "Type": "AWS::S3::Bucket",\n'
        f'      "Metadata": {{"aws-arch-agent": {ignore}}}\n    }}\n  }}\n}}\n'
    )
    _write(tmp_path, "stack.json", text)
    finding = _finding("CF-S3-001", "stack.json", 3)
    warnings = suppressions.apply([finding], tmp_path, today=TODAY)
    assert finding.suppression is None
    assert len(warnings) == 1 and "Malformed aws-arch-agent Metadata on Bucket" in warnings[0]
    assert error in warnings[0]


def test_absolute_template_path_outside_repo(tmp_path: Path) -> None:
    outside = _write(tmp_path / "elsewhere", "stack.yaml", BUCKET_YAML.format(
        comment="  # aws-arch-agent: ignore CF-S3-001\n"
    ))
    finding = _finding("CF-S3-001", str(outside), 4)
    suppressions.apply([finding], tmp_path / "repo", today=TODAY)
    assert finding.suppression is not None


# --- reports ------------------------------------------------------------------------------------


def _suppressed() -> Finding:
    finding = _finding("CF-S3-001", "stack.yaml", 3)
    finding.suppression = Suppression(kind="inline", reason="logs bucket", expires="2027-01-31")
    return finding


def test_reports_label_suppressed_findings() -> None:
    ctx = RepoContext(repo_path="/r")
    md = render_markdown(ctx, [_suppressed()])
    assert "- Suppressed: **1** finding(s)" in md
    assert "- Status: **suppressed (inline comment, expires 2027-01-31)** — `logs bucket`" in md

    html = render_html(ctx, [_suppressed()])
    assert 'data-suppressed="true"' in html
    assert "suppressed (inline comment, expires 2027-01-31)" in html and "logs bucket" in html

    item = json.loads(render_json(ctx, [_suppressed()]))["findings"][0]
    assert item["suppression"] == {"kind": "inline", "reason": "logs bucket", "expires": "2027-01-31"}
    plain = json.loads(render_json(ctx, [_finding("CF-S3-001", "stack.yaml", 3)]))["findings"][0]
    assert plain["suppression"] is None


def test_json_report_with_suppression_validates() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    from aws_arch_agent.report.schema import REPORT_SCHEMA

    data = json.loads(render_json(RepoContext(repo_path="/r"), [_suppressed()]))
    jsonschema.validate(data, REPORT_SCHEMA)


# --- --fail-on ----------------------------------------------------------------------------------


def _fail_on(tmp_path: Path, *extra: str) -> int:
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--no-llm", "--fail-on", "high",
         "--out", str(tmp_path / "report.md"), *extra],
    )
    return result.exit_code


def test_fail_on_ignores_suppressed_findings(tmp_path: Path) -> None:
    _cdk_ts_repo(tmp_path)
    assert _fail_on(tmp_path) == 1
    _cdk_ts_repo(tmp_path, '// aws-arch-agent: ignore SEC-005 reason="public" expires=2099-12-31\n')
    assert _fail_on(tmp_path) == 0
    assert "suppressed (inline comment, expires 2099-12-31)" in (tmp_path / "report.md").read_text()


def test_fail_on_counts_expired_suppression(tmp_path: Path) -> None:
    _cdk_ts_repo(tmp_path, "// aws-arch-agent: ignore SEC-005 expires=2001-01-01\n")
    # The expiry warning is a scan warning, which exits 2 before the fail-on exit of 1.
    assert _fail_on(tmp_path) == 2
    report = (tmp_path / "report.md").read_text()
    assert "Suppression of SEC-005 at lib/stack.ts:2 expired on 2001-01-01" in report


def test_fail_on_with_enforce_baseline_and_suppression(tmp_path: Path) -> None:
    _cdk_ts_repo(tmp_path, "// aws-arch-agent: ignore SEC-005\n")
    assert _fail_on(tmp_path, "--enforce-baseline") == 0


# --- rules.exclude_paths ------------------------------------------------------------------------


def _config(root: Path, rules: dict) -> None:
    _write(root, ".aws-arch-agent.json", json.dumps({"rules": rules}))


def test_exclude_paths_config_parsed(tmp_path: Path) -> None:
    _config(tmp_path, {"exclude_paths": {"./lib/**": ["SEC-005"], "test/*.ts": ["REL-031", "X"]}})
    cfg = load_config(tmp_path)
    assert cfg.rules_exclude_paths == {"lib/**": ["SEC-005"], "test/*.ts": ["REL-031", "X"]}
    assert load_config(tmp_path / "missing").rules_exclude_paths is None


@pytest.mark.parametrize(
    "value",
    [
        ["lib/**"],
        {"lib/**": "SEC-005"},
        {"lib/**": [1]},
        {"lib/**": [""]},
        {"": ["SEC-005"]},
        {"/abs/**": ["SEC-005"]},
        {"C:/abs/**": ["SEC-005"]},
    ],
)
def test_exclude_paths_config_invalid(tmp_path: Path, value: object) -> None:
    _config(tmp_path, {"exclude_paths": value})
    with pytest.raises(ConfigError, match="rules.exclude_paths"):
        load_config(tmp_path)


def test_exclude_by_path_matching() -> None:
    findings = [
        _finding("SEC-005", "lib/stack.ts", 1),
        _finding("SEC-005", "lib/deep/stack.ts", 1),
        _finding("SEC-005", "other/stack.ts", 1),
        _finding("REL-031", "lib/stack.ts", 1),
        Finding(id="SEC-005", title="t", recommendation="r"),
    ]
    kept = suppressions.exclude_by_path(findings, {"lib/*.ts": ["SEC-005"]})
    assert [(f.id, f.file) for f in kept] == [
        ("SEC-005", "lib/deep/stack.ts"), ("SEC-005", "other/stack.ts"),
        ("REL-031", "lib/stack.ts"), ("SEC-005", None),
    ]
    assert len(suppressions.exclude_by_path(findings, {"lib/**": ["SEC-005"]})) == 3


def test_exclude_paths_v1(tmp_path: Path) -> None:
    _cdk_ts_repo(tmp_path)
    _md, _ctx, findings, _w = analyze_v1(
        tmp_path, use_llm=False, rules_exclude_paths={"lib/**": ["SEC-005"]}
    )
    ids = {f.id for f in findings}
    assert "SEC-005" not in ids and "REL-031" in ids


def test_exclude_paths_v1_via_cli(tmp_path: Path) -> None:
    _cdk_ts_repo(tmp_path)
    _config(tmp_path, {"exclude_paths": {"lib/**": ["SEC-005"]}})
    assert _fail_on(tmp_path) == 0


def test_exclude_paths_and_suppression_v2(tmp_path: Path) -> None:
    pytest.importorskip("langgraph")
    from aws_arch_agent.agent.v2_graph import analyze_v2

    _cdk_ts_repo(tmp_path, "// aws-arch-agent: ignore REL-031\n")
    report, _ctx, findings, _w = analyze_v2(
        tmp_path, use_llm=False, skip_synth=True, rules_exclude_paths={"lib/*.ts": ["SEC-005"]}
    )
    ids = {f.id for f in findings}
    assert "SEC-005" not in ids
    assert _by_id(findings, "REL-031").suppression is not None
    assert "suppressed (inline comment)" in report


def test_suppression_v2_templates(tmp_path: Path) -> None:
    pytest.importorskip("langgraph")
    from aws_arch_agent.agent.v2_graph import analyze_v2

    _write(tmp_path, "stack.yaml", BUCKET_YAML.format(
        comment="  # aws-arch-agent: ignore CF-S3-001 expires=2001-01-01\n"
                "  # aws-arch-agent: ignore CF-S3-005\n"
    ))
    _r, _ctx, findings, warnings = analyze_v2(
        tmp_path, use_llm=False, templates_path=str(tmp_path / "stack.yaml"),
        iac="cloudformation",
    )
    assert _by_id(findings, "CF-S3-005").suppression is not None
    # Only the line above the logical ID counts, so the expired directive two lines up is unseen.
    assert _by_id(findings, "CF-S3-001").suppression is None
    assert not any("expired" in w for w in warnings)


def test_metadata_timestamp_expiry_does_not_crash() -> None:
    """An unquoted YAML timestamp is a datetime: it compares by its date, never raises."""
    from datetime import date, datetime

    from aws_arch_agent.suppressions import _metadata_rules

    resource = {"Metadata": {"aws-arch-agent": {"ignore": [
        {"id": "CF-S3-001", "expires": datetime(2027, 1, 31, 10, 0)}]}}}
    rules, errors = _metadata_rules(resource)
    assert errors == [] and rules[0].expires == date(2027, 1, 31)
    assert rules[0].expires < date(2027, 2, 1)
