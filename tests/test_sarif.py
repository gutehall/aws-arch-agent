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
    driver_rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert any(rule["id"] == "AWS-ARCH-AGENT-WARNING" for rule in driver_rules)
    assert any(rule["id"] == "SEC-001" for rule in driver_rules)


def _sarif(findings, warnings=None) -> dict:
    return json.loads(render_sarif(RepoContext(repo_path="/repo", language="typescript"), findings, warnings))


def test_driver_metadata_and_rule_help_uri() -> None:
    from aws_arch_agent import __version__
    from aws_arch_agent.report.docs import doc_links

    f = Finding(id="CF-S3-001", title="S3 bucket", severity="High", recommendation="Block public access.",
                category="Security", file="stack.yaml", line=7)
    data = _sarif([f], warnings=["w"])
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/gutehall/aws-arch-agent"
    rule = next(r for r in driver["rules"] if r["id"] == "CF-S3-001")
    assert rule["helpUri"] == doc_links(f)[0]["url"] and rule["helpUri"].startswith("https://")
    result = data["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 7}


def test_partial_fingerprints_ignore_line_and_separate_evidence() -> None:
    base = dict(id="CF-S3-001", title="t", recommendation="r", file="stack.yaml")
    a = _sarif([Finding(**base, line=3, evidence="Bucket")])["runs"][0]["results"][0]
    b = _sarif([Finding(**base, line=30, evidence="Bucket")])["runs"][0]["results"][0]
    c = _sarif([Finding(**base, line=3, evidence="Other")])["runs"][0]["results"][0]
    key = "awsArchAgent/v1"
    assert a["partialFingerprints"][key] == b["partialFingerprints"][key]
    assert a["partialFingerprints"][key] != c["partialFingerprints"][key]


def test_inline_suppression_and_warnings_stay_unsuppressed() -> None:
    from aws_arch_agent.models import Suppression

    f = Finding(id="CF-S3-001", title="t", recommendation="r", file="stack.yaml", line=3,
                suppression=Suppression(kind="inline", reason="logs bucket", expires="2027-01-31"))
    plain = Finding(id="CF-S3-002", title="t", recommendation="r", file="stack.yaml", line=4)
    results = _sarif([f, plain], warnings=["boom"])["runs"][0]["results"]
    assert results[0]["suppressions"] == [
        {"kind": "inSource", "status": "accepted", "justification": "logs bucket; expires 2027-01-31"}
    ]
    assert "suppressions" not in results[1]
    warning = next(r for r in results if r["ruleId"] == "AWS-ARCH-AGENT-WARNING")
    assert "suppressions" not in warning and "partialFingerprints" not in warning


def test_baselined_findings_get_external_suppression(tmp_path) -> None:
    from aws_arch_agent.baseline import finding_fingerprint
    from aws_arch_agent.cli import _mark_baselined

    accepted_f = Finding(id="CF-S3-001", title="t", recommendation="r", file="stack.yaml", line=3, evidence="B")
    new_f = Finding(id="CF-S3-002", title="t", recommendation="r", file="stack.yaml", line=4, evidence="B")
    content = render_sarif(RepoContext(repo_path="/repo", language="unknown"), [accepted_f, new_f], ["warn"])
    data = json.loads(_mark_baselined(content, "sarif", [accepted_f, new_f], {finding_fingerprint(accepted_f)}))
    results = data["runs"][0]["results"]
    assert results[0]["properties"]["baselined"] is True
    assert results[0]["suppressions"] == [
        {"kind": "external", "status": "accepted", "justification": "Accepted in baseline"}
    ]
    assert results[1]["properties"]["baselined"] is False and "suppressions" not in results[1]
    assert "suppressions" not in results[2]
