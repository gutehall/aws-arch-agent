"""Rule themes."""
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.report.sarif import render_sarif
from aws_arch_agent.report.summary import build_summary
from aws_arch_agent.rules.cf_template import CF_THEMES
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.themes import DOC_END, DOC_START, THEMES, docs_table, parse, select, themes_of

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "src" / "aws_arch_agent" / "rules"


def test_every_registered_rule_has_a_theme() -> None:
    """Done when: enforced by this test."""
    missing = [r.id for r in ALL_RULES if not r.themes]
    assert missing == []
    bad = {r.id: t for r in ALL_RULES for t in r.themes if t not in THEMES}
    assert bad == {}


def test_every_template_check_the_code_can_emit_has_a_theme() -> None:
    emitted = set()
    for path in RULES_DIR.glob("*.py"):
        emitted |= set(re.findall(r'"(CF-[A-Z0-9]+(?:-V2)?-\d{3})"', path.read_text(encoding="utf-8")))
    assert emitted, "no CF ids found"
    assert sorted(emitted - set(CF_THEMES)) == []
    assert {t for themes in CF_THEMES.values() for t in themes} <= set(THEMES)
    assert all(CF_THEMES.values())


def test_themes_are_set_on_the_rule_definitions() -> None:
    """The class declares them; no rule inherits an empty default."""
    for rule in ALL_RULES:
        assert "themes" in type(rule).__dict__, rule.id


def test_docs_list_themes_per_rule() -> None:
    doc = (ROOT / "docs" / "CF_RULES.md").read_text(encoding="utf-8")
    block = doc.split(DOC_START, 1)[1].split(DOC_END, 1)[0].strip()
    assert block == docs_table()


def test_parse_and_select() -> None:
    assert parse(["finops,identity", "finops"]) == ["finops", "identity"]
    with pytest.raises(ValueError, match="unknown theme"):
        parse(["money"])
    a = Finding(id="CF-EBS-002", title="t", recommendation="r", themes=["finops"])
    b = Finding(id="CF-SG-001", title="t", recommendation="r", themes=["network-exposure"])
    assert select([a, b], ["finops"]) == [a]
    assert select([a, b], None) == [a, b]
    assert themes_of("CF-GEN-001") == ("finops", "sustainability")
    assert themes_of("SEC-001") == ("identity",)
    assert themes_of("NOPE") == ()


STACK = {
    "Data": {"Type": "AWS::EC2::Volume", "Properties": {
        "AvailabilityZone": "us-east-1a", "Size": 100, "VolumeType": "gp2", "Encrypted": True}},
    "Open": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "x", "SecurityGroupIngress": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}},
    "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
    "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {}},
}


def _scan(tmp_path: Path, *args: str) -> dict:
    (tmp_path / "stack.json").write_text(
        json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": STACK}), encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "json",
                                      "--out", str(out), *args])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text())


def test_theme_finops_returns_only_cost_findings(tmp_path: Path) -> None:
    """Done when: --theme finops returns only cost-related findings."""
    everything = _scan(tmp_path)["findings"]
    assert any("finops" not in f["themes"] for f in everything)
    data = _scan(tmp_path, "--theme", "finops")
    findings = data["findings"]
    assert findings and all("finops" in f["themes"] for f in findings)
    assert {f["id"] for f in findings} >= {"CF-EBS-002", "CF-CW-001"}
    assert "CF-SG-001" not in {f["id"] for f in findings}
    assert data["context"]["notes"]["themes"] == ["finops"]
    assert data["summary"]["findings"] == len(findings)


def test_config_themes_and_validation(tmp_path: Path) -> None:
    (tmp_path / ".aws-arch-agent.yaml").write_text("themes: [network-exposure]\n", encoding="utf-8")
    assert load_config(tmp_path).themes == ["network-exposure"]
    ids = {f["id"] for f in _scan(tmp_path)["findings"]}
    assert "CF-SG-001" in ids and "CF-EBS-002" not in ids
    (tmp_path / ".aws-arch-agent.yaml").write_text("themes: [money]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown theme"):
        load_config(tmp_path)
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--theme", "nope",
                                      "--out", str(tmp_path / "x.md")])
    assert result.exit_code != 0


def _f(rid: str, themes: list[str], severity: str = "Low") -> Finding:
    return Finding(id=rid, title=f"t {rid}", severity=severity, category="Security", recommendation="r",
                   themes=themes)


def test_markdown_groups_by_theme_and_sarif_carries_themes() -> None:
    items = [_f("CF-S3-005", ["data-protection", "network-exposure"], "Medium"), _f("CF-EBS-002", ["finops"])]
    md = render_markdown(RepoContext(repo_path="/r"), items, group_by="theme")
    assert "## Theme: finops" in md and "## Theme: network-exposure" in md
    assert md.count("### [CF-S3-005]") == 2  # under both of its themes
    assert "## Medium Priority Findings" not in md
    assert "- Themes: data-protection, network-exposure" in render_markdown(RepoContext(repo_path="/r"), items)
    run = json.loads(render_sarif(RepoContext(repo_path="/r"), items))["runs"][0]
    assert run["results"][0]["properties"]["themes"] == ["data-protection", "network-exposure"]
    assert run["tool"]["driver"]["rules"][1]["properties"]["tags"] == ["finops"]


def test_summary_has_a_line_per_theme() -> None:
    items = [_f("CF-S3-005", ["data-protection", "network-exposure"]), _f("CF-EBS-002", ["finops"])]
    summary = build_summary(items)
    assert [row["name"] for row in summary["themes"]] == ["finops", "data-protection", "network-exposure"]
    assert "**By theme** (a finding can be in more than one):" in render_markdown(RepoContext(repo_path="/r"), items)


def test_html_theme_filter(tmp_path: Path) -> None:
    (tmp_path / "stack.json").write_text(
        json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": STACK}), encoding="utf-8")
    out = tmp_path / "r.html"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "html", "--out", str(out)])
    assert result.exit_code == 0, result.output
    html = out.read_text()
    assert 'id="theme-filter"' in html and '<option value="finops">finops (' in html
    assert 'data-themes="finops"' in html


def test_empty_theme_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="names no theme"):
        load_config(tmp_path, themes=[""])
    (tmp_path / ".aws-arch-agent.yaml").write_text("themes: ['']\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="names no theme"):
        load_config(tmp_path)


def test_v2_filters_before_the_pillar_notes(tmp_path: Path) -> None:
    from aws_arch_agent.agent.v2_graph import analyze_v2

    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "s.template.json").write_text(json.dumps({"Resources": STACK}), encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    report, _ctx, findings, _w = analyze_v2(tmp_path, use_llm=False, templates_path=str(tmp_path / "templates"),
                                            theme_filter=["finops"])
    assert findings and all("finops" in f.themes for f in findings)
    assert "CF-SG-001" not in report and "SEC-005" not in report  # not even in the pillar notes
