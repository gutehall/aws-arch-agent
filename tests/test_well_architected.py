"""The Well-Architected catalog, the rule mapping, and the per-question answers."""
import json
import re
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.models import Finding, RepoContext, Verdict
from aws_arch_agent.report.html import render_html
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.rules import wa_map, well_architected
from aws_arch_agent.rules.cf_template import CF_THEMES, CF_TITLES
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.themes import themes_of
from aws_arch_agent.rules.well_architected import (
    answers,
    best_practices_of,
    question_id_of_practice,
    question_of,
    questions,
)

RULES_DIR = Path(__file__).resolve().parents[1] / "src" / "aws_arch_agent" / "rules"
ALL_BEST_PRACTICES = {bp.id for q in questions() for bp in q.best_practices}
CFN_TEMPLATE = {"Resources": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
TF_MAIN = 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'


def _rule_ids() -> set[str]:
    """Every id a scan can report: CDK rules, and template checks named anywhere in rules/."""
    emitted = set()
    for path in RULES_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        emitted |= set(re.findall(r'"(CF-[A-Z0-9]+(?:-V2)?-\d{3})"', text))
    return {r.id for r in ALL_RULES} | set(CF_TITLES) | set(CF_THEMES) | emitted


def _ctx() -> RepoContext:
    return RepoContext(repo_path="/repo", language="typescript", files_scanned=1)


def _finding(rule_id: str) -> Finding:
    return Finding(id=rule_id, title=f"title of {rule_id}", recommendation="fix it")


def test_catalog_lists_every_question_and_best_practice() -> None:
    qs = questions()
    assert len(qs) == 57
    assert len(ALL_BEST_PRACTICES) == 307
    assert sum(len(q.best_practices) for q in qs) == 307
    assert len({q.id for q in qs}) == 57
    per_pillar = {}
    for q in qs:
        per_pillar[q.pillar] = per_pillar.get(q.pillar, 0) + 1
        assert q.title and q.url.startswith("https://docs.aws.amazon.com/wellarchitected/")
        for bp in q.best_practices:
            assert question_id_of_practice(bp.id) == q.id, bp.id
            assert bp.title
    assert per_pillar == {
        "Operational Excellence": 11, "Security": 11, "Reliability": 13,
        "Performance Efficiency": 5, "Cost Optimization": 11, "Sustainability": 6,
    }


def test_every_rule_maps_to_best_practices_of_one_question() -> None:
    ids = _rule_ids()
    assert sorted(ids - set(wa_map.RULE_BEST_PRACTICES)) == []
    assert sorted(set(wa_map.RULE_BEST_PRACTICES) - ids) == []
    for rule_id, bps in wa_map.RULE_BEST_PRACTICES.items():
        assert bps, rule_id
        assert set(bps) <= ALL_BEST_PRACTICES, rule_id
        assert len({question_id_of_practice(bp) for bp in bps}) == 1, rule_id


def test_every_best_practice_has_a_rule() -> None:
    """CI fails here when a best practice has no rule and is not listed as not checked yet.

    A check that covers a best practice must also remove it from NOT_CHECKED, so the list
    only shrinks until every best practice has a rule.
    """
    covered = {bp for bps in wa_map.RULE_BEST_PRACTICES.values() for bp in bps}
    assert sorted(wa_map.NOT_CHECKED - ALL_BEST_PRACTICES) == []
    assert sorted(ALL_BEST_PRACTICES - covered - wa_map.NOT_CHECKED) == []
    assert sorted(covered & wa_map.NOT_CHECKED) == []


def test_rules_store_question_and_best_practices() -> None:
    for rule in ALL_RULES:
        assert rule.best_practices == best_practices_of(rule.id)
        assert rule.question == question_id_of_practice(rule.best_practices[0])
    assert question_of("CF-RDS-001") == "SEC 8"
    assert best_practices_of("CF-RDS-001") == ("SEC08-BP02",)
    assert question_of("NOPE-001") is None


def test_question_id_of_practice() -> None:
    assert question_id_of_practice("SEC08-BP02") == "SEC 8"
    assert question_id_of_practice("PERF01-BP07") == "PERF 1"
    assert question_id_of_practice("REL13-BP05") == "REL 13"


def test_annotate_sets_question_on_findings() -> None:
    f = _finding("CF-S3-005")
    well_architected.annotate([f])
    assert f.question == "SEC 9"
    assert f.best_practices == ["SEC09-BP02"]


def _unchecked(question: str) -> list[str]:
    covered = {bp for bps in wa_map.RULE_BEST_PRACTICES.values() for bp in bps}
    q = next(q for q in questions() if q.id == question)
    return [bp.id for bp in q.best_practices if bp.id not in covered]


def test_answers_one_per_question_from_findings() -> None:
    items = answers([_finding("CF-S3-005"), _finding("CF-S3-005"), _finding("CF-RDS-001")])
    assert [a.question.id for a in items] == [q.id for q in questions()]
    by_id = {a.question.id: a for a in items}
    # SEC 9: every best practice has a rule, and two findings fall under it.
    assert not by_id["SEC 9"].met
    assert by_id["SEC 9"].not_checked == ()
    assert by_id["SEC 9"].reason() == "2 findings"
    # SEC 4: every best practice has a rule and no finding: met.
    assert by_id["SEC 4"].met and by_id["SEC 4"].reason() == ""
    # SEC 8: one finding, plus whatever no rule checks yet.
    left = _unchecked("SEC 8")
    assert list(by_id["SEC 8"].not_checked) == left
    expected = "1 finding" + (f"; {len(left)} of 4 best practices not checked" if left else "")
    assert by_id["SEC 8"].reason() == expected
    # Nothing checks OPS 1, so it is not met even with no findings.
    assert _unchecked("OPS 1")
    assert not by_id["OPS 1"].met and not by_id["OPS 1"].findings


def test_unchecked_best_practices_follow_the_mapping_not_the_list(monkeypatch) -> None:
    """A best practice missing from both tables is still not checked."""
    monkeypatch.setattr(wa_map, "NOT_CHECKED", frozenset())
    assert not {a.question.id: a for a in answers([])}["OPS 1"].met


def test_rules_that_did_not_run_check_nothing() -> None:
    # Only CDK rules ran: SEC 4 is met only if CDK rules alone cover all of it.
    cdk_ids = [r.id for r in ALL_RULES]
    cdk_bps = {bp for rid in cdk_ids for bp in best_practices_of(rid)}
    sec4 = next(q for q in questions() if q.id == "SEC 4")
    by_id = {a.question.id: a for a in answers([], cdk_ids)}
    assert by_id["SEC 4"].met == all(bp.id in cdk_bps for bp in sec4.best_practices)
    # No rule ran: nothing is met, and every best practice is not checked.
    for a in answers([], []):
        assert not a.met
        assert len(a.not_checked) == len(a.question.best_practices)


def test_rules_run_follows_source_config_theme_and_severity() -> None:
    active = ["SEC-001", "CF-S3-001", "CF-CW-001"]
    assert well_architected.rules_run(active, cdk=True, templates=False) == ["SEC-001"]
    assert well_architected.rules_run(active, cdk=False, templates=True) == [
        "CF-S3-001", "CF-CW-001"]
    finops = well_architected.rules_run(active, cdk=True, templates=True, theme_filter=["finops"])
    assert finops == [rid for rid in active if "finops" in themes_of(rid)]
    assert well_architected.rules_run(active, cdk=True, templates=True,
                                      severity_threshold="high") == []
    assert well_architected.rules_run(active, cdk=True, templates=True,
                                      severity_threshold="low") == active


def test_a_filtered_scan_answers_nothing_met(tmp_path: Path) -> None:
    (tmp_path / "stack.template.json").write_text(json.dumps(CFN_TEMPLATE), encoding="utf-8")
    report, ctx, _f, _w = analyze_v1(tmp_path, use_llm=False, severity_threshold="high")
    assert ctx.rules_run == []
    assert "0 of 57 questions met." in report


def test_verdicts_do_not_change_the_answers() -> None:
    plain = _finding("CF-RDS-001")
    judged = _finding("CF-RDS-001")
    judged.verdict = Verdict(verdict="false_positive", why="test")
    assert [a.to_dict() for a in answers([plain])] == [a.to_dict() for a in answers([judged])]


def test_markdown_has_one_line_per_question_with_findings_under_it() -> None:
    findings = [_finding("CF-S3-005"), _finding("CF-S3-005")]
    report = render_markdown(_ctx(), findings)
    section = report.split("## Well-Architected answers", 1)[1].split("\n## ", 1)[0]
    lines = [ln for ln in section.splitlines() if ln.startswith("- **")]
    assert len(lines) == 57
    assert "- **SEC 9** How do you protect your data in transit? — **not met** (2 findings)" in lines
    assert "- **SEC 4** How do you detect and investigate security events? — **met**" in lines
    assert "  - [CF-S3-005] title of CF-S3-005 ×2" in section
    met = sum(1 for a in answers(findings) if a.met)
    assert f"{met} of 57 questions met." in section


def test_json_report_has_answers() -> None:
    data = json.loads(render_json(_ctx(), [_finding("CF-RDS-001")]))
    assert len(data["answers"]) == 57
    sec8 = next(a for a in data["answers"] if a["question"] == "SEC 8")
    assert sec8 == {
        "question": "SEC 8",
        "pillar": "Security",
        "title": "How do you protect your data at rest?",
        "status": "not met",
        "findings": ["CF-RDS-001"],
        "not_checked": _unchecked("SEC 8"),
    }
    assert data["findings"][0]["question"] == "SEC 8"
    assert data["findings"][0]["best_practices"] == ["SEC08-BP02"]


def test_html_report_has_answers_escaped() -> None:
    f = _finding("CF-RDS-001")
    f.title = "<script>alert(1)</script>"
    page = render_html(_ctx(), [f])
    section = page.split('<section class="answers"', 1)[1].split("</section>", 1)[0]
    assert "Well-Architected answers" in section
    assert section.count("<li><b>") == 57
    assert "[CF-RDS-001] &lt;script&gt;alert(1)&lt;/script&gt;" in section
    assert "<script>alert" not in section


@pytest.mark.parametrize("source", ["cloudformation", "terraform"])
def test_template_scans_answer_from_the_same_catalog(tmp_path: Path, source: str) -> None:
    if source == "cloudformation":
        (tmp_path / "stack.template.json").write_text(json.dumps(CFN_TEMPLATE), encoding="utf-8")
    else:
        (tmp_path / "main.tf").write_text(TF_MAIN, encoding="utf-8")
    report, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    assert ctx.source == source
    s3 = next(f for f in findings if f.id == "CF-S3-001")
    assert (s3.question, s3.best_practices) == ("SEC 3", ["SEC03-BP07"])
    assert "- **SEC 3** How do you manage permissions for people and machines? — **not met**" in report
    assert "  - [CF-S3-001] " in report


def test_v2_writes_the_answers_from_findings_without_asking(tmp_path: Path, monkeypatch) -> None:
    def no_input(*_args, **_kwargs):
        raise AssertionError("V2 asked the operator")

    monkeypatch.setattr("builtins.input", no_input)
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    report, ctx, findings, _warnings = analyze_v2(tmp_path, use_llm=False, skip_synth=True)
    # No synth: the template checks did not run, so they check nothing here.
    assert ctx.rules_run and not any(rid.startswith("CF-") for rid in ctx.rules_run)
    assert "## Well-Architected answers" in report
    section = report.split("## Well-Architected answers", 1)[1].split("\n## ", 1)[0]
    assert len([ln for ln in section.splitlines() if ln.startswith("- **")]) == 57
    for a in answers(findings, ctx.rules_run):
        assert f"- **{a.question.id}** {a.question.title} — **{a.status}**" in section
    assert all(f.question == question_of(f.id) for f in findings)
