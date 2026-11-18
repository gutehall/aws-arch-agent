"""The AI lens catalog and the lens answers. The 57 core questions stay as they are."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import lens_map, lenses, well_architected
from aws_arch_agent.rules.well_architected import question_id_of_practice

DATA = Path(lenses.DATA_PATH)

QUESTIONS_PER_LENS = {"machine-learning": 35, "generative-ai": 29, "responsible-ai": 28,
                      "agentic-ai": 41}
PRACTICES_PER_LENS = {"machine-learning": 105, "generative-ai": 51, "responsible-ai": 98,
                      "agentic-ai": 150}


def _catalog() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def test_catalog_counts_and_source_per_lens() -> None:
    data = _catalog()
    assert set(data["lenses"]) == set(lenses.LENSES)
    for lens, meta in data["lenses"].items():
        assert meta["_source"].startswith("https://docs.aws.amazon.com/wellarchitected/")
        assert meta["_as_of"]
    qs = data["questions"]
    assert len(qs) == 133
    assert sum(len(q["best_practices"]) for q in qs) == 404
    for lens in lenses.LENSES:
        mine = [q for q in qs if q["lens"] == lens]
        assert len(mine) == QUESTIONS_PER_LENS[lens], lens
        assert sum(len(q["best_practices"]) for q in mine) == PRACTICES_PER_LENS[lens], lens
    assert len({q["id"] for q in qs}) == 133
    assert len({b["id"] for q in qs for b in q["best_practices"]}) == 404


def test_every_practice_id_parses_to_its_question_id() -> None:
    for q in _catalog()["questions"]:
        assert q["title"] and q["pillar"] and q["url"].startswith("https://docs.aws.amazon.com/")
        assert q["best_practices"], q["id"]
        for bp in q["best_practices"]:
            assert question_id_of_practice(bp["id"]) == q["id"], bp["id"]


def test_named_practices_belong_to_the_documented_questions() -> None:
    assert question_id_of_practice("GENSEC01-BP01") == "GENSEC 1"
    assert question_id_of_practice("RAISP02-BP02") == "RAISP 2"
    assert question_id_of_practice("AGENTREL02-BP05") == "AGENTREL 2"
    ids = {bp.id for q in lenses.questions() for bp in q.best_practices}
    assert {"GENSEC01-BP01", "RAISP02-BP02", "AGENTREL02-BP05"} <= ids


def test_responsible_ai_pillar_is_the_focus_area() -> None:
    framework = {"Operational Excellence", "Security", "Reliability",
                 "Performance Efficiency", "Cost Optimization", "Sustainability"}
    rai = {q.pillar for q in lenses.questions() if q.lens == "responsible-ai"}
    assert rai and not rai & framework


def test_core_catalog_is_not_merged_with_the_lenses() -> None:
    assert len(well_architected.questions()) == 57
    assert sum(len(q.best_practices) for q in well_architected.questions()) == 307
    core_ids = {q.id for q in well_architected.questions()}
    assert not core_ids & {q.id for q in lenses.questions()}


def test_every_lens_practice_is_in_the_map_or_not_checked() -> None:
    mapped = {bp for bps in lens_map.LENS_RULE_BEST_PRACTICES.values() for bp in bps}
    every = {bp.id for q in lenses.questions() for bp in q.best_practices}
    assert every == mapped | lens_map.LENS_NOT_CHECKED
    assert not mapped & lens_map.LENS_NOT_CHECKED


def test_each_lens_rule_answers_one_lens_question() -> None:
    every = {bp.id for q in lenses.questions() for bp in q.best_practices}
    for rid, bps in lens_map.LENS_RULE_BEST_PRACTICES.items():
        assert bps and set(bps) <= every, rid
        assert len({question_id_of_practice(b) for b in bps}) == 1, rid


def test_lens_answers_has_one_answer_per_lens_question() -> None:
    out = lenses.lens_answers([])
    assert len(out) == 133
    assert [a.question.id for a in out] == [q.id for q in lenses.questions()]
    for a in out:
        assert a.lens in lenses.LENSES
        if a.question.best_practices and not any(
            bp.id in {b for bps in lens_map.LENS_RULE_BEST_PRACTICES.values() for b in bps}
            for bp in a.question.best_practices
        ):
            assert a.status == "not met"
            assert a.not_checked == tuple(bp.id for bp in a.question.best_practices)
    assert a.to_dict()["lens"] == a.lens


def test_lens_only_finding_is_not_under_a_core_question(monkeypatch) -> None:
    monkeypatch.setitem(lens_map.LENS_RULE_BEST_PRACTICES, "CF-TEST-LENS-001",
                        ("GENSEC02-BP01",))
    lenses._rules_by_practice.cache_clear()
    try:
        f = Finding(id="CF-TEST-LENS-001", title="t", recommendation="r")
        well_architected.annotate([f])
        assert f.question == "GENSEC 2"
        assert f.best_practices == ["GENSEC02-BP01"]
        assert all(not a.findings for a in well_architected.answers([f]))
        under = {a.question.id: a for a in lenses.lens_answers([f])}
        assert under["GENSEC 2"].findings == (f,)
        assert under["GENSEC 2"].status == "not met"
    finally:
        lenses._rules_by_practice.cache_clear()


# --- the AI gate and the reports ----------------------------------------------------------

import pytest  # noqa: E402

from aws_arch_agent.agent.v1 import analyze_v1  # noqa: E402
from aws_arch_agent.agent.v2_graph import analyze_v2  # noqa: E402
from aws_arch_agent.config import ConfigError, lenses_ai_setting  # noqa: E402
from aws_arch_agent.models import RepoContext  # noqa: E402
from aws_arch_agent.report.html import render_html  # noqa: E402
from aws_arch_agent.report.json_report import render_json  # noqa: E402
from aws_arch_agent.report.markdown import render_markdown  # noqa: E402

S3_ONLY = {"Resources": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
BEDROCK = {"Resources": {"Agent": {"Type": "AWS::Bedrock::Agent", "Properties": {
    "AgentName": "a", "FoundationModel": "m", "Instruction": "x" * 40}}}}
NOTEBOOK = {"Resources": {"Nb": {"Type": "AWS::SageMaker::NotebookInstance", "Properties": {
    "InstanceType": "ml.t3.medium", "RoleArn": "arn:aws:iam::1:role/r"}}}}
TF_BEDROCK = 'resource "aws_bedrockagent_agent" "a" {\n  agent_name = "a"\n}\n'


def _repo(tmp_path: Path, template: dict) -> Path:
    (tmp_path / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    return tmp_path


def _lens(tmp_path: Path, template: dict, lenses_ai: bool | None = None) -> list:
    _r, ctx, findings, _w = analyze_v1(_repo(tmp_path, template), use_llm=False,
                                       lenses_ai=lenses_ai)
    return lenses.answers_for(ctx, findings)


def test_s3_only_template_has_no_lens_answers(tmp_path: Path) -> None:
    assert _lens(tmp_path, S3_ONLY) == []


@pytest.mark.parametrize("template", [BEDROCK, NOTEBOOK])
def test_an_ai_resource_turns_the_lenses_on(tmp_path: Path, template: dict) -> None:
    out = _lens(tmp_path, template)
    assert len(out) == 133
    assert {a.lens for a in out} == set(lenses.LENSES)


def test_lenses_ai_false_turns_them_off_for_a_bedrock_template(tmp_path: Path) -> None:
    assert _lens(tmp_path, BEDROCK, lenses_ai=False) == []


def test_lenses_ai_true_turns_them_on_for_an_s3_template(tmp_path: Path) -> None:
    assert len(_lens(tmp_path, S3_ONLY, lenses_ai=True)) == 133


def test_terraform_bedrock_turns_the_lenses_on(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(TF_BEDROCK, encoding="utf-8")
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    assert len(lenses.answers_for(ctx, findings)) == 133


def test_v2_honors_the_gate(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(TF_BEDROCK, encoding="utf-8")
    _r, ctx, findings, _w = analyze_v2(tmp_path, use_llm=False, skip_synth=True, iac="terraform")
    assert len(lenses.answers_for(ctx, findings)) == 133
    _r, ctx, findings, _w = analyze_v2(tmp_path, use_llm=False, skip_synth=True,
                                       iac="terraform", lenses_ai=False)
    assert lenses.answers_for(ctx, findings) == []
    off = tmp_path / "s3"
    off.mkdir()
    (off / "main.tf").write_text('resource "aws_s3_bucket" "d" {\n  bucket = "d"\n}\n',
                                 encoding="utf-8")
    _r, ctx, findings, _w = analyze_v2(off, use_llm=False, skip_synth=True, iac="terraform")
    assert lenses.answers_for(ctx, findings) == []
    _r, ctx, findings, _w = analyze_v2(off, use_llm=False, skip_synth=True, iac="terraform",
                                       lenses_ai=True)
    assert len(lenses.answers_for(ctx, findings)) == 133


def test_the_gate_does_not_touch_the_core_answers(tmp_path: Path) -> None:
    on = analyze_v1(_repo(tmp_path, BEDROCK), use_llm=False)[1]
    assert on.ai_lenses
    data = json.loads(render_json(on, []))
    assert len(data["answers"]) == 57 and len(data["lens_answers"]) == 133


@pytest.mark.parametrize("value,expected", [(None, None), ({}, None), ({"ai": True}, True),
                                            ({"ai": False}, False), ({"ai": "false"}, False)])
def test_lenses_ai_config(value, expected) -> None:
    assert lenses_ai_setting(value) is expected


@pytest.mark.parametrize("value", [True, {"ai": "maybe"}, {"other": 1}])
def test_lenses_ai_config_rejects_bad_values(value) -> None:
    with pytest.raises(ConfigError):
        lenses_ai_setting(value)


def _ctx(ai: bool = True) -> RepoContext:
    return RepoContext(repo_path="/repo", language="typescript", files_scanned=1, ai_lenses=ai)


def test_reports_show_met_and_not_met_lens_answers(monkeypatch) -> None:
    """One lens question is met (its only practice has a passing rule), one is not."""
    monkeypatch.setitem(lens_map.LENS_RULE_BEST_PRACTICES, "CF-TEST-LENS-002", ("GENSEC02-BP01",))
    monkeypatch.setitem(lens_map.LENS_RULE_BEST_PRACTICES, "CF-TEST-LENS-003", ("GENSEC03-BP01",))
    lenses._rules_by_practice.cache_clear()
    try:
        ctx = _ctx()
        ctx.rules_run = ["CF-TEST-LENS-002", "CF-TEST-LENS-003"]
        f = Finding(id="CF-TEST-LENS-003", title="no logging <b>", recommendation="r")
        well_architected.annotate([f])
        items = {a.question.id: a for a in lenses.answers_for(ctx, [f])}
        assert items["GENSEC 2"].status == "met"
        assert items["GENSEC 3"].status == "not met"

        data = json.loads(render_json(ctx, [f]))
        by_q = {a["question"]: a for a in data["lens_answers"]}
        assert by_q["GENSEC 2"]["lens"] == "generative-ai"
        assert by_q["GENSEC 2"]["status"] == "met"
        assert by_q["GENSEC 3"]["status"] == "not met"
        assert by_q["GENSEC 3"]["findings"] == ["CF-TEST-LENS-003"]
        assert len(data["answers"]) == 57

        md = render_markdown(ctx, [f])
        assert "### Generative AI Lens" in md and "### Machine Learning Lens" in md
        assert "- **GENSEC 2**" in md and "— **met**" in md
        assert "- **GENSEC 3** How do you monitor and audit events" in md
        assert "  - [CF-TEST-LENS-003] no logging <b>" in md

        page = render_html(ctx, [f])
        section = page.split('<section id="view-answers"', 1)[1].split("</section>", 1)[0]
        assert "Generative AI Lens" in section and 'data-lens="agentic-ai"' in section
        assert section.count('<article class="answer') == 57 + 133
        assert "no logging &lt;b&gt;" in section and "no logging <b>" not in section
    finally:
        lenses._rules_by_practice.cache_clear()


def test_an_empty_lens_list_adds_no_section_and_leaves_core_answers() -> None:
    ctx = _ctx(ai=False)
    data = json.loads(render_json(ctx, []))
    assert data["lens_answers"] == [] and len(data["answers"]) == 57
    md = render_markdown(ctx, [])
    assert "lens answers" not in md.lower() and "Lens\n" not in md
    assert "## Well-Architected answers" in md
    page = render_html(ctx, [])
    assert 'class="lens-group"' not in page and "AI Well-Architected" not in page
    assert page.count('<article class="answer') == 57


def test_schema_requires_lens_on_each_lens_answer() -> None:
    from aws_arch_agent.report.schema import REPORT_SCHEMA

    item = REPORT_SCHEMA["properties"]["lens_answers"]["items"]
    assert "lens" in item["required"] and "lens" in item["properties"]
