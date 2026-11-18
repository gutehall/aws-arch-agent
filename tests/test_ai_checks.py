"""The AI template checks and repo-note checks. They run only for an AI workload, and each
answers one lens best practice, never a core question."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import ai_gate, lens_map, lenses, wa_map
from aws_arch_agent.rules.fix_snippets import _CLOUDFORMATION, _TERRAFORM
from aws_arch_agent.report.doc_topics import RULE_TOPICS, TOPICS
from aws_arch_agent.rules.registry import ALL_RULES

AGENT = {"Type": "AWS::Bedrock::Agent", "Properties": {"AgentName": "a"}}
GUARDED = {"Type": "AWS::Bedrock::Agent", "Properties": {
    "AgentName": "a", "IdleSessionTTLInSeconds": 600,
    "GuardrailConfiguration": {"GuardrailIdentifier": "g", "GuardrailVersion": "1"}}}
S3 = {"Type": "AWS::S3::Bucket", "Properties": {}}
ENDPOINT = {"Type": "AWS::SageMaker::Endpoint", "Properties": {"EndpointConfigName": "c"}}


def _scan(tmp_path: Path, resources: dict, files: dict[str, str] | None = None,
          **kwargs) -> tuple[set[str], object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "stack.template.json").write_text(json.dumps({"Resources": resources}),
                                                  encoding="utf-8")
    for rel, text in (files or {}).items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, **kwargs)
    return {f.id for f in findings}, findings


def test_agent_with_no_guardrail_reports_001_and_a_guarded_one_does_not(tmp_path: Path) -> None:
    ids, findings = _scan(tmp_path / "a", {"A": AGENT})
    assert {"CF-BEDROCK-001", "CF-BEDROCK-003"} <= ids
    f = next(f for f in findings if f.id == "CF-BEDROCK-001")
    assert (f.question, f.best_practices) == ("GENSEC 2", ["GENSEC02-BP01"])
    ids, _ = _scan(tmp_path / "b", {"A": GUARDED})
    assert not ids & {"CF-BEDROCK-001", "CF-BEDROCK-003"}


def test_unresolved_agent_properties_are_not_judged(tmp_path: Path) -> None:
    agent = {"Type": "AWS::Bedrock::Agent", "Properties": {
        "AgentName": "a", "IdleSessionTTLInSeconds": {"Ref": "Ttl"},
        "GuardrailConfiguration": {"Ref": "Guard"}}}
    ids, _ = _scan(tmp_path, {"A": agent})
    assert not ids & {"CF-BEDROCK-001", "CF-BEDROCK-003"}


def test_logging_check_is_an_account_check_off_unless_rules_org(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path / "a", {"A": GUARDED})
    assert "CF-BEDROCK-004" not in ids
    ids, findings = _scan(tmp_path / "b", {"A": GUARDED}, rules_org=True)
    assert "CF-BEDROCK-004" in ids
    assert next(f for f in findings if f.id == "CF-BEDROCK-004").best_practices == ["GENSEC03-BP01"]
    ids, _ = _scan(tmp_path / "c", {"A": GUARDED}, rules_include=["CF-BEDROCK-004"])
    assert "CF-BEDROCK-004" in ids


def test_logging_answer_says_it_is_off_unless_rules_org(tmp_path: Path) -> None:
    _ids, _f = _scan(tmp_path, {"A": GUARDED})
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    by_q = {a.question.id: a for a in lenses.answers_for(ctx, findings)}
    assert by_q["GENSEC 3"].needs_org == ("GENSEC03-BP01",)
    assert "off unless rules.org is on" in by_q["GENSEC 3"].reason()


def test_terraform_agent_and_logging(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_bedrockagent_agent" "a" {\n  agent_name = "a"\n}\n', encoding="utf-8")
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False)
    assert {"CF-BEDROCK-001", "CF-BEDROCK-003"} <= {f.id for f in findings}
    (tmp_path / "main.tf").write_text(
        'resource "aws_bedrockagent_agent" "a" {\n  agent_name = "a"\n'
        "  idle_session_ttl_in_seconds = 500\n  guardrail_configuration {\n"
        '    guardrail_identifier = "g"\n  }\n}\n'
        'resource "aws_bedrock_model_invocation_logging_configuration" "l" {\n}\n',
        encoding="utf-8")
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_org=True)
    assert not {f.id for f in findings} & {"CF-BEDROCK-001", "CF-BEDROCK-003", "CF-BEDROCK-004"}


def test_endpoint_with_no_monitoring_schedule_reports_006(tmp_path: Path) -> None:
    ids, findings = _scan(tmp_path / "a", {"E": ENDPOINT})
    assert "CF-SAGE-006" in ids
    f = next(f for f in findings if f.id == "CF-SAGE-006")
    assert f.best_practices == ["MLPERF06-BP04"] and f.question == "MLPERF 6"
    schedule = {"Type": "AWS::SageMaker::MonitoringSchedule", "Properties": {
        "MonitoringScheduleConfig": {}, "EndpointName": {"Fn::GetAtt": ["E", "EndpointName"]}}}
    ids, _ = _scan(tmp_path / "b", {"E": ENDPOINT, "S": schedule})
    assert "CF-SAGE-006" not in ids
    other = {"Type": "AWS::SageMaker::MonitoringSchedule", "Properties": {
        "MonitoringScheduleConfig": {}, "EndpointName": "elsewhere"}}
    ids, _ = _scan(tmp_path / "c", {"E": ENDPOINT, "S": other})
    assert "CF-SAGE-006" in ids


def test_sage_005_still_answers_its_core_question(tmp_path: Path) -> None:
    config = {"Type": "AWS::SageMaker::EndpointConfig", "Properties": {"ProductionVariants": [
        {"VariantName": "v", "InstanceType": "ml.m5.large", "InitialInstanceCount": 1}]}}
    _ids, findings = _scan(tmp_path, {"C": config})
    f = next(f for f in findings if f.id == "CF-SAGE-005")
    assert f.question == "REL 10" and wa_map.RULE_BEST_PRACTICES["CF-SAGE-005"] == ("REL10-BP01",)


def test_an_s3_only_repo_reports_none_of_the_ai_ids(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path, {"B": S3}, rules_org=True)
    assert not {i for i in ids if i.startswith("CF-BEDROCK") or i == "CF-SAGE-006"}
    assert not {i for i in ids if i in {f"REPO-{n}" for n in range(194, 199)}}


def test_lenses_ai_false_silences_the_checks(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path, {"A": AGENT}, lenses_ai=False)
    assert not {i for i in ids if i.startswith("CF-BEDROCK")}


def test_each_shipped_id_is_in_the_lens_map_once_and_not_in_the_core_map() -> None:
    shipped = ["CF-BEDROCK-001", "CF-BEDROCK-003", "CF-BEDROCK-004", "CF-SAGE-006",
               "REPO-194", "REPO-195", "REPO-196", "REPO-197", "REPO-198"]
    for rid in shipped:
        assert rid in lens_map.LENS_RULE_BEST_PRACTICES and rid not in wa_map.RULE_BEST_PRACTICES
        (bp,) = lens_map.LENS_RULE_BEST_PRACTICES[rid]
        assert bp not in lens_map.LENS_NOT_CHECKED
    assert "CF-BEDROCK-002" not in lens_map.LENS_RULE_BEST_PRACTICES
    for rid in shipped[:4]:
        assert rid in _CLOUDFORMATION or rid in _TERRAFORM
        assert RULE_TOPICS[rid] in TOPICS
    rules = {r.id: r for r in ALL_RULES}
    assert rules["REPO-195"].question == "GENPERF 1"
    assert rules["REPO-195"].best_practices == ("GENPERF01-BP01",)


# --- repo notes ------------------------------------------------------------------------------


def _repo_findings(tmp_path: Path, files: dict[str, str], *, force: bool = False,
                   resources: dict | None = None) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": AGENT}, files,
                   **({"lenses_ai": True} if force else {}))
    return {i for i in ids if i in {f"REPO-{n}" for n in range(194, 199)}}


ALL_FIVE = {"REPO-194", "REPO-195", "REPO-196", "REPO-197", "REPO-198"}


def test_an_ai_fixture_with_no_notes_reports_all_five(tmp_path: Path) -> None:
    assert _repo_findings(tmp_path, {"README.md": "# App\n"}) == ALL_FIVE


@pytest.mark.parametrize("rule_id,files", [
    ("REPO-194", {"docs/responsible-ai.md": "Release criteria and approvals.\n"}),
    ("REPO-195", {"evals/golden.jsonl": "{}\n"}),
    ("REPO-196", {"docs/human-oversight.md": "A person approves refunds.\n"}),
    ("REPO-197", {"docs/agent-role.md": "The agent answers billing questions.\n"}),
    ("REPO-198", {"prompts/system.txt": "You are helpful.\n"}),
])
def test_adding_the_note_clears_that_one_rule(tmp_path: Path, rule_id: str, files: dict) -> None:
    got = _repo_findings(tmp_path, {"README.md": "# App\n", **files})
    assert got == ALL_FIVE - {rule_id}


def test_a_prompt_resource_clears_the_prompt_catalog_rule(tmp_path: Path) -> None:
    prompt = {"Type": "AWS::Bedrock::Prompt", "Properties": {"Name": "p"}}
    got = _repo_findings(tmp_path, {"README.md": "# App\n"}, resources={"A": AGENT, "P": prompt})
    assert "REPO-198" not in got


def test_a_non_ai_fixture_reports_none_of_them(tmp_path: Path) -> None:
    assert _repo_findings(tmp_path, {"README.md": "# App\n"}, resources={"B": S3}) == set()


def test_a_forced_gate_runs_the_workload_rules_but_not_the_resource_rules(tmp_path: Path) -> None:
    got = _repo_findings(tmp_path, {"README.md": "# App\n"}, force=True, resources={"B": S3})
    assert got == {"REPO-194", "REPO-195", "REPO-196"}


def test_repo_rules_are_quiet_outside_a_scan() -> None:
    from aws_arch_agent.rules.repo_practices import REPO_RULES

    assert not ai_gate.active()
    rule = next(r for r in REPO_RULES if r.id == "REPO-194")
    assert rule.run(Path(".")) == []


def test_v2_runs_the_ai_repo_rules_once_synth_shows_an_ai_workload(tmp_path: Path) -> None:
    """node_collect runs repo rules before any resource is seen; they run again after."""
    from aws_arch_agent.agent.v2_graph import analyze_v2

    (tmp_path / "stack.template.json").write_text(
        json.dumps({"Resources": {"A": AGENT}}), encoding="utf-8")
    (tmp_path / "README.md").write_text("# App\n", encoding="utf-8")
    _r, ctx, findings, _w = analyze_v2(tmp_path, use_llm=False, skip_synth=True,
                                       templates_path=str(tmp_path))
    assert ctx.ai_lenses and ALL_FIVE <= {f.id for f in findings}


def test_ai_resources_do_not_count_toward_the_core_dashboard_check(tmp_path: Path) -> None:
    many = {f"A{i}": AGENT for i in range(25)}
    ids, _ = _scan(tmp_path, many)
    assert "CF-DASH-001" not in ids
