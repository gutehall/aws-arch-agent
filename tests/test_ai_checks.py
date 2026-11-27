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


# --- Bedrock and AgentCore template checks: CloudFormation, Terraform and synthesised CDK ---

from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths  # noqa: E402

_KEY = "arn:aws:kms:us-east-1:111122223333:key/k"
_FILTERED = {"Type": "AWS::Bedrock::Guardrail", "Properties": {
    "Name": "g", "BlockedInputMessaging": "no", "BlockedOutputsMessaging": "no",
    "ContentPolicyConfig": {"FiltersConfig": [
        {"Type": "HATE", "InputStrength": "HIGH", "OutputStrength": "HIGH"}]}}}
_TOPICS_ONLY = {"Type": "AWS::Bedrock::Guardrail", "Properties": {
    "Name": "g", "BlockedInputMessaging": "no", "BlockedOutputsMessaging": "no",
    "TopicPolicyConfig": {"TopicsConfig": [{"Name": "t", "Definition": "d", "Type": "DENY"}]}}}
_PROMPT = {"Type": "AWS::Bedrock::Prompt", "Properties": {"Name": "p", "Variants": [
    {"Name": "main", "TemplateType": "TEXT", "ModelId": "m",
     "TemplateConfiguration": {"Text": {"Text": "Hi"}}}]}}
_BOUNDED = {"Type": "AWS::Bedrock::Prompt", "Properties": {
    "Name": "p", "CustomerEncryptionKeyArn": _KEY, "Variants": [
        {"Name": "main", "TemplateType": "TEXT", "ModelId": "m",
         "TemplateConfiguration": {"Text": {"Text": "Hi"}},
         "InferenceConfiguration": {"Text": {"MaxTokens": 512}}}]}}
_VERSION = {"Type": "AWS::Bedrock::PromptVersion", "Properties": {
    "PromptArn": {"Fn::GetAtt": ["P", "Arn"]}}}
_ALIAS = {"Type": "AWS::Bedrock::AgentAlias", "Properties": {
    "AgentAliasName": "live", "AgentId": {"Fn::GetAtt": ["A", "AgentId"]}}}
_KEYED_AGENT = {"Type": "AWS::Bedrock::Agent", "Properties": {
    **GUARDED["Properties"], "CustomerEncryptionKeyArn": _KEY}}


def _runtime(mode: str) -> dict:
    return {"Type": "AWS::BedrockAgentCore::Runtime", "Properties": {
        "AgentRuntimeName": "r", "RoleArn": "arn:aws:iam::1:role/r",
        "AgentRuntimeArtifact": {"ContainerConfiguration": {"ContainerUri": "x"}},
        "NetworkConfiguration": {"NetworkMode": mode}}}


def _gateway(kind: str) -> dict:
    return {"Type": "AWS::BedrockAgentCore::Gateway", "Properties": {
        "Name": "g", "ProtocolType": "MCP", "RoleArn": "arn:aws:iam::1:role/r", "AuthorizerType": kind}}


def _memory(**extra) -> dict:
    return {"Type": "AWS::BedrockAgentCore::Memory", "Properties": {
        "Name": "m", "EventExpiryDuration": 30, **extra}}


_TF_PROMPT = (
    'resource "aws_bedrockagent_prompt" "p" {\n  name = "p"\n%s'
    '  variant {\n    name = "main"\n    model_id = "m"\n    template_type = "TEXT"\n%s'
    '    template_configuration {\n      text {\n        text = "Hi"\n      }\n    }\n  }\n}\n'
)
_TF_MAX = "    inference_configuration {\n      text {\n        max_tokens = 512\n      }\n    }\n"
_TF_KEY = '  customer_encryption_key_arn = "arn:aws:kms:us-east-1:111122223333:key/k"\n'
_TF_AGENT = (
    'resource "aws_bedrockagent_agent" "a" {\n  agent_name = "a"\n%s'
    "  idle_session_ttl_in_seconds = 500\n  guardrail_configuration {\n"
    '    guardrail_identifier = "g"\n  }\n}\n'
)
_TF_ALIAS = (
    'resource "aws_bedrockagent_agent_alias" "l" {\n  agent_alias_name = "live"\n'
    "  agent_id = aws_bedrockagent_agent.a.agent_id\n}\n"
)
_TF_GUARD = (
    'resource "aws_bedrock_guardrail" "g" {\n  name = "g"\n%s}\n'
)
_TF_FILTER = (
    "  content_policy_config {\n    filters_config {\n      type = \"HATE\"\n"
    '      input_strength = "HIGH"\n      output_strength = "HIGH"\n    }\n  }\n'
)
_TF_PII = (
    "  sensitive_information_policy_config {\n    pii_entities_config {\n"
    '      type = "EMAIL"\n      action = "ANONYMIZE"\n    }\n  }\n'
)
_TF_TOPIC = (
    "  topic_policy_config {\n    topics_config {\n      name = \"t\"\n"
    '      definition = "d"\n      type = "DENY"\n    }\n  }\n'
)


def _tf_runtime(mode: str) -> str:
    return ('resource "aws_bedrockagentcore_agent_runtime" "r" {\n  agent_runtime_name = "r"\n'
            f'  network_configuration {{\n    network_mode = "{mode}"\n  }}\n}}\n')


def _tf_gateway(kind: str) -> str:
    return f'resource "aws_bedrockagentcore_gateway" "g" {{\n  name = "g"\n  authorizer_type = "{kind}"\n}}\n'


def _tf_memory(extra: str = "") -> str:
    return f'resource "aws_bedrockagentcore_memory" "m" {{\n  name = "m"\n  event_expiry_duration = 30\n{extra}}}\n'


# check id: (CloudFormation resources that fail, that pass; Terraform that fails, that passes).
# None: the check does not run on that source.
TEMPLATE_CASES = {
    "CF-BEDROCK-005": ({"G": _TOPICS_ONLY}, {"G": _FILTERED},
                       _TF_GUARD % _TF_TOPIC, _TF_GUARD % _TF_PII),
    "CF-BEDROCK-006": ({"A": GUARDED}, {"A": _KEYED_AGENT},
                       _TF_AGENT % "", _TF_AGENT % _TF_KEY),
    "CF-BEDROCK-007": ({"A": GUARDED}, {"A": GUARDED, "L": _ALIAS},
                       _TF_AGENT % "", _TF_AGENT % "" + _TF_ALIAS),
    "CF-BEDROCK-008": ({"P": _BOUNDED}, {"P": _BOUNDED, "V": _VERSION}, None, None),
    "CF-BEDROCK-009": ({"P": _PROMPT}, {"P": _BOUNDED},
                       _TF_PROMPT % ("", ""), _TF_PROMPT % ("", _TF_MAX)),
    "CF-AGENTCORE-001": ({"R": _runtime("PUBLIC")}, {"R": _runtime("VPC")},
                         _tf_runtime("PUBLIC"), _tf_runtime("VPC")),
    "CF-AGENTCORE-002": ({"G": _gateway("NONE")}, {"G": _gateway("CUSTOM_JWT")},
                         _tf_gateway("NONE"), _tf_gateway("AWS_IAM")),
    "CF-AGENTCORE-003": ({"M": _memory()}, {"M": _memory(EncryptionKeyArn=_KEY)},
                         _tf_memory(), _tf_memory(f'  encryption_key_arn = "{_KEY}"\n')),
}


def _cdk_ids(tmp_path: Path, resources: dict) -> set[str]:
    """Synthesised CDK: a template in cdk.out, read the way V2 reads synth output."""
    out = tmp_path / "cdk.out"
    out.mkdir(parents=True)
    (out / "Stack.template.json").write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return {f.id for f in run_cf_rules_from_paths([out / "Stack.template.json"], repo_path=tmp_path)}


def _tf_ids(tmp_path: Path, text: str) -> set[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False)
    return {f.id for f in findings}


@pytest.mark.parametrize("check_id", sorted(TEMPLATE_CASES))
def test_template_check_fails_and_passes_on_each_source(tmp_path: Path, check_id: str) -> None:
    cf_fail, cf_pass, tf_fail, tf_pass = TEMPLATE_CASES[check_id]
    ids, findings = _scan(tmp_path / "cf-fail", cf_fail)
    assert check_id in ids
    f = next(f for f in findings if f.id == check_id)
    assert f.best_practices == list(lens_map.LENS_RULE_BEST_PRACTICES[check_id])
    assert check_id not in _scan(tmp_path / "cf-pass", cf_pass)[0]
    assert check_id in _cdk_ids(tmp_path / "cdk-fail", cf_fail)
    assert check_id not in _cdk_ids(tmp_path / "cdk-pass", cf_pass)
    if tf_fail is not None:
        assert check_id in _tf_ids(tmp_path / "tf-fail", tf_fail)
        assert check_id not in _tf_ids(tmp_path / "tf-pass", tf_pass)


def test_terraform_prompt_is_not_judged_for_a_version(tmp_path: Path) -> None:
    assert "CF-BEDROCK-008" not in _tf_ids(tmp_path, _TF_PROMPT % (_TF_KEY, _TF_MAX))


def test_new_template_checks_skip_what_they_cannot_read(tmp_path: Path) -> None:
    resources = {
        "G": {"Type": "AWS::Bedrock::Guardrail", "Properties": {
            "Name": "g", "ContentPolicyConfig": {"Ref": "Policy"}}},
        "A": {"Type": "AWS::Bedrock::Agent", "Properties": {
            **GUARDED["Properties"], "CustomerEncryptionKeyArn": {"Ref": "Key"}}},
        # A link the scan cannot read may point at any agent or prompt.
        "L": {"Type": "AWS::Bedrock::AgentAlias", "Properties": "unreadable"},
        "P": {"Type": "AWS::Bedrock::Prompt", "Properties": {
            "Name": "p", "CustomerEncryptionKeyArn": _KEY, "Variants": {"Ref": "Variants"}}},
        "V": {"Type": "AWS::Bedrock::PromptVersion", "Properties": "unreadable"},
        "R": {"Type": "AWS::BedrockAgentCore::Runtime", "Properties": {
            "NetworkConfiguration": {"NetworkMode": {"Ref": "Mode"}}}},
        "W": {"Type": "AWS::BedrockAgentCore::Gateway", "Properties": {"AuthorizerType": {"Ref": "Auth"}}},
        "M": _memory(EncryptionKeyArn={"Ref": "Key"}),
    }
    ids, _ = _scan(tmp_path, resources)
    assert not ids & set(TEMPLATE_CASES)
    tf = (
        'resource "aws_bedrock_guardrail" "g" {\n  name = "g"\n  dynamic "content_policy_config" {\n'
        "    for_each = var.p\n    content {\n    }\n  }\n}\n"
        + _tf_gateway("NONE").replace('"NONE"', "var.auth")
        + 'resource "aws_bedrockagentcore_agent_runtime" "r" {\n  network_configuration {\n'
        "    network_mode = var.mode\n  }\n}\n"
    )
    assert not _tf_ids(tmp_path / "tf", tf) & set(TEMPLATE_CASES)


def test_an_alias_for_another_agent_does_not_count(tmp_path: Path) -> None:
    other = {"Type": "AWS::Bedrock::AgentAlias", "Properties": {
        "AgentAliasName": "live", "AgentId": {"Fn::GetAtt": ["B", "AgentId"]}}}
    ids, findings = _scan(tmp_path, {"A": GUARDED, "B": GUARDED, "L": other})
    assert [f.evidence for f in findings if f.id == "CF-BEDROCK-007"] == ["A (AWS::Bedrock::Agent)"]


def test_a_variant_that_runs_an_agent_needs_no_max_tokens(tmp_path: Path) -> None:
    prompt = {"Type": "AWS::Bedrock::Prompt", "Properties": {"Name": "p", "Variants": [
        {"Name": "agent", "TemplateType": "TEXT", "TemplateConfiguration": {"Text": {"Text": "Hi"}},
         "GenAiResource": {"Agent": {"AgentIdentifier": "arn"}}}]}}
    assert "CF-BEDROCK-009" not in _scan(tmp_path, {"P": prompt})[0]


def test_new_template_checks_stay_off_without_an_ai_workload(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path / "a", {"G": _TOPICS_ONLY, "M": _memory()}, lenses_ai=False)
    assert not ids & set(TEMPLATE_CASES)
    ids, _ = _scan(tmp_path / "b", {"B": S3}, rules_org=True)
    assert not {i for i in ids if i.startswith(("CF-BEDROCK", "CF-AGENTCORE"))}


def test_new_ai_types_do_not_count_toward_the_core_dashboard_check(tmp_path: Path) -> None:
    assert {"bedrock_agent_alias", "bedrock_prompt_version"} <= ai_gate.UNCOUNTED_TYPES
    many = {f"L{i}": _ALIAS for i in range(25)}
    ids, _ = _scan(tmp_path, {"A": _KEYED_AGENT, **many})
    assert "CF-DASH-001" not in ids


def test_each_new_id_is_in_the_lens_map_and_has_fixes_and_docs() -> None:
    for rid in [*TEMPLATE_CASES, "REPO-199", "REPO-200", "REPO-201"]:
        assert rid in lens_map.LENS_RULE_BEST_PRACTICES and rid not in wa_map.RULE_BEST_PRACTICES
        (bp,) = lens_map.LENS_RULE_BEST_PRACTICES[rid]
        assert bp not in lens_map.LENS_NOT_CHECKED
        assert RULE_TOPICS[rid] in TOPICS
    for rid in TEMPLATE_CASES:
        assert rid in _CLOUDFORMATION
        assert rid in _TERRAFORM or rid == "CF-BEDROCK-008"


# --- Bedrock calls in code and evaluation in CI ----------------------------------------------

_PY_CALL = (
    "import boto3\n\nclient = boto3.client(\"bedrock-runtime\")\n\n\n"
    "def ask(text):\n    return client.converse(\n        modelId=\"m\",\n"
    "        messages=[{\"role\": \"user\", \"content\": [{\"text\": text}]}],\n%s    )\n"
)
_GUARD_ARG = '        guardrailConfig={"guardrailIdentifier": "g", "guardrailVersion": "1"},\n'
_MAX_ARG = '        inferenceConfig={"maxTokens": 512},\n'
_TS_CALL = (
    'import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";\n'
    "const client = new BedrockRuntimeClient({});\n"
    "export const ask = (text: string) => client.send(new ConverseCommand({\n"
    '  modelId: "m",\n  messages: [{ role: "user", content: [{ text }] }],\n%s}));\n'
)
CODE_IDS = {"REPO-199", "REPO-200", "REPO-201"}


def _code_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None,
              **kwargs) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": AGENT}, files, **kwargs)
    return ids & CODE_IDS


def test_python_call_with_no_guardrail_or_token_bound(tmp_path: Path) -> None:
    assert _code_ids(tmp_path / "a", {"app/handler.py": _PY_CALL % ""}) == {"REPO-199", "REPO-200"}
    assert _code_ids(tmp_path / "b", {"app/handler.py": _PY_CALL % _GUARD_ARG}) == {"REPO-200"}
    assert _code_ids(tmp_path / "c", {"app/handler.py": _PY_CALL % (_GUARD_ARG + _MAX_ARG)}) == set()


def test_typescript_call_with_no_guardrail_or_token_bound(tmp_path: Path) -> None:
    assert _code_ids(tmp_path / "a", {"src/ask.ts": _TS_CALL % ""}) == {"REPO-199", "REPO-200"}
    bounded = _TS_CALL % ('  inferenceConfig: { maxTokens: 512 },\n'
                          '  guardrailConfig: { guardrailIdentifier: "g", guardrailVersion: "1" },\n')
    assert _code_ids(tmp_path / "b", {"src/ask.ts": bounded}) == set()


def test_calls_in_tests_and_non_bedrock_clients_are_not_read(tmp_path: Path) -> None:
    files = {"tests/test_ask.py": _PY_CALL % "",
             "app/sm.py": "import boto3\nsm = boto3.client('sagemaker-runtime')\nsm.invoke_endpoint(EndpointName='e')\n"}
    assert _code_ids(tmp_path, files) == set()


def test_code_rules_stay_off_for_a_non_ai_repo(tmp_path: Path) -> None:
    files = {"app/handler.py": _PY_CALL % "", ".github/workflows/ci.yml": "jobs: {}\n"}
    assert _code_ids(tmp_path / "a", files, resources={"B": S3}) == set()
    assert _code_ids(tmp_path / "b", files, resources={"A": AGENT}, lenses_ai=False) == set()


def test_ci_with_no_evaluation_reports_201(tmp_path: Path) -> None:
    ci = ".github/workflows/ci.yml"
    plain = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n"
    assert _code_ids(tmp_path / "a", {ci: plain}) == {"REPO-201"}
    assert _code_ids(tmp_path / "b", {ci: plain + "      - run: npx promptfoo eval\n"}) == set()
    assert _code_ids(tmp_path / "c", {ci: plain + "      - run: python -m pytest evals/\n"}) == set()
    # A shell eval is not an evaluation; no build at all is REPO-002's finding.
    assert _code_ids(tmp_path / "d", {ci: plain + '      - run: eval "$(ssh-agent)"\n'}) == {"REPO-201"}
    assert _code_ids(tmp_path / "e", {"README.md": "# App\n"}) == set()


# --- SageMaker and Responsible AI guardrail checks: CloudFormation, Terraform and synthesised CDK ---

_NOTEBOOK = {"Type": "AWS::SageMaker::NotebookInstance", "Properties": {
    "InstanceType": "ml.t3.medium", "RoleArn": "arn:aws:iam::1:role/r", "RootAccess": "Disabled",
    "DirectInternetAccess": "Disabled", "SubnetId": "subnet-1", "KmsKeyId": _KEY}}
_IDLE_NOTEBOOK = {"Type": "AWS::SageMaker::NotebookInstance", "Properties": {
    **_NOTEBOOK["Properties"], "LifecycleConfigName": "idle-stop"}}


def _domain(**extra) -> dict:
    return {"Type": "AWS::SageMaker::Domain", "Properties": {
        "DomainName": "d", "AuthMode": "IAM", "VpcId": "vpc-1", "SubnetIds": ["subnet-1"],
        "DefaultUserSettings": {"ExecutionRole": "arn:aws:iam::1:role/r"}, **extra}}


_VARIANT = {"VariantName": "AllTraffic", "ModelName": "m", "InstanceType": "ml.m5.large",
            "InitialInstanceCount": 2}
_CAPTURE = {"EnableCapture": True, "InitialSamplingPercentage": 20,
            "DestinationS3Uri": "s3://b/capture", "CaptureOptions": [{"CaptureMode": "Input"}]}


def _config(**extra) -> dict:
    return {"Type": "AWS::SageMaker::EndpointConfig", "Properties": {
        "KmsKeyId": _KEY, "ProductionVariants": [_VARIANT], **extra}}


_SM_ENDPOINT = {"Type": "AWS::SageMaker::Endpoint", "Properties": {
    "EndpointConfigName": {"Fn::GetAtt": ["C", "EndpointConfigName"]}}}
_SCHEDULE = {"Type": "AWS::SageMaker::MonitoringSchedule", "Properties": {
    "MonitoringScheduleConfig": {}, "EndpointName": {"Fn::GetAtt": ["E", "EndpointName"]}}}


def _target(resource_id, dimension: str = "sagemaker:variant:DesiredInstanceCount") -> dict:
    return {"Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
        "ServiceNamespace": "sagemaker", "ScalableDimension": dimension, "MinCapacity": 2,
        "MaxCapacity": 4, "ResourceId": resource_id}}


_SCALED_ID = {"Fn::Sub": "endpoint/${E.EndpointName}/variant/AllTraffic"}
_SERVED = {"C": _config(DataCaptureConfig=_CAPTURE), "E": _SM_ENDPOINT, "S": _SCHEDULE}


def _feature_group(online: dict | None = None, offline: dict | None = None) -> dict:
    props: dict = {"FeatureGroupName": "f", "RecordIdentifierFeatureName": "id",
                   "EventTimeFeatureName": "t", "FeatureDefinitions": []}
    if online is not None:
        props["OnlineStoreConfig"] = online
    if offline is not None:
        props["OfflineStoreConfig"] = offline
    return {"Type": "AWS::SageMaker::FeatureGroup", "Properties": props}


def _model(container: dict) -> dict:
    return {"Type": "AWS::SageMaker::Model", "Properties": {
        "ExecutionRoleArn": "arn:aws:iam::1:role/r", "PrimaryContainer": container}}


_ARTIFACT = {"Image": "1.dkr.ecr.us-east-1.amazonaws.com/x:1", "ModelDataUrl": "s3://b/model.tar.gz"}
_PACKAGE = {"ModelPackageName": "arn:aws:sagemaker:us-east-1:1:model-package/g/3"}


def _guard(**policies) -> dict:
    return {"Type": "AWS::Bedrock::Guardrail", "Properties": {
        "Name": "g", "BlockedInputMessaging": "no", "BlockedOutputsMessaging": "no", **policies}}


_CONTENT = {"FiltersConfig": [{"Type": "HATE", "InputStrength": "HIGH", "OutputStrength": "HIGH"}]}
_TOPICS = {"TopicsConfig": [{"Name": "t", "Definition": "d", "Type": "DENY"}]}
_PII = {"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": "ANONYMIZE"}]}
_GROUNDING = {"FiltersConfig": [{"Type": "GROUNDING", "Threshold": 0.75}]}
_KB = {"Type": "AWS::Bedrock::KnowledgeBase", "Properties": {"Name": "k", "RoleArn": "r"}}

_TF_NOTEBOOK = (
    'resource "aws_sagemaker_notebook_instance" "n" {\n  name = "n"\n  role_arn = "r"\n'
    '  instance_type = "ml.t3.medium"\n%s}\n'
)
_TF_DOMAIN = (
    'resource "aws_sagemaker_domain" "d" {\n  domain_name = "d"\n  auth_mode = "IAM"\n'
    '  vpc_id = "vpc-1"\n  subnet_ids = ["subnet-1"]\n%s'
    '  default_user_settings {\n    execution_role = "r"\n  }\n}\n'
)
_TF_CONFIG = (
    'resource "aws_sagemaker_endpoint_configuration" "c" {\n  name = "c"\n'
    f'  kms_key_arn = "{_KEY}"\n'
    '  production_variants {\n    variant_name = "AllTraffic"\n    model_name = "m"\n'
    '    instance_type = "ml.m5.large"\n    initial_instance_count = 2\n  }\n%s}\n'
)
_TF_CAPTURE = (
    '  data_capture_config {\n    enable_capture = true\n    initial_sampling_percentage = 20\n'
    '    destination_s3_uri = "s3://b/capture"\n    capture_options {\n'
    '      capture_mode = "Input"\n    }\n  }\n'
)
_TF_ENDPOINT = (
    _TF_CONFIG % _TF_CAPTURE
    + 'resource "aws_sagemaker_endpoint" "e" {\n  name = "e"\n'
    "  endpoint_config_name = aws_sagemaker_endpoint_configuration.c.name\n}\n"
)
_TF_TARGET = (
    'resource "aws_appautoscaling_target" "t" {\n  service_namespace = "sagemaker"\n'
    '  scalable_dimension = "sagemaker:variant:DesiredInstanceCount"\n'
    '  resource_id = "endpoint/${aws_sagemaker_endpoint.e.name}/variant/AllTraffic"\n'
    "  min_capacity = 2\n  max_capacity = 4\n}\n"
)
_TF_FEATURES = (
    'resource "aws_sagemaker_feature_group" "f" {\n  feature_group_name = "f"\n'
    '  record_identifier_feature_name = "id"\n  event_time_feature_name = "t"\n'
    '  role_arn = "r"\n  online_store_config {\n    enable_online_store = true\n%s  }\n}\n'
)
_TF_FEATURE_KEY = f'    security_config {{\n      kms_key_id = "{_KEY}"\n    }}\n'
_TF_MODEL = (
    'resource "aws_sagemaker_model" "m" {\n  name = "m"\n  execution_role_arn = "r"\n'
    "  primary_container {\n%s  }\n}\n"
)
_TF_IMAGE = '    image = "1.dkr.ecr.us-east-1.amazonaws.com/x:1"\n    model_data_url = "s3://b/m.tar.gz"\n'
_TF_PACKAGE = '    model_package_name = "arn:aws:sagemaker:us-east-1:1:model-package/g/3"\n'
_TF_KB = 'resource "aws_bedrockagent_knowledge_base" "k" {\n  name = "k"\n  role_arn = "r"\n}\n'
_TF_GROUNDING = (
    "  contextual_grounding_policy_config {\n    filters_config {\n"
    '      type = "GROUNDING"\n      threshold = 0.75\n    }\n  }\n'
)

ML_CASES = {
    "CF-SAGE-007": ({"N": _NOTEBOOK}, {"N": _IDLE_NOTEBOOK},
                    _TF_NOTEBOOK % "", _TF_NOTEBOOK % '  lifecycle_config_name = "idle"\n'),
    "CF-SAGE-008": ({"D": _domain()}, {"D": _domain(AppNetworkAccessType="VpcOnly")},
                    _TF_DOMAIN % '  app_network_access_type = "PublicInternetOnly"\n',
                    _TF_DOMAIN % '  app_network_access_type = "VpcOnly"\n'),
    "CF-SAGE-009": ({"D": _domain()}, {"D": _domain(KmsKeyId=_KEY)},
                    _TF_DOMAIN % "", _TF_DOMAIN % f'  kms_key_id = "{_KEY}"\n'),
    "CF-SAGE-010": ({"C": _config()}, {"C": _config(DataCaptureConfig=_CAPTURE)},
                    _TF_CONFIG % "", _TF_CONFIG % _TF_CAPTURE),
    "CF-SAGE-011": (_SERVED, {**_SERVED, "T": _target(_SCALED_ID)},
                    _TF_ENDPOINT, _TF_ENDPOINT + _TF_TARGET),
    "CF-SAGE-012": ({"F": _feature_group(online={"EnableOnlineStore": True})},
                    {"F": _feature_group(online={"EnableOnlineStore": True,
                                                 "SecurityConfig": {"KmsKeyId": _KEY}})},
                    _TF_FEATURES % "", _TF_FEATURES % _TF_FEATURE_KEY),
    "CF-SAGE-013": ({"M": _model(_ARTIFACT)}, {"M": _model(_PACKAGE)},
                    _TF_MODEL % _TF_IMAGE, _TF_MODEL % _TF_PACKAGE),
    "CF-BEDROCK-010": ({"G": _guard(ContentPolicyConfig=_CONTENT)},
                       {"G": _guard(ContentPolicyConfig=_CONTENT, TopicPolicyConfig=_TOPICS)},
                       _TF_GUARD % _TF_FILTER, _TF_GUARD % (_TF_FILTER + _TF_TOPIC)),
    "CF-BEDROCK-011": ({"G": _guard(ContentPolicyConfig=_CONTENT)},
                       {"G": _guard(ContentPolicyConfig=_CONTENT, SensitiveInformationPolicyConfig=_PII)},
                       _TF_GUARD % _TF_FILTER, _TF_GUARD % (_TF_FILTER + _TF_PII)),
    "CF-BEDROCK-012": ({"G": _guard(ContentPolicyConfig=_CONTENT), "K": _KB},
                       {"G": _guard(ContentPolicyConfig=_CONTENT, ContextualGroundingPolicyConfig=_GROUNDING),
                        "K": _KB},
                       _TF_GUARD % _TF_FILTER + _TF_KB, _TF_GUARD % (_TF_FILTER + _TF_GROUNDING) + _TF_KB),
}


@pytest.mark.parametrize("check_id", sorted(ML_CASES))
def test_ml_and_rai_check_fails_and_passes_on_each_source(tmp_path: Path, check_id: str) -> None:
    cf_fail, cf_pass, tf_fail, tf_pass = ML_CASES[check_id]
    ids, findings = _scan(tmp_path / "cf-fail", cf_fail)
    assert check_id in ids
    f = next(f for f in findings if f.id == check_id)
    assert f.best_practices == list(lens_map.LENS_RULE_BEST_PRACTICES[check_id])
    assert check_id not in _scan(tmp_path / "cf-pass", cf_pass)[0]
    assert check_id in _cdk_ids(tmp_path / "cdk-fail", cf_fail)
    assert check_id not in _cdk_ids(tmp_path / "cdk-pass", cf_pass)
    assert check_id in _tf_ids(tmp_path / "tf-fail", tf_fail)
    assert check_id not in _tf_ids(tmp_path / "tf-pass", tf_pass)


def test_ml_and_rai_checks_skip_what_they_cannot_read(tmp_path: Path) -> None:
    resources = {
        "N": {"Type": "AWS::SageMaker::NotebookInstance", "Properties": {
            **_NOTEBOOK["Properties"], "LifecycleConfigName": {"Ref": "Config"}}},
        "D": _domain(AppNetworkAccessType={"Ref": "Access"}, KmsKeyId={"Ref": "Key"}),
        "C": _config(DataCaptureConfig={"Ref": "Capture"}),
        "F": _feature_group(online={"Ref": "Online"}, offline={"S3StorageConfig": {"Ref": "S3"}}),
        "M": _model({"Ref": "Container"}),
        "G": _guard(ContentPolicyConfig=_CONTENT, TopicPolicyConfig={"Ref": "Topics"},
                    SensitiveInformationPolicyConfig={"PiiEntitiesConfig": {"Ref": "Pii"}},
                    ContextualGroundingPolicyConfig={"Ref": "Grounding"}),
        "K": _KB,
    }
    ids, _ = _scan(tmp_path, resources)
    assert not ids & set(ML_CASES)
    tf = (
        _TF_DOMAIN % "  app_network_access_type = var.access\n"
        + 'resource "aws_sagemaker_endpoint_configuration" "c" {\n  production_variants {\n'
        '    instance_type = "ml.m5.large"\n  }\n  dynamic "data_capture_config" {\n'
        "    for_each = var.c\n    content {\n    }\n  }\n}\n"
        + _TF_MODEL % "    model_package_name = var.package\n"
    )
    assert not _tf_ids(tmp_path / "tf", tf) & {"CF-SAGE-008", "CF-SAGE-010", "CF-SAGE-013"}


def test_endpoint_scaling_is_judged_only_when_the_scan_can_tell(tmp_path: Path) -> None:
    # A target for another endpoint by literal name, an unreadable target and a target in a
    # stack the scan cannot see may each scale this endpoint.
    for case, extra in {
        "literal": {"T": _target("endpoint/elsewhere/variant/AllTraffic")},
        "unread": {"T": _target({"Ref": "Target"})},
        "child": {"Nested": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "u"}}},
    }.items():
        assert "CF-SAGE-011" not in _scan(tmp_path / case, {**_SERVED, **extra})[0], case
    # A target on another dimension does not scale the instance count.
    other = {**_SERVED, "T": _target(_SCALED_ID, "sagemaker:variant:DesiredProvisionedConcurrency")}
    assert "CF-SAGE-011" in _scan(tmp_path / "dimension", other)[0]
    # A literal endpoint name ties a literal resource id.
    named = {**_SERVED, "E": {"Type": "AWS::SageMaker::Endpoint", "Properties": {
        "EndpointName": "live", "EndpointConfigName": {"Fn::GetAtt": ["C", "EndpointConfigName"]}}},
        "T": _target("endpoint/live/variant/AllTraffic")}
    assert "CF-SAGE-011" not in _scan(tmp_path / "named", named)[0]
    # A serverless endpoint scales by itself; an endpoint whose config is elsewhere is not judged.
    serverless = {**_SERVED, "C": {"Type": "AWS::SageMaker::EndpointConfig", "Properties": {
        "ProductionVariants": [{"VariantName": "v", "ModelName": "m",
                                "ServerlessConfig": {"MaxConcurrency": 5, "MemorySizeInMB": 2048}}]}}}
    assert "CF-SAGE-011" not in _scan(tmp_path / "serverless", serverless)[0]
    alone = {"E": {"Type": "AWS::SageMaker::Endpoint", "Properties": {"EndpointConfigName": "c"}}}
    assert "CF-SAGE-011" not in _scan(tmp_path / "alone", alone)[0]


def test_data_capture_turned_off_and_serverless_configs(tmp_path: Path) -> None:
    off = _config(DataCaptureConfig={**_CAPTURE, "EnableCapture": False})
    assert "CF-SAGE-010" in _scan(tmp_path / "off", {"C": off})[0]
    default = _config(DataCaptureConfig={k: v for k, v in _CAPTURE.items() if k != "EnableCapture"})
    assert "CF-SAGE-010" not in _scan(tmp_path / "default", {"C": default})[0]
    serverless = {"Type": "AWS::SageMaker::EndpointConfig", "Properties": {"ProductionVariants": [
        {"VariantName": "v", "ModelName": "m", "ServerlessConfig": {"MaxConcurrency": 5, "MemorySizeInMB": 2048}}]}}
    assert "CF-SAGE-010" not in _scan(tmp_path / "serverless", {"C": serverless})[0]


def test_feature_group_stores(tmp_path: Path) -> None:
    # The online store is off unless EnableOnlineStore is true.
    ids, _ = _scan(tmp_path / "off", {"F": _feature_group(online={"EnableOnlineStore": False})})
    assert "CF-SAGE-012" not in ids
    offline = _feature_group(offline={"S3StorageConfig": {"S3Uri": "s3://b/f"}})
    ids, findings = _scan(tmp_path / "offline", {"F": offline})
    assert "offline" in next(f for f in findings if f.id == "CF-SAGE-012").recommendation
    keyed = _feature_group(offline={"S3StorageConfig": {"S3Uri": "s3://b/f", "KmsKeyId": _KEY}})
    assert "CF-SAGE-012" not in _scan(tmp_path / "keyed", {"F": keyed})[0]


def test_guardrail_rai_checks_do_not_repeat_bedrock_005(tmp_path: Path) -> None:
    # A guardrail with no filter at all is CF-BEDROCK-005's finding, not CF-BEDROCK-011's.
    ids, _ = _scan(tmp_path / "bare", {"G": _guard()})
    assert "CF-BEDROCK-005" in ids and "CF-BEDROCK-011" not in ids
    assert "CF-BEDROCK-010" in ids
    # The grounding check asks only when the template has a knowledge base.
    assert "CF-BEDROCK-012" not in _scan(tmp_path / "no-kb", {"G": _guard(ContentPolicyConfig=_CONTENT)})[0]


def test_ml_checks_stay_off_without_an_ai_workload(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path / "a", {"D": _domain(), "M": _model(_ARTIFACT)}, lenses_ai=False)
    assert not ids & set(ML_CASES)
    ids, _ = _scan(tmp_path / "b", {"B": S3, "T": _target("endpoint/e/variant/AllTraffic")})
    assert not ids & set(ML_CASES)


def test_new_sagemaker_types_turn_the_gate_on_and_are_not_counted(tmp_path: Path) -> None:
    new = {"sagemaker_domain", "sagemaker_feature_group", "sagemaker_model",
           "sagemaker_model_package_group", "sagemaker_model_card"}
    assert new <= ai_gate.AI_TYPES and new <= ai_gate.UNCOUNTED_TYPES
    many = {f"M{i}": _model(_PACKAGE) for i in range(25)}
    ids, _ = _scan(tmp_path, many)
    assert "CF-DASH-001" not in ids


def test_each_ml_and_rai_id_is_in_the_lens_map_and_has_fixes_and_docs() -> None:
    for rid in [*ML_CASES, "REPO-202", "REPO-203", "REPO-204"]:
        assert rid in lens_map.LENS_RULE_BEST_PRACTICES and rid not in wa_map.RULE_BEST_PRACTICES
        (bp,) = lens_map.LENS_RULE_BEST_PRACTICES[rid]
        assert bp not in lens_map.LENS_NOT_CHECKED
        assert RULE_TOPICS[rid] in TOPICS
    for rid in ML_CASES:
        assert rid in _CLOUDFORMATION and rid in _TERRAFORM


# --- Responsible AI governance notes and bias evaluation -------------------------------------

GOVERNANCE_IDS = {"REPO-202", "REPO-203", "REPO-204"}
_CI = {".github/workflows/ci.yml": "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n"}


def _governance_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None,
                    **kwargs) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"E": ENDPOINT}, {"README.md": "# App\n", **files}, **kwargs)
    return ids & GOVERNANCE_IDS


def test_a_sagemaker_workload_with_no_notes_reports_all_three(tmp_path: Path) -> None:
    assert _governance_ids(tmp_path, _CI) == GOVERNANCE_IDS


@pytest.mark.parametrize("rule_id,files", [
    ("REPO-202", {"MODEL_CARD.md": "Intended use.\n"}),
    ("REPO-202", {"docs/overview.md": "# System card\n\nIntended use.\n"}),
    ("REPO-203", {"requirements.txt": "fairlearn==0.10\n"}),
    ("REPO-203", {"pipeline/build.py": "from sagemaker.clarify import BiasConfig\n"}),
    ("REPO-203", {".github/workflows/bias.yml": "jobs:\n  b:\n    steps:\n      - run: aequitas-report\n"}),
    ("REPO-204", {"docs/escalation.md": "Who is paged and how to switch the model off.\n"}),
])
def test_adding_the_answer_clears_that_governance_rule(tmp_path: Path, rule_id: str, files: dict) -> None:
    assert _governance_ids(tmp_path, {**_CI, **files}) == GOVERNANCE_IDS - {rule_id}


def test_a_model_card_resource_and_a_bias_job_clear_their_rules(tmp_path: Path) -> None:
    card = {"Type": "AWS::SageMaker::ModelCard", "Properties": {"ModelCardName": "c",
                                                                "ModelCardStatus": "Draft", "Content": {}}}
    bias = {"Type": "AWS::SageMaker::ModelBiasJobDefinition", "Properties": {}}
    got = _governance_ids(tmp_path, _CI, resources={"E": ENDPOINT, "C": card, "B": bias})
    assert got == {"REPO-204"}


def test_bias_rule_needs_a_sagemaker_workload_and_a_build(tmp_path: Path) -> None:
    assert "REPO-203" not in _governance_ids(tmp_path / "bedrock", _CI, resources={"A": AGENT})
    assert "REPO-203" not in _governance_ids(tmp_path / "no-build", {})
    # A bias tool named only in a test is not a bias evaluation.
    files = {**_CI, "tests/test_fair.py": "import fairlearn\n"}
    assert "REPO-203" in _governance_ids(tmp_path / "test-only", files)


def test_governance_rules_stay_off_for_a_non_ai_repo(tmp_path: Path) -> None:
    assert _governance_ids(tmp_path / "a", _CI, resources={"B": S3}) == set()
    assert _governance_ids(tmp_path / "b", _CI, lenses_ai=False) == set()


_PY_HELPER_CALL = (
    "import boto3\n\nclient = boto3.client(\"bedrock-runtime\")\n\n\n"
    "def ask(text, **settings):\n    return client.converse(modelId=\"m\", messages=[], **settings)\n"
)


def test_settings_in_a_local_helper_or_caller_count(tmp_path: Path) -> None:
    # The call file imports its settings from a helper module.
    settings = "GUARD = {'guardrailIdentifier': 'g'}\nBOUND = {'maxTokens': 512}\n"
    call = "from .settings import GUARD, BOUND\n" + _PY_CALL % ""
    assert _code_ids(tmp_path / "a", {"app/__init__.py": "", "app/settings.py": settings,
                                      "app/handler.py": call}) == set()
    # A caller passes the settings to the helper that makes the call.
    caller = ("from app.bedrock import ask\n\n"
              "ask('hi', guardrailConfig={'guardrailIdentifier': 'g'}, inferenceConfig={'maxTokens': 9})\n")
    assert _code_ids(tmp_path / "b", {"app/bedrock.py": _PY_HELPER_CALL, "app/main.py": caller}) == set()
    # TypeScript: a relative import (ESM .js spelling) of a helper that holds the guardrail.
    helper = 'export const guard = { guardrailIdentifier: "g", guardrailVersion: "1" };\n'
    call_ts = 'import { guard } from "./guard.js";\n' + _TS_CALL % "  guardrailConfig: guard,\n"
    assert _code_ids(tmp_path / "c", {"src/guard.ts": helper, "src/ask.ts": call_ts}) == {"REPO-200"}
    # An unrelated file with a guardrail does not clear a call that never reaches it.
    assert _code_ids(tmp_path / "d", {"app/handler.py": _PY_CALL % "",
                                      "other/guarded.py": _PY_CALL % _GUARD_ARG}) == {"REPO-199", "REPO-200"}


def test_import_resolution_prefers_nearest_and_reads_all_suffixes() -> None:
    from aws_arch_agent.rules.repo_practices import related_code

    files = {
        "app/handler.py": "import config\n",
        "app/config.py": "",
        "config.py": "guardrailIdentifier = 'g'\n",
        "src/ask.ts": 'import { g } from "./guard.mjs";\nimport { h } from "./h";\n',
        "src/guard.mts": "",
        "src/h.jsx": "",
    }
    related = related_code(files, ["app/handler.py", "src/ask.ts"])
    assert related["app/handler.py"] == {"app/handler.py", "app/config.py"}
    assert related["src/ask.ts"] == {"src/ask.ts", "src/guard.mts", "src/h.jsx"}
    assert set(related) == {"app/handler.py", "src/ask.ts"}


# --- AGENTSEC 9: security testing of an agent ------------------------------------------------

AGENT_SECURITY_IDS = {"REPO-205", "REPO-206", "REPO-207"}


def _agent_security_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None,
                        **kwargs) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": AGENT}, {"README.md": "# App\n", **files}, **kwargs)
    return ids & AGENT_SECURITY_IDS


def test_an_agent_with_no_security_testing_reports_all_three(tmp_path: Path) -> None:
    assert _agent_security_ids(tmp_path, _CI) == AGENT_SECURITY_IDS


@pytest.mark.parametrize("rule_id,files", [
    ("REPO-205", {".github/workflows/redteam.yml": "jobs:\n  r:\n    steps:\n      - run: garak --model_type rest\n"}),
    ("REPO-205", {".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: npx promptfoo redteam run\n"}),
    ("REPO-206", {"docs/security-testing.md": "Tests run in an isolated account.\n"}),
    ("REPO-206", {"docs/ops.md": "# Penetration testing\n\nScope and approvals.\n"}),
    ("REPO-207", {"docs/threat-detection.md": "GuardDuty findings revoke the agent role.\n"}),
])
def test_adding_the_answer_clears_that_agent_security_rule(tmp_path: Path, rule_id: str,
                                                           files: dict) -> None:
    assert _agent_security_ids(tmp_path, {**_CI, **files}) == AGENT_SECURITY_IDS - {rule_id}


def test_a_detector_or_a_findings_rule_in_the_iac_clears_threat_detection(tmp_path: Path) -> None:
    detector = {"Type": "AWS::GuardDuty::Detector", "Properties": {"Enable": True}}
    findings_rule = {"Type": "AWS::Events::Rule", "Properties": {
        "EventPattern": {"source": ["aws.guardduty"]}, "Targets": []}}
    for name, extra in (("detector", detector), ("rule", findings_rule)):
        got = _agent_security_ids(tmp_path / name, _CI, resources={"A": AGENT, "X": extra})
        assert got == AGENT_SECURITY_IDS - {"REPO-207"}


def test_plain_promptfoo_is_an_eval_not_a_red_team(tmp_path: Path) -> None:
    files = {".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: npx promptfoo eval\n"}
    assert "REPO-205" in _agent_security_ids(tmp_path, files)


def test_agent_security_rules_need_an_agent(tmp_path: Path) -> None:
    assert _agent_security_ids(tmp_path / "sagemaker", _CI, resources={"E": ENDPOINT}) == set()
    assert _agent_security_ids(tmp_path / "s3", _CI, resources={"B": S3}) == set()
    assert _agent_security_ids(tmp_path / "off", _CI, lenses_ai=False) == set()


def test_agent_security_rules_answer_agentsec_9_only() -> None:
    for rid in AGENT_SECURITY_IDS:
        assert rid not in wa_map.RULE_BEST_PRACTICES
        assert RULE_TOPICS[rid] in TOPICS
        bps = lens_map.LENS_RULE_BEST_PRACTICES[rid]
        assert {bp[:10] for bp in bps} == {"AGENTSEC09"}
        assert not set(bps) & lens_map.LENS_NOT_CHECKED


# --- AGENTSEC 8: guardrail prompt attack and response filters --------------------------------

_ATTACK = {"Type": "PROMPT_ATTACK", "InputStrength": "HIGH", "OutputStrength": "NONE"}
_PII_IN_ONLY = {"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": "ANONYMIZE", "OutputEnabled": False}]}
_TF_ATTACK = (
    "  content_policy_config {\n    filters_config {\n      type = \"PROMPT_ATTACK\"\n"
    '      input_strength = "HIGH"\n      output_strength = "NONE"\n    }\n  }\n'
)
_TF_PII_IN_ONLY = _TF_PII.replace('action = "ANONYMIZE"\n', 'action = "ANONYMIZE"\n      output_enabled = false\n')

AGENTSEC08_CASES = {
    "CF-BEDROCK-013": ({"G": _guard(ContentPolicyConfig=_CONTENT)},
                       {"G": _guard(ContentPolicyConfig={"FiltersConfig": [*_CONTENT["FiltersConfig"], _ATTACK]})},
                       _TF_GUARD % _TF_FILTER, _TF_GUARD % _TF_ATTACK),
    "CF-BEDROCK-014": ({"G": _guard(ContentPolicyConfig=_CONTENT, SensitiveInformationPolicyConfig=_PII_IN_ONLY)},
                       {"G": _guard(ContentPolicyConfig=_CONTENT, SensitiveInformationPolicyConfig=_PII)},
                       _TF_GUARD % (_TF_FILTER + _TF_PII_IN_ONLY), _TF_GUARD % (_TF_FILTER + _TF_PII)),
}


@pytest.mark.parametrize("check_id", sorted(AGENTSEC08_CASES))
def test_agentsec08_check_fails_and_passes_on_each_source(tmp_path: Path, check_id: str) -> None:
    cf_fail, cf_pass, tf_fail, tf_pass = AGENTSEC08_CASES[check_id]
    ids, findings = _scan(tmp_path / "cf-fail", cf_fail)
    assert check_id in ids
    f = next(f for f in findings if f.id == check_id)
    assert f.best_practices == list(lens_map.LENS_RULE_BEST_PRACTICES[check_id])
    assert check_id not in _scan(tmp_path / "cf-pass", cf_pass)[0]
    assert check_id in _cdk_ids(tmp_path / "cdk-fail", cf_fail)
    assert check_id not in _cdk_ids(tmp_path / "cdk-pass", cf_pass)
    assert check_id in _tf_ids(tmp_path / "tf-fail", tf_fail)
    assert check_id not in _tf_ids(tmp_path / "tf-pass", tf_pass)
    assert check_id in _CLOUDFORMATION and check_id in _TERRAFORM
    assert RULE_TOPICS[check_id] in TOPICS
    assert check_id not in wa_map.RULE_BEST_PRACTICES


@pytest.mark.parametrize("guard", [
    # No filter at all is CF-BEDROCK-005's finding.
    _guard(TopicPolicyConfig=_TOPICS),
    # An unreadable filter list, type or strength is not judged.
    _guard(ContentPolicyConfig={"Ref": "Content"}),
    _guard(ContentPolicyConfig={"FiltersConfig": [{"Type": {"Ref": "T"}, "InputStrength": "HIGH"}]}),
    _guard(ContentPolicyConfig={"FiltersConfig": [{**_ATTACK, "InputStrength": {"Ref": "S"}}]}),
])
def test_prompt_attack_check_skips_what_005_reports_or_it_cannot_read(tmp_path: Path, guard: dict) -> None:
    assert "CF-BEDROCK-013" not in _scan(tmp_path, {"G": guard})[0]


@pytest.mark.parametrize("attack,fires", [
    ({**_ATTACK, "InputStrength": "NONE"}, True),
    ({**_ATTACK, "InputEnabled": False}, True),
    ({**_ATTACK, "InputEnabled": "true"}, False),
])
def test_a_prompt_attack_filter_off_for_input_does_not_count(tmp_path: Path, attack: dict, fires: bool) -> None:
    guard = _guard(ContentPolicyConfig={"FiltersConfig": [attack]})
    assert ("CF-BEDROCK-013" in _scan(tmp_path, {"G": guard})[0]) is fires


@pytest.mark.parametrize("pii,fires", [
    ({"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": "NONE"}]}, True),
    ({"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": "BLOCK", "OutputAction": "NONE"}]}, True),
    ({"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": "NONE", "OutputAction": "ANONYMIZE"}]}, False),
    ({"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": "NONE"}],
      "RegexesConfig": [{"Name": "k", "Pattern": "AKIA.*", "Action": "BLOCK"}]}, False),
    ({"PiiEntitiesConfig": [{"Type": "EMAIL", "Action": {"Ref": "A"}}]}, False),
    ({"PiiEntitiesConfig": []}, False),
])
def test_response_filter_check_reads_each_entity(tmp_path: Path, pii: dict, fires: bool) -> None:
    guard = _guard(ContentPolicyConfig=_CONTENT, SensitiveInformationPolicyConfig=pii)
    assert ("CF-BEDROCK-014" in _scan(tmp_path, {"G": guard})[0]) is fires


def test_agentsec08_checks_stay_off_for_a_non_ai_scan(tmp_path: Path) -> None:
    guard = _guard(ContentPolicyConfig=_CONTENT, SensitiveInformationPolicyConfig=_PII_IN_ONLY)
    ids, _ = _scan(tmp_path, {"G": guard}, lenses_ai=False)
    assert not ids & set(AGENTSEC08_CASES)


# --- AGENTSEC 7: human oversight and rogue agents --------------------------------------------

OVERSIGHT_IDS = {"REPO-208", "REPO-209", "REPO-210"}
_RED_TEAM_ONCE = {".github/workflows/ci.yml": "on: [push]\njobs:\n  t:\n    steps:\n      - run: garak --model_type rest\n"}
_RED_TEAM_WEEKLY = {".github/workflows/redteam.yml": (
    "on:\n  schedule:\n    - cron: '0 3 * * 1'\njobs:\n  r:\n    steps:\n      - run: npx promptfoo redteam run\n")}


def _oversight_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None,
                   **kwargs) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": AGENT}, {"README.md": "# App\n", **files}, **kwargs)
    return ids & OVERSIGHT_IDS


def test_an_agent_with_no_oversight_controls_reports_all_three(tmp_path: Path) -> None:
    assert _oversight_ids(tmp_path, _CI) == OVERSIGHT_IDS


@pytest.mark.parametrize("rule_id,files", [
    ("REPO-208", {"docs/approval-policy.md": "Two reviewers approve a payment.\n"}),
    ("REPO-208", {"docs/ops.md": "# Four-eyes review\n\nCritical operations.\n"}),
    ("REPO-209", {"docs/agent-containment.md": "Revoke the role session.\n"}),
    ("REPO-209", {"docs/ops.md": "# Rogue agents\n\nDisable the alias.\n"}),
    ("REPO-210", _RED_TEAM_WEEKLY),
    ("REPO-210", {"docs/security-assessments.md": "2026-11: red team found two issues.\n"}),
])
def test_adding_the_answer_clears_that_oversight_rule(tmp_path: Path, rule_id: str, files: dict) -> None:
    assert _oversight_ids(tmp_path, {**_CI, **files}) == OVERSIGHT_IDS - {rule_id}


def test_an_anomaly_detector_in_the_iac_clears_anomaly_detection(tmp_path: Path) -> None:
    detector = {"Type": "AWS::CloudWatch::AnomalyDetector", "Properties": {
        "Namespace": "AWS/Bedrock", "MetricName": "Invocations", "Stat": "Sum"}}
    got = _oversight_ids(tmp_path, _CI, resources={"A": AGENT, "D": detector})
    assert got == OVERSIGHT_IDS - {"REPO-209"}


def test_a_red_team_run_only_on_push_is_not_on_a_schedule(tmp_path: Path) -> None:
    assert "REPO-210" in _oversight_ids(tmp_path, _RED_TEAM_ONCE)
    # The same run does answer REPO-205, which asks only for a scan in the pipeline.
    assert "REPO-205" not in _scan(tmp_path / "again", {"A": AGENT}, _RED_TEAM_ONCE)[0]


def test_oversight_rules_need_an_agent(tmp_path: Path) -> None:
    assert _oversight_ids(tmp_path / "sagemaker", _CI, resources={"E": ENDPOINT}) == set()
    assert _oversight_ids(tmp_path / "s3", _CI, resources={"B": S3}) == set()


def test_oversight_rules_answer_agentsec_7_only() -> None:
    for rid in OVERSIGHT_IDS:
        assert rid not in wa_map.RULE_BEST_PRACTICES
        assert RULE_TOPICS[rid] in TOPICS
        bps = lens_map.LENS_RULE_BEST_PRACTICES[rid]
        assert {bp[:10] for bp in bps} == {"AGENTSEC07"}
        assert not set(bps) & lens_map.LENS_NOT_CHECKED


# --- AGENTSEC 6, 5 and 3: multi-agent trust, agent records and tracing, agent identities -----

SUPERVISOR = {"Type": "AWS::Bedrock::Agent", "Properties": {"AgentName": "s", "AgentCollaboration": "SUPERVISOR"}}
AGENT_RECORD_IDS = {"REPO-211", "REPO-212", "REPO-213", "REPO-214", "REPO-215", "REPO-216"}


def _record_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": SUPERVISOR}, {"README.md": "# App\n", **files})
    return ids & AGENT_RECORD_IDS


def test_a_supervisor_agent_with_no_controls_reports_all_six(tmp_path: Path) -> None:
    assert _record_ids(tmp_path, _CI) == AGENT_RECORD_IDS


def test_multi_agent_rules_need_a_multi_agent_system(tmp_path: Path) -> None:
    assert _record_ids(tmp_path, _CI, resources={"A": AGENT}) == AGENT_RECORD_IDS - {"REPO-211", "REPO-212"}
    disabled = {"Type": "AWS::Bedrock::Agent", "Properties": {"AgentName": "a", "AgentCollaboration": "DISABLED"}}
    assert not _record_ids(tmp_path / "off", _CI, resources={"A": disabled}) & {"REPO-211", "REPO-212"}


@pytest.mark.parametrize("cleared,files,extra", [
    ({"REPO-211"}, {"docs/multi-agent-security.md": "Trust boundaries.\n"}, {}),
    ({"REPO-211"}, {"docs/ops.md": "# Agent-to-agent messages\n\nSigned.\n"}, {}),
    ({"REPO-212", "REPO-214"}, {"requirements.txt": "aws-xray-sdk==2.12\n"}, {}),
    ({"REPO-212"}, {}, {"D": {"Type": "AWS::CloudWatch::AnomalyDetector", "Properties": {}}}),
    ({"REPO-213"}, {"docs/audit-trail.md": "Invocation logs.\n"}, {}),
    ({"REPO-213"}, {"app/run.py": 'import boto3\nc = boto3.client("bedrock-agent-runtime")\n'
                                  'c.invoke_agent(agentId="a", enableTrace=True)\n'}, {}),
    ({"REPO-212", "REPO-214"}, {"requirements.txt": "aws-opentelemetry-distro==0.10\n"}, {}),
    ({"REPO-215"}, {}, {"R": {"Type": "AWS::BedrockAgentCore::Runtime", "Properties": {
        "AuthorizerConfiguration": {"CustomJWTAuthorizer": {"DiscoveryUrl": "https://idp"}}}}}),
    ({"REPO-216"}, {}, {"U": {"Type": "AWS::AccessAnalyzer::Analyzer", "Properties": {"Type": "ACCOUNT_UNUSED_ACCESS"}}}),
    ({"REPO-216"}, {"docs/access-review.md": "2026-11 review of agent roles.\n"}, {}),
])
def test_adding_the_answer_clears_those_rules(tmp_path: Path, cleared: set, files: dict, extra: dict) -> None:
    got = _record_ids(tmp_path, {**_CI, **files}, resources={"A": SUPERVISOR, **extra})
    assert got == AGENT_RECORD_IDS - cleared


def test_an_external_access_analyzer_is_not_an_unused_access_review(tmp_path: Path) -> None:
    external = {"Type": "AWS::AccessAnalyzer::Analyzer", "Properties": {"Type": "ACCOUNT"}}
    assert "REPO-216" in _record_ids(tmp_path, _CI, resources={"A": AGENT, "X": external})


def _role(trust: dict, **props) -> dict:
    return {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": trust}]}, **props}}


_AGENT_TRUST = {"Service": "bedrock.amazonaws.com"}
_SHARED_TRUST = {"Service": "bedrock.amazonaws.com", "AWS": "arn:aws:iam::111122223333:root"}
_BOUNDARY = {"PermissionsBoundary": "arn:aws:iam::111122223333:policy/agent-boundary"}
_TF_ROLE = (
    'resource "aws_iam_role" "r" {\n  name = "r"\n%s'
    '  assume_role_policy = jsonencode({\n    Version = "2012-10-17"\n'
    '    Statement = [{\n      Effect = "Allow"\n      Action = "sts:AssumeRole"\n'
    '      Principal = %s\n    }]\n  })\n}\n'
)
_TF_AGENT = 'resource "aws_bedrockagent_agent" "a" {\n  agent_name = "a"\n}\n'

AGENT_ROLE_CASES = {
    "CF-BEDROCK-015": ({"A": AGENT, "R": _role(_SHARED_TRUST, **_BOUNDARY)},
                       {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY)},
                       _TF_AGENT + _TF_ROLE % ('  permissions_boundary = "arn:aws:iam::1:policy/b"\n',
                                               '{ Service = "bedrock.amazonaws.com", AWS = "arn:aws:iam::111122223333:root" }'),
                       _TF_AGENT + _TF_ROLE % ('  permissions_boundary = "arn:aws:iam::1:policy/b"\n',
                                               '{ Service = "bedrock.amazonaws.com" }')),
    "CF-BEDROCK-016": ({"A": AGENT, "R": _role(_AGENT_TRUST)},
                       {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY)},
                       _TF_AGENT + _TF_ROLE % ("", '{ Service = "bedrock.amazonaws.com" }'),
                       _TF_AGENT + _TF_ROLE % ('  permissions_boundary = "arn:aws:iam::1:policy/b"\n',
                                               '{ Service = "bedrock.amazonaws.com" }')),
}


@pytest.mark.parametrize("check_id", sorted(AGENT_ROLE_CASES))
def test_agent_role_check_fails_and_passes_on_each_source(tmp_path: Path, check_id: str) -> None:
    cf_fail, cf_pass, tf_fail, tf_pass = AGENT_ROLE_CASES[check_id]
    ids, findings = _scan(tmp_path / "cf-fail", cf_fail)
    assert check_id in ids
    f = next(f for f in findings if f.id == check_id)
    assert f.best_practices == list(lens_map.LENS_RULE_BEST_PRACTICES[check_id])
    assert check_id not in _scan(tmp_path / "cf-pass", cf_pass)[0]
    assert check_id in _cdk_ids(tmp_path / "cdk-fail", cf_fail)
    assert check_id not in _cdk_ids(tmp_path / "cdk-pass", cf_pass)
    assert check_id in _tf_ids(tmp_path / "tf-fail", tf_fail)
    assert check_id not in _tf_ids(tmp_path / "tf-pass", tf_pass)
    assert check_id in _CLOUDFORMATION and check_id in _TERRAFORM
    assert RULE_TOPICS[check_id] in TOPICS
    assert check_id not in wa_map.RULE_BEST_PRACTICES


def test_agent_role_checks_skip_other_roles_and_unreadable_trust(tmp_path: Path) -> None:
    lambda_role = _role({"Service": "lambda.amazonaws.com", "AWS": "arn:aws:iam::111122223333:root"})
    unknown = {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Ref": "Trust"}}}
    ids, _ = _scan(tmp_path, {"A": AGENT, "L": lambda_role, "U": unknown})
    assert not ids & set(AGENT_ROLE_CASES)
    # No AI resource: an agent role alone does not turn the lenses on.
    ids, _ = _scan(tmp_path / "no-ai", {"R": _role(_SHARED_TRUST)})
    assert not ids & set(AGENT_ROLE_CASES)


def test_agentcore_service_counts_as_an_agent_service(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path, {"A": AGENT, "R": _role({"Service": "bedrock-agentcore.amazonaws.com"})})
    assert "CF-BEDROCK-016" in ids


# --- GENSEC 5 and 6: agent role scope and training data validation ---------------------------

_WIDE = {"Policies": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "lambda:*", "Resource": "*"}]}}]}
_NARROW = {"Policies": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "arn:aws:bedrock:us-east-1::foundation-model/m"}]}}]}
_TF_POLICY = (
    'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.r.id\n'
    '  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n'
    '      Effect = "Allow"\n      Action = "%s"\n      Resource = "%s"\n    }]\n  })\n}\n'
)
_TF_AGENT_ROLE = _TF_AGENT + _TF_ROLE % ('  permissions_boundary = "arn:aws:iam::1:policy/b"\n',
                                         '{ Service = "bedrock.amazonaws.com" }')


def test_agent_role_scope_check_fails_and_passes_on_each_source(tmp_path: Path) -> None:
    cid = "CF-BEDROCK-017"
    fail = {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY, **_WIDE)}
    ok = {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY, **_NARROW)}
    ids, findings = _scan(tmp_path / "cf-fail", fail)
    assert cid in ids
    assert next(f for f in findings if f.id == cid).best_practices == ["GENSEC05-BP01"]
    assert cid not in _scan(tmp_path / "cf-pass", ok)[0]
    assert cid in _cdk_ids(tmp_path / "cdk-fail", fail)
    assert cid not in _cdk_ids(tmp_path / "cdk-pass", ok)
    assert cid in _tf_ids(tmp_path / "tf-fail", _TF_AGENT_ROLE + _TF_POLICY % ("lambda:*", "*"))
    assert cid not in _tf_ids(tmp_path / "tf-pass", _TF_AGENT_ROLE + _TF_POLICY % (
        "bedrock:InvokeModel", "arn:aws:bedrock:us-east-1::foundation-model/m"))
    assert cid in _CLOUDFORMATION and cid in _TERRAFORM and RULE_TOPICS[cid] in TOPICS
    admin = _role(_AGENT_TRUST, **_BOUNDARY, ManagedPolicyArns=["arn:aws:iam::aws:policy/AdministratorAccess"])
    assert cid in _scan(tmp_path / "admin", {"A": AGENT, "R": admin})[0]


def test_agent_role_scope_skips_roles_no_agent_assumes(tmp_path: Path) -> None:
    lambda_role = _role({"Service": "lambda.amazonaws.com"}, **_WIDE)
    assert "CF-BEDROCK-017" not in _scan(tmp_path, {"A": AGENT, "L": lambda_role})[0]


_PIPELINE = {"Type": "AWS::SageMaker::Pipeline", "Properties": {
    "PipelineName": "train", "RoleArn": "r", "PipelineDefinition": {"PipelineDefinitionBody": "{}"}}}
_CUSTOMIZE = {"app/tune.py": 'import boto3\nb = boto3.client("bedrock")\nb.create_model_customization_job(jobName="j")\n'}


@pytest.mark.parametrize("files,fires", [
    ({}, True),
    ({"requirements.txt": "great-expectations==1.0\n"}, False),
    ({"pipeline/build.py": "from sagemaker.workflow.quality_check_step import DataQualityCheckStep\n"}, False),
    ({".github/workflows/data.yml": "jobs:\n  d:\n    steps:\n      - run: python -m pydeequ.check\n"}, False),
    ({"tests/test_data.py": "import great_expectations\n"}, True),
])
def test_training_data_rules_read_tools_outside_tests(tmp_path: Path, files: dict, fires: bool) -> None:
    ids, _ = _scan(tmp_path / "bedrock", {"A": AGENT}, {**_CI, **_CUSTOMIZE, **files})
    assert ("REPO-217" in ids) is fires
    ids, _ = _scan(tmp_path / "sagemaker", {"E": ENDPOINT, "P": _PIPELINE}, {**_CI, **files})
    assert ("REPO-221" in ids) is fires


def test_training_data_rules_split_by_service(tmp_path: Path) -> None:
    # SageMaker training is REPO-221's; Bedrock customization is REPO-217's.
    ids, _ = _scan(tmp_path / "sm", {"E": ENDPOINT, "P": _PIPELINE}, _CI)
    assert "REPO-221" in ids and "REPO-217" not in ids
    ids, _ = _scan(tmp_path / "br", {"A": AGENT}, {**_CI, **_CUSTOMIZE})
    assert "REPO-217" in ids and "REPO-221" not in ids
    assert "REPO-217" not in _scan(tmp_path / "off", {"A": AGENT}, {**_CI, **_CUSTOMIZE}, lenses_ai=False)[0]
    tf = _TF_AGENT + 'resource "aws_bedrock_custom_model" "m" {\n  custom_model_name = "m"\n}\n'
    assert "REPO-217" in _tf_ids(tmp_path / "tf", tf)




# --- Machine Learning lens security: MLSEC 1, 4, 5 and 6 -------------------------------------

ML_SECURITY_IDS = {"REPO-218", "REPO-219", "REPO-220", "REPO-221", "REPO-222", "REPO-223"}
_TRAIN = {"train.py": "from sagemaker.pytorch import PyTorch\nest = PyTorch(entry_point='t.py')\nest.fit()\n"}


def _ml_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None, **kwargs) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"E": ENDPOINT}, {"README.md": "# App\n", **files}, **kwargs)
    return ids & ML_SECURITY_IDS


def test_a_sagemaker_workload_that_trains_reports_all_six(tmp_path: Path) -> None:
    assert _ml_ids(tmp_path, {**_CI, **_TRAIN}) == ML_SECURITY_IDS


def test_training_rules_need_training(tmp_path: Path) -> None:
    assert _ml_ids(tmp_path, _CI) == ML_SECURITY_IDS - {"REPO-220", "REPO-221"}


@pytest.mark.parametrize("cleared,files,extra", [
    ({"REPO-218"}, {"docs/data-card.md": "Source and license.\n"}, {}),
    ({"REPO-218"}, {"docs/ml.md": "# Third-party licenses\n\nApache-2.0.\n"}, {}),
    ({"REPO-219"}, {}, {"P": {"Type": "AWS::SageMaker::Project", "Properties": {"ProjectName": "p"}}}),
    ({"REPO-219"}, {"docs/ml-governance.md": "Approved templates only.\n"}, {}),
    ({"REPO-220"}, {"train.py": _TRAIN["train.py"].replace("'t.py'", "'t.py', encrypt_inter_container_traffic=True")}, {}),
    ({"REPO-221"}, {"requirements.txt": "great-expectations==1.0\n"}, {}),
    ({"REPO-222"}, {"requirements.txt": "adversarial-robustness-toolbox==1.17\n"}, {}),
    ({"REPO-222"}, {".github/workflows/robust.yml": "jobs:\n  r:\n    steps:\n      - run: textattack attack\n"}, {}),
    ({"REPO-223"}, {}, {"T": {"Type": "AWS::CloudTrail::Trail", "Properties": {
        "IsLogging": True, "S3BucketName": "b",
        "EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::data/"]}]}]}}}),
    ({"REPO-223"}, {}, {"M": {"Type": "AWS::Macie::Session", "Properties": {}}}),
])
def test_adding_the_answer_clears_that_ml_security_rule(tmp_path: Path, cleared: set, files: dict,
                                                       extra: dict) -> None:
    got = _ml_ids(tmp_path, {**_CI, **_TRAIN, **files}, resources={"E": ENDPOINT, **extra})
    assert got == ML_SECURITY_IDS - cleared


def test_ml_security_rules_need_a_sagemaker_resource(tmp_path: Path) -> None:
    assert _ml_ids(tmp_path / "bedrock", {**_CI, **_TRAIN}, resources={"A": AGENT}) == set()
    assert _ml_ids(tmp_path / "off", {**_CI, **_TRAIN}, lenses_ai=False) == set()


def _policy(action, resource="*") -> dict:
    return {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "p", "Roles": ["r"], "PolicyDocument": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}}}


@pytest.mark.parametrize("policy,fires", [
    (_policy("sagemaker:InvokeEndpoint"), True),
    (_policy(["sagemaker:InvokeEndpointAsync", "sagemaker:Invoke*"]), True),
    (_policy("sagemaker:InvokeEndpoint", "arn:aws:sagemaker:us-east-1:1:endpoint/e"), False),
    (_policy("sagemaker:*"), False),
    (_policy("sagemaker:DescribeEndpoint"), False),
])
def test_invoke_every_endpoint_check(tmp_path: Path, policy: dict, fires: bool) -> None:
    ids, findings = _scan(tmp_path, {"E": ENDPOINT, "P": policy})
    assert ("CF-SAGE-014" in ids) is fires
    if fires:
        assert next(f for f in findings if f.id == "CF-SAGE-014").best_practices == ["MLSEC06-BP01"]


def test_invoke_every_endpoint_check_on_each_source(tmp_path: Path) -> None:
    assert "CF-SAGE-014" in _cdk_ids(tmp_path / "cdk", {"E": ENDPOINT, "P": _policy("sagemaker:InvokeEndpoint")})
    tf = _TF_MODEL % _TF_PACKAGE + _TF_POLICY % ("sagemaker:InvokeEndpoint", "*")
    assert "CF-SAGE-014" in _tf_ids(tmp_path / "tf", tf)
    tf_ok = _TF_MODEL % _TF_PACKAGE + _TF_POLICY % ("sagemaker:InvokeEndpoint", "arn:aws:sagemaker:us-east-1:1:endpoint/e")
    assert "CF-SAGE-014" not in _tf_ids(tmp_path / "tf-ok", tf_ok)
    assert "CF-SAGE-014" in _CLOUDFORMATION and "CF-SAGE-014" in _TERRAFORM
    assert RULE_TOPICS["CF-SAGE-014"] in TOPICS


# --- AGENTSEC 4, 2 and 1, AGENTOPS 2 and 1: the remaining agent practices --------------------

AGENT_PRACTICE_IDS = {f"REPO-{n}" for n in range(224, 234)}
MEMORY = {"Type": "AWS::BedrockAgentCore::Memory", "Properties": {"Name": "m", "EventExpiryDuration": 30}}


def _practice_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": SUPERVISOR, "M": MEMORY}, {"README.md": "# App\n", **files})
    return ids & AGENT_PRACTICE_IDS


def test_an_agent_with_none_of_the_practices_reports_all_ten(tmp_path: Path) -> None:
    assert _practice_ids(tmp_path, _CI) == AGENT_PRACTICE_IDS


def test_memory_and_hand_off_rules_need_their_resources(tmp_path: Path) -> None:
    assert _practice_ids(tmp_path, _CI, resources={"A": AGENT}) == AGENT_PRACTICE_IDS - {"REPO-227", "REPO-232"}
    assert _practice_ids(tmp_path / "sm", _CI, resources={"E": ENDPOINT}) == set()


_ACTION_GROUP = {"ActionGroups": [{"ActionGroupName": "refunds", "FunctionSchema": {"Functions": [
    {"Name": "refund", "RequireConfirmation": "ENABLED"}]}}]}


@pytest.mark.parametrize("cleared,files,extra", [
    ({"REPO-224"}, {}, {"A": {"Type": "AWS::Bedrock::Agent", "Properties": {
        "AgentName": "s", "AgentCollaboration": "SUPERVISOR", **_ACTION_GROUP}}}),
    ({"REPO-225"}, {"tools/refund.py": "from pydantic import BaseModel\n"}, {}),
    ({"REPO-225"}, {"package.json": '{"dependencies": {"zod": "3.23.0"}}\n'}, {}),
    ({"REPO-226"}, {}, {"G": {"Type": "AWS::BedrockAgentCore::Gateway", "Properties": {"Name": "g"}}}),
    ({"REPO-227"}, {"app/mem.py": "client.apply_guardrail(source='INPUT')\n"}, {}),
    ({"REPO-228"}, {}, {"G": _guard(ContentPolicyConfig=_CONTENT, ContextualGroundingPolicyConfig=_GROUNDING)}),
    ({"REPO-229"}, {}, {"V": {"Type": "AWS::Bedrock::PromptVersion", "Properties": {"PromptArn": "p"}}}),
    ({"REPO-230"}, {".github/workflows/drift.yml": "jobs:\n  d:\n    steps:\n      - run: aws cloudformation detect-stack-drift --stack-name s\n"}, {}),
    ({"REPO-231"}, {"docs/ops.md": "# Continuous improvement\n\nWeekly.\n"}, {}),
    ({"REPO-232"}, {"docs/ops.md": "# Hand-offs\n\nTo a person.\n"}, {}),
    ({"REPO-233"}, {"tests/test_tool_timeout.py": "def test_x():\n    pass\n"}, {}),
    ({"REPO-233"}, {}, {"F": {"Type": "AWS::FIS::ExperimentTemplate", "Properties": {}}}),
])
def test_adding_the_answer_clears_that_agent_practice(tmp_path: Path, cleared: set, files: dict,
                                                       extra: dict) -> None:
    got = _practice_ids(tmp_path, {**_CI, **files}, resources={"A": SUPERVISOR, "M": MEMORY, **extra})
    assert got == AGENT_PRACTICE_IDS - cleared


def test_a_test_named_for_failure_outside_tests_does_not_count(tmp_path: Path) -> None:
    assert "REPO-233" in _practice_ids(tmp_path, {**_CI, "src/failure.py": "x = 1\n"})


# --- Responsible AI lens: RAIUC 4, RAIBR 4, RAIRC 3, RAIMON 1, RAIGT 1, RAISP 3 ---------------

RAI_IDS = {f"REPO-{n}" for n in range(234, 250)}


def _rai_ids(tmp_path: Path, files: dict[str, str], resources: dict | None = None, **kwargs) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"A": AGENT}, {"README.md": "# App\n", **files}, **kwargs)
    return ids & RAI_IDS


def test_an_ai_workload_with_no_rai_practices_reports_all(tmp_path: Path) -> None:
    assert _rai_ids(tmp_path, _CI) == RAI_IDS
    assert _rai_ids(tmp_path / "sm", _CI, resources={"E": ENDPOINT}) == RAI_IDS


def test_rai_rules_stay_off_for_a_non_ai_repo(tmp_path: Path) -> None:
    assert _rai_ids(tmp_path / "s3", _CI, resources={"B": S3}) == set()
    assert _rai_ids(tmp_path / "off", _CI, lenses_ai=False) == set()


def test_metric_rules_need_a_build(tmp_path: Path) -> None:
    got = _rai_ids(tmp_path, {})
    assert not got & {f"REPO-{n}" for n in range(237, 245)}


@pytest.mark.parametrize("cleared,files,extra", [
    ({"REPO-234"}, {"docs/ux.md": "# User journey\n\nSteps.\n"}, {}),
    ({"REPO-235"}, {"docs/a11y.md": "Screen readers.\n"}, {}),
    ({"REPO-236"}, {"docs/ai.md": "# Trade-offs\n\nAccuracy over speed.\n"}, {}),
    ({"REPO-237"}, {"evals/promptfooconfig.yaml": "defaultTest:\n  assert:\n    - type: moderation\n      metric: toxicity\n"}, {}),
    ({"REPO-238", "REPO-243"}, {"evals/run.py": "from ragas.metrics import faithfulness\n# jailbreak suite\n"}, {}),
    ({"REPO-239"}, {"evals/robustness.py": "perturb = True\n"}, {}),
    ({"REPO-240"}, {"requirements.txt": "presidio-analyzer==2.2\n"}, {}),
    ({"REPO-241"}, {"evals/controllability.yaml": "cases: []\n"}, {}),
    ({"REPO-242"}, {"requirements.txt": "shap==0.46\n"}, {}),
    ({"REPO-244"}, {"evals/citations.yaml": "cases: []\n"}, {}),
    ({"REPO-245"}, {"docs/consent.md": "Opt in.\n"}, {}),
    ({"REPO-246"}, {}, {"M": {"Type": "AWS::SageMaker::MonitoringSchedule", "Properties": {}}}),
    ({"REPO-247"}, {}, {"D": {"Type": "AWS::CloudWatch::Dashboard", "Properties": {"DashboardBody": "{}"}}}),
    ({"REPO-248"}, {"docs/ai-notice.md": "Users are told.\n"}, {}),
    ({"REPO-249"}, {"docs/responsible-use.md": "What to avoid.\n"}, {}),
])
def test_adding_the_answer_clears_that_rai_rule(tmp_path: Path, cleared: set, files: dict, extra: dict) -> None:
    got = _rai_ids(tmp_path, {**_CI, **files}, resources={"A": AGENT, **extra})
    assert got == RAI_IDS - cleared


def test_a_metric_named_only_in_a_test_does_not_count(tmp_path: Path) -> None:
    assert "REPO-237" in _rai_ids(tmp_path, {**_CI, "tests/test_toxicity.py": "toxicity = 0\n"})


_HARM = {"Type": "HATE", "InputStrength": "HIGH", "OutputStrength": "HIGH"}
RAISP_CASES = {
    "CF-BEDROCK-018": ({"G": _guard(ContentPolicyConfig={"FiltersConfig": [{**_HARM, "InputStrength": "NONE"}, _ATTACK]})},
                       {"G": _guard(ContentPolicyConfig={"FiltersConfig": [_HARM, _ATTACK]})},
                       _TF_GUARD % _TF_FILTER.replace('input_strength = "HIGH"', 'input_strength = "NONE"'),
                       _TF_GUARD % _TF_FILTER),
    "CF-BEDROCK-019": ({"G": _guard(ContentPolicyConfig={"FiltersConfig": [_ATTACK]})},
                       {"G": _guard(ContentPolicyConfig={"FiltersConfig": [_HARM, _ATTACK]})},
                       _TF_GUARD % _TF_FILTER.replace('output_strength = "HIGH"', 'output_strength = "NONE"'),
                       _TF_GUARD % _TF_FILTER),
    "CF-SAGE-015": ({"C": _config(DataCaptureConfig=_CAPTURE)},
                    {"C": _config(DataCaptureConfig={**_CAPTURE, "KmsKeyId": _KEY})},
                    _TF_CONFIG % _TF_CAPTURE,
                    _TF_CONFIG % _TF_CAPTURE.replace("    enable_capture", f'    kms_key_id = "{_KEY}"\n    enable_capture')),
}


@pytest.mark.parametrize("check_id", sorted(RAISP_CASES))
def test_rai_template_check_fails_and_passes_on_each_source(tmp_path: Path, check_id: str) -> None:
    cf_fail, cf_pass, tf_fail, tf_pass = RAISP_CASES[check_id]
    ids, findings = _scan(tmp_path / "cf-fail", cf_fail)
    assert check_id in ids
    assert next(f for f in findings if f.id == check_id).best_practices == list(
        lens_map.LENS_RULE_BEST_PRACTICES[check_id])
    assert check_id not in _scan(tmp_path / "cf-pass", cf_pass)[0]
    assert check_id in _cdk_ids(tmp_path / "cdk-fail", cf_fail)
    assert check_id not in _cdk_ids(tmp_path / "cdk-pass", cf_pass)
    assert check_id in _tf_ids(tmp_path / "tf-fail", tf_fail)
    assert check_id not in _tf_ids(tmp_path / "tf-pass", tf_pass)
    assert check_id in _CLOUDFORMATION and check_id in _TERRAFORM
    assert RULE_TOPICS[check_id] in TOPICS


def test_harm_filter_checks_skip_005_and_unreadable(tmp_path: Path) -> None:
    for name, guard in (("topics", _guard(TopicPolicyConfig=_TOPICS)),
                        ("ref", _guard(ContentPolicyConfig={"FiltersConfig": [{**_HARM, "OutputStrength": {"Ref": "S"}}]}))):
        ids = _scan(tmp_path / name, {"G": guard})[0]
        assert "CF-BEDROCK-019" not in ids
    # PII only: no harmful-content filter on either side.
    ids = _scan(tmp_path / "pii", {"G": _guard(SensitiveInformationPolicyConfig=_PII)})[0]
    assert {"CF-BEDROCK-018", "CF-BEDROCK-019"} <= ids


# --- GENSEC 1, MLSEC 3: model, data store and execution role scope ---------------------------

def test_invoke_every_model_check(tmp_path: Path) -> None:
    ids, findings = _scan(tmp_path / "wide", {"A": AGENT, "P": _policy("bedrock:InvokeModel")})
    assert "CF-BEDROCK-020" in ids
    assert next(f for f in findings if f.id == "CF-BEDROCK-020").best_practices == ["GENSEC01-BP01"]
    assert "CF-BEDROCK-020" not in _scan(tmp_path / "named", {"A": AGENT, "P": _policy(
        "bedrock:InvokeModel", "arn:aws:bedrock:us-east-1::foundation-model/m")})[0]
    assert "CF-BEDROCK-020" not in _scan(tmp_path / "svc", {"A": AGENT, "P": _policy("bedrock:*")})[0]
    assert "CF-BEDROCK-020" in _cdk_ids(tmp_path / "cdk", {"A": AGENT, "P": _policy("bedrock:Invoke*")})
    assert "CF-BEDROCK-020" in _tf_ids(tmp_path / "tf", _TF_AGENT + _TF_POLICY % ("bedrock:InvokeModel", "*"))


def test_bedrock_role_reading_every_data_store(tmp_path: Path) -> None:
    reads = {"Policies": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}]}}]}
    scoped = {"Policies": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::docs/*"}]}}]}
    ids = _scan(tmp_path / "wide", {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY, **reads)})[0]
    assert "CF-BEDROCK-021" in ids
    assert "CF-BEDROCK-021" not in _scan(tmp_path / "ok", {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY, **scoped)})[0]
    lam = _role({"Service": "lambda.amazonaws.com"}, **reads)
    assert "CF-BEDROCK-021" not in _scan(tmp_path / "lambda", {"A": AGENT, "R": lam})[0]
    assert "CF-BEDROCK-021" in _tf_ids(tmp_path / "tf", _TF_AGENT_ROLE + _TF_POLICY % ("s3:GetObject", "*"))


def test_sagemaker_execution_role_scope(tmp_path: Path) -> None:
    sm = {"Service": "sagemaker.amazonaws.com"}
    full = _role(sm, ManagedPolicyArns=["arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"])
    ids, findings = _scan(tmp_path / "full", {"E": ENDPOINT, "R": full})
    assert "CF-SAGE-016" in ids
    assert next(f for f in findings if f.id == "CF-SAGE-016").best_practices == ["MLSEC03-BP01"]
    assert "CF-SAGE-016" in _scan(tmp_path / "wide", {"E": ENDPOINT, "R": _role(sm, **_WIDE)})[0]
    assert "CF-SAGE-016" not in _scan(tmp_path / "ok", {"E": ENDPOINT, "R": _role(sm, **_NARROW)})[0]
    tf = _TF_MODEL % _TF_PACKAGE + (_TF_ROLE % ("", '{ Service = "sagemaker.amazonaws.com" }')).replace(
        'resource "aws_iam_role" "r" {\n', 'resource "aws_iam_role" "r" {\n  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonS3FullAccess"]\n')
    assert "CF-SAGE-016" in _tf_ids(tmp_path / "tf", tf)
    for cid in ("CF-BEDROCK-020", "CF-BEDROCK-021", "CF-SAGE-016"):
        assert cid in _CLOUDFORMATION and cid in _TERRAFORM and RULE_TOPICS[cid] in TOPICS


# --- Generative AI Medium practices: REPO-250 to REPO-258 ------------------------------------

_BEDROCK_CALL_PY = 'import boto3\nc = boto3.client("bedrock-runtime")\nc.converse(modelId=m, %smessages=[])\n'


@pytest.mark.parametrize("rule_id,lacking,answer", [
    ("REPO-250", {"app.py": _BEDROCK_CALL_PY % ""}, {"app.py": "def validate(x):\n    pass\n" + _BEDROCK_CALL_PY % ""}),
    ("REPO-253", {"app.py": _BEDROCK_CALL_PY % ""}, {"app.py": "import tenacity\n" + _BEDROCK_CALL_PY % ""}),
    ("REPO-256", {"app.py": _BEDROCK_CALL_PY % ""}, {"app.py": "n = client.count_tokens(x)\n" + _BEDROCK_CALL_PY % ""}),
    ("REPO-257", {"app.py": _BEDROCK_CALL_PY % ""}, {"app.py": _BEDROCK_CALL_PY % 'system=[{"cachePoint": {"type": "default"}}], '}),
    ("REPO-258", {"app.py": _BEDROCK_CALL_PY % 'guardrailConfig={"guardrailIdentifier": "g"}, '},
     {"app.py": _BEDROCK_CALL_PY % 'guardrailConfig={"guardrailIdentifier": "g"}, ' + "# guardContent\n"}),
    ("REPO-251", {}, {"docs/audit-logs.md": "CloudTrail data.\n"}),
    ("REPO-254", {}, {"app.py": "cloudwatch.put_metric_data(Namespace='App')\n"}),
    ("REPO-255", {}, {"docs/feedback.md": "Thumbs up and down.\n"}),
])
def test_genai_medium_rule_fires_and_clears(tmp_path: Path, rule_id: str, lacking: dict, answer: dict) -> None:
    assert rule_id in _scan(tmp_path / "lacking", {"A": AGENT}, {**_CI, **lacking})[0]
    assert rule_id not in _scan(tmp_path / "answered", {"A": AGENT}, {**_CI, **lacking, **answer})[0]


def test_model_ids_in_one_file_are_a_catalog(tmp_path: Path) -> None:
    one = {"models.py": "A = 'anthropic.claude-3-haiku-20240307-v1:0'\nB = 'amazon.titan-embed-text-v2:0'\n"}
    assert "REPO-252" not in _scan(tmp_path / "one", {"A": AGENT}, one)[0]
    two = {**one, "app.py": "m = 'us.anthropic.claude-3-5-sonnet-20241022-v2:0'\n"}
    assert "REPO-252" in _scan(tmp_path / "two", {"A": AGENT}, two)[0]


def test_unguarded_calls_are_199s_and_not_258s(tmp_path: Path) -> None:
    ids = _scan(tmp_path, {"A": AGENT}, {"app.py": _BEDROCK_CALL_PY % ""})[0]
    assert "REPO-199" in ids and "REPO-258" not in ids


def test_genai_medium_rules_stay_off_for_a_non_ai_repo(tmp_path: Path) -> None:
    ids = _scan(tmp_path, {"B": S3}, {**_CI, "app.py": _BEDROCK_CALL_PY % ""})[0]
    assert not ids & {f"REPO-{n}" for n in range(250, 259)}


# --- Machine Learning Medium practices: REPO-259 to REPO-276 ---------------------------------

ML_MEDIUM_IDS = {f"REPO-{n}" for n in range(259, 277)}


def _ml_medium(tmp_path: Path, files: dict, resources: dict | None = None) -> set[str]:
    ids, _ = _scan(tmp_path, resources or {"E": ENDPOINT}, {"README.md": "# App\n", **files})
    return ids & ML_MEDIUM_IDS


def test_a_training_sagemaker_workload_reports_the_ml_medium_rules(tmp_path: Path) -> None:
    # A build config answers REPO-269; no GPU host means no REPO-272.
    assert _ml_medium(tmp_path, {**_CI, **_TRAIN}) == ML_MEDIUM_IDS - {"REPO-269", "REPO-272"}


def test_training_lever_rules_need_training(tmp_path: Path) -> None:
    got = _ml_medium(tmp_path, _CI)
    assert not got & {"REPO-270", "REPO-271", "REPO-273", "REPO-274", "REPO-275"}


@pytest.mark.parametrize("cleared,files,extra", [
    ({"REPO-259"}, {"docs/data-privacy.md": "PII is masked.\n"}, {}),
    ({"REPO-260"}, {}, {"P": _PIPELINE}),
    ({"REPO-261"}, {}, {"B": {"Type": "AWS::S3::Bucket", "Properties": {"LifecycleConfiguration": {"Rules": []}}}}),
    ({"REPO-262"}, {}, {"F": {"Type": "AWS::SageMaker::FlowDefinition", "Properties": {}}}),
    ({"REPO-263"}, {"requirements.txt": "shap==0.46\n"}, {}),
    ({"REPO-264"}, {"monitor.py": "from sagemaker.model_monitor import DefaultModelMonitor\n"}, {}),
    ({"REPO-265"}, {}, {"R": {"Type": "AWS::Events::Rule", "Properties": {"Targets": [
        {"Arn": "p", "Id": "t", "SageMakerPipelineParameters": {}}]}}}),
    ({"REPO-266"}, {"docs/feature-review.md": "Monthly.\n"}, {}),
    ({"REPO-267"}, {".github/workflows/drift.yml": "jobs:\n  d:\n    steps:\n      - run: terraform plan -detailed-exitcode\n"}, {}),
    ({"REPO-268"}, {"docs/ml.md": "# Instance sizing\n\nml.g5.xlarge.\n"}, {}),
    ({"REPO-270"}, {"local.py": "est = PyTorch(entry_point='t.py', instance_type='local')\n"}, {}),
    ({"REPO-271"}, {"automl.py": "job = AutoMLV2()\n"}, {}),
    ({"REPO-273"}, {"train.py": _TRAIN["train.py"].replace("'t.py'", "'t.py', distribution={}")}, {}),
    ({"REPO-274"}, {"train.py": _TRAIN["train.py"].replace("'t.py'", "'t.py', checkpoint_s3_uri='s3://b/c'")}, {}),
    ({"REPO-275"}, {"tune.py": "import optuna\n"}, {}),
    ({"REPO-276"}, {}, {"B": {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": {}}}}),
])
def test_adding_the_answer_clears_that_ml_medium_rule(tmp_path: Path, cleared: set, files: dict, extra: dict) -> None:
    got = _ml_medium(tmp_path, {**_CI, **_TRAIN, **files}, resources={"E": ENDPOINT, **extra})
    assert got == ML_MEDIUM_IDS - {"REPO-269", "REPO-272"} - cleared


def test_gpu_hosts_and_no_build(tmp_path: Path) -> None:
    gpu = {"G": {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "p4d.24xlarge"}}}
    assert "REPO-272" in _ml_medium(tmp_path / "gpu", _CI, resources={"E": ENDPOINT, **gpu})
    assert "REPO-269" in _ml_medium(tmp_path / "no-build", {})


def test_ml_medium_rules_need_a_sagemaker_resource(tmp_path: Path) -> None:
    assert _ml_medium(tmp_path, {**_CI, **_TRAIN}, resources={"A": AGENT}) == set()


# --- One rule per remaining lens question: LENS_PRACTICE_TABLE -------------------------------

from aws_arch_agent.rules.repo_practices import LENS_PRACTICE_RULES, LENS_PRACTICE_TABLE  # noqa: E402

PRACTICE_IDS = {r.id for r in LENS_PRACTICE_RULES}
_GATE_RESOURCES = {"ai": {"A": AGENT}, "agent": {"A": AGENT}, "multi": {"A": SUPERVISOR},
                   "sagemaker": {"E": ENDPOINT}}


def test_every_lens_practice_has_a_rule_now() -> None:
    assert not lens_map.LENS_NOT_CHECKED
    for rule in LENS_PRACTICE_RULES:
        bps = lens_map.LENS_RULE_BEST_PRACTICES[rule.id]
        assert len({lenses.question_id_of_practice(bp) for bp in bps}) == 1
        assert rule.id not in wa_map.RULE_BEST_PRACTICES
        assert RULE_TOPICS[rule.id] in TOPICS


@pytest.mark.parametrize("gate", sorted(_GATE_RESOURCES))
def test_lens_practice_rules_fire_by_gate(tmp_path: Path, gate: str) -> None:
    ids, _ = _scan(tmp_path, _GATE_RESOURCES[gate], {"README.md": "# App\n"})
    expected = {rid for rid, _n, _q, g, *_r in LENS_PRACTICE_TABLE if g == gate}
    if gate == "ai":
        expected -= {"REPO-311"}  # applies only to self-hosted model serving
    if gate == "agent":
        # a supervisor is also an agent; a plain agent is not a multi-agent system
        assert not ids & {rid for rid, _n, _q, g, *_r in LENS_PRACTICE_TABLE if g == "multi"}
    assert expected <= ids


def test_lens_practice_rules_stay_off_outside_their_gate(tmp_path: Path) -> None:
    sagemaker_only = {rid for rid, _n, _q, g, *_r in LENS_PRACTICE_TABLE if g == "sagemaker"}
    agent_only = {rid for rid, _n, _q, g, *_r in LENS_PRACTICE_TABLE if g in ("agent", "multi")}
    assert not _scan(tmp_path / "bedrock", {"A": AGENT})[0] & sagemaker_only
    assert not _scan(tmp_path / "sm", {"E": ENDPOINT})[0] & agent_only
    assert not _scan(tmp_path / "s3", {"B": S3})[0] & PRACTICE_IDS
    assert not _scan(tmp_path / "off", {"A": AGENT}, lenses_ai=False)[0] & PRACTICE_IDS


@pytest.mark.parametrize("rule_id,resources,files", [
    ("REPO-280", {"E": ENDPOINT, "P": _PIPELINE}, {}),
    ("REPO-285", {"E": ENDPOINT, "C": _config(DataCaptureConfig=_CAPTURE)}, {"x.json": '{"DeploymentConfig": {}}'}),
    ("REPO-298", {"E": ENDPOINT, "B": {"Type": "AWS::S3::Bucket", "Properties": {"LifecycleConfiguration": {"Rules": []}}}}, {}),
    ("REPO-306", {"A": AGENT}, {"app.py": "MODEL = 'us.anthropic.claude-3-5-haiku-20241022-v1:0'\n"}),
    ("REPO-316", {"A": AGENT}, {"agent.py": "graph.invoke(x, {'recursion_limit': 10})\n"}),
    ("REPO-343", {"A": AGENT}, {"requirements.txt": "opentelemetry-sdk==1.27\n"}),
    ("REPO-346", {"A": AGENT, "Q": {"Type": "AWS::SQS::Queue", "Properties": {}}}, {}),
    ("REPO-349", {"A": SUPERVISOR, "S": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {}}}, {}),
    ("REPO-367", {"A": AGENT, "B": {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": {}}}}, {}),
])
def test_a_signal_in_the_repo_answers_the_question(tmp_path: Path, rule_id: str, resources: dict,
                                                   files: dict) -> None:
    gate = next(g for rid, _n, _q, g, *_r in LENS_PRACTICE_TABLE if rid == rule_id)
    assert rule_id in _scan(tmp_path / "lacking", _GATE_RESOURCES[gate])[0]
    assert rule_id not in _scan(tmp_path / "answered", resources, files)[0]


def test_managed_hosting_rule_needs_self_hosted_serving(tmp_path: Path) -> None:
    assert "REPO-311" not in _scan(tmp_path / "managed", {"A": AGENT})[0]
    assert "REPO-311" in _scan(tmp_path / "vllm", {"A": AGENT}, {"Dockerfile": "FROM vllm/vllm-openai:v0.6\n",
                                                                   "requirements.txt": "vllm==0.6\n"})[0]


def test_a_heading_answers_a_lens_practice_rule(tmp_path: Path) -> None:
    ids, _ = _scan(tmp_path, {"A": AGENT}, {"docs/ops.md": "# Break-glass\n\nHow to stop the agent.\n"})
    assert "REPO-345" not in ids


def test_note_names_match_whole_words_only(tmp_path: Path) -> None:
    # xml_team.md is not an "ml team" note; fault-detection.md is not threat detection.
    ids = _scan(tmp_path / "sm", {"E": ENDPOINT}, {"docs/xml_team.md": "x\n", "docs/html-pipeline.md": "x\n"})[0]
    assert {"REPO-277", "REPO-280"} <= ids
    ids = _scan(tmp_path / "agent", {"A": AGENT}, {"docs/fault-detection.md": "x\n", "docs/open-tests.md": "x\n"})[0]
    assert {"REPO-206", "REPO-207"} <= ids


def test_service_wildcards_are_not_data_reads(tmp_path: Path) -> None:
    wide = {"Policies": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:*", "dynamodb:*"], "Resource": "*"}]}}]}
    ids = _scan(tmp_path, {"A": AGENT, "R": _role(_AGENT_TRUST, **_BOUNDARY, **wide)})[0]
    assert "CF-BEDROCK-021" not in ids
