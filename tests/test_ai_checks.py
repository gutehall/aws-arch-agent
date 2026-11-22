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
