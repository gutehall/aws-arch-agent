"""Each repo-level rule of the last Well-Architected batch fires on a repo that lacks the
control and stays quiet once the repo has it.

The generic negative snippets in rule_cases.json hold no IaC, so an IaC-gated rule passes them
without being tested. Here the negative is the same repo with the answering note or resource."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import LENS_PRACTICE_TABLE

_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_HOST = {"i.tf": 'resource "aws_instance" "web" {\n  instance_type = "m5.large"\n}\n'}
_BIG = {"main.tf": "".join(f'resource "aws_lambda_function" "f{i}" {{\n}}\n' for i in range(4))
        + "".join(f'resource "aws_dynamodb_table" "t{i}" {{\n}}\n' for i in range(4))}
_MARKET = {"m.tf": 'data "aws_ami" "m" {\n  owners = ["aws-marketplace"]\n}\n'
                   'resource "aws_ec2_host" "h" {\n  instance_type = "m5.large"\n}\n'}
_ADR = ("# Compute\n\nWe considered Lambda and Fargate. The Well-Architected guidance and the "
        "reference architecture favour Lambda. The cost comparison is $40 against $120. The "
        "tradeoff is cold starts. A benchmark gave measured results, the data we used.\n")
_AI = {"a.tf": 'resource "aws_bedrockagent_agent" "a" {\n  agent_name = "a"\n}\n'}
_ALIAS = 'provider "aws" {\n  alias  = "east"\n  region = "us-east-1"\n}\n'
_CALL = ('import boto3\nc = boto3.client("bedrock-runtime")\n'
         'c.converse(modelId="m", %smessages=[])\n')
_RUNNER = 'resource "aws_instance" "gh_runner" {\n  instance_type = "m5.large"\n}\n'

# rule id: (the repo that lacks the control, what the repo adds or changes to have it)
CASES = {
    "REPO-161": (_TF, {"docs/customers.md": "Shops and support.\n"}),
    "REPO-162": (_TF, {"docs/compliance.md": "We follow PCI DSS.\n"}),
    "REPO-163": (_TF, {"docs/threat-model.md": "Assets and threats.\n"}),
    "REPO-164": (_TF, {"docs/adr/0001-queue.md": "Tradeoff: cost against ordering.\n"}),
    "REPO-165": ({**_TF, "docs/runbooks/restore.md": "Run it.\n"},
                 {"docs/runbooks/restore.md": "Owner: platform\n"}),
    "REPO-166": (_TF, {"docs/on-call.md": "Platform is on call.\n"}),
    "REPO-167": (_TF, {"docs/ownership.md": "Platform owns the network stack.\n"}),
    "REPO-168": (_TF, {"/.github/pull_request_template.md": "What changed?\n"}),
    "REPO-169": (_TF, {"docs/escalation.md": "After 15 minutes page the lead.\n"}),
    "REPO-170": (_TF, {"docs/on-call.md": "Page the platform rota.\n"}),
    "REPO-171": (_TF, {"docs/ops-ownership.md": "Sponsor: the CTO.\n"}),
    "REPO-172": (_TF, {"docs/runbooks/deploy.md": "Steps.\n"}),
    "REPO-173": (_TF, {"docs/playbooks/latency.md": "Open the dashboard.\n"}),
    "REPO-174": (_TF, {"docs/support-plan.md": "Enterprise Support.\n"}),
    "REPO-175": (_TF, {"docs/readiness.md": "- [ ] alarms\n- [ ] team trained\n"}),
    "REPO-176": (_TF, {"docs/post-incident-template.md": "## Lessons learned\n"}),
    "REPO-177": (_TF, {"/.github/ISSUE_TEMPLATE/change.md": "What was the outcome?\n"}),
    "REPO-178": (_TF, {"docs/continuous-improvement.md": "One fix a sprint.\n"}),
    "REPO-179": (_TF, {"docs/cost.md": "Steady usage is $400 a month; peak is $900.\n"}),
    "REPO-180": (_HOST, {"docs/cost-estimate.md": "Estimated cost: $120 a month.\n"}),
    "REPO-181": (_MARKET, {"docs/licensing.md": "Bring your own licence.\n"}),
    "REPO-182": (_TF, {"docs/cost-review-2026-03.md": "Reviewed on 2026-03-02.\n"}),
    "REPO-183": (_TF, {"docs/adr/0001-compute.md": _ADR}),
    "REPO-184": (_HOST, {"a.tf": 'resource "aws_cloudwatch_metric_alarm" "a" {\n'
                                 '  metric_name = "Latency"\n  threshold = 300\n}\n'}),
    "REPO-185": (_HOST, {"p.tf": 'resource "aws_autoscaling_policy" "p" {\n'
                                 '  policy_type = "TargetTrackingScaling"\n}\n'}),
    "REPO-186": (_TF, {"/.github/workflows/ci.yml": "jobs:\n  load:\n    steps:\n"
                                                    "      - run: k6 run load.js\n"}),
    "REPO-187": (_TF, {"docs/performance-review.md": "Reviewed monthly.\n"}),
    "REPO-188": (_BIG, {"main.tf": _BIG["main.tf"] + 'module "billing" {\n  source = "./b"\n}\n'}),
    "REPO-189": ({**_TF, "p.tf": _ALIAS},
                 {"p.tf": _ALIAS + 'resource "aws_s3_bucket" "r" {\n  provider = aws.east\n}\n'}),
    "REPO-190": (_TF, {"docs/sustainability.md": "Cut idle capacity by a third.\n"}),
    "REPO-191": (_TF, {"/.github/dependabot.yml": "version: 2\n"}),
    "REPO-192": ({"f.tf": _RUNNER},
                 {"f.tf": _RUNNER.replace("}\n", '  instance_market_options {\n'
                                          '    market_type = "spot"\n  }\n}\n')}),
    "REPO-194": (_AI, {"docs/responsible-ai.md": "Release criteria.\n"}),
    "REPO-195": (_AI, {"evals/golden.jsonl": "{}\n"}),
    "REPO-196": (_AI, {"docs/human-oversight.md": "A person approves.\n"}),
    "REPO-197": (_AI, {"docs/agent-role.md": "Success criteria.\n"}),
    "REPO-198": (_AI, {"prompts/system.txt": "Be helpful.\n"}),
    "REPO-199": ({**_AI, "app.py": _CALL % ""}, {"app.py": _CALL % 'guardrailConfig={"guardrailIdentifier": "g"}, '}),
    "REPO-200": ({**_AI, "app.py": _CALL % ""}, {"app.py": _CALL % 'inferenceConfig={"maxTokens": 256}, '}),
    "REPO-201": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"},
                 {"/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: npx promptfoo eval\n"}),
    "REPO-202": (_AI, {"docs/model-card.md": "Intended use and limitations.\n"}),
    "REPO-203": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n',
                  "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"},
                 {"/requirements.txt": "fairlearn==0.10\n"}),
    "REPO-204": (_AI, {"docs/escalation.md": "Who is paged and how to switch the model off.\n"}),
    "REPO-205": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"},
                 {"/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: npx promptfoo redteam run\n"}),
    "REPO-206": (_AI, {"docs/red-team.md": "Tests run in an isolated account.\n"}),
    "REPO-207": (_AI, {"g.tf": 'resource "aws_guardduty_detector" "d" {\n  enable = true\n}\n'}),
    "REPO-208": (_AI, {"docs/approval-policy.md": "Two reviewers approve a payment.\n"}),
    "REPO-209": (_AI, {"docs/agent-containment.md": "Revoke the role session.\n"}),
    "REPO-211": ({"a.tf": _AI["a.tf"].replace("}\n", '  agent_collaboration = "SUPERVISOR"\n}\n')},
                 {"docs/multi-agent-security.md": "Trust boundaries between agents.\n"}),
    "REPO-212": ({"a.tf": _AI["a.tf"].replace("}\n", '  agent_collaboration = "SUPERVISOR"\n}\n')},
                 {"/requirements.txt": "aws-xray-sdk==2.12\n"}),
    "REPO-213": (_AI, {"docs/audit-trail.md": "Invocation logs go to a locked bucket.\n"}),
    "REPO-214": (_AI, {"/requirements.txt": "aws-opentelemetry-distro==0.10\n"}),
    "REPO-215": (_AI, {"docs/agent-identity.md": "The agent uses a workload identity.\n"}),
    "REPO-216": (_AI, {"aa.tf": 'resource "aws_accessanalyzer_analyzer" "u" {\n  analyzer_name = "u"\n  type = "ACCOUNT_UNUSED_ACCESS"\n}\n'}),
    "REPO-217": ({**_AI, "p.tf": 'resource "aws_bedrock_custom_model" "m" {\n  custom_model_name = "m"\n}\n'},
                 {"/requirements.txt": "great-expectations==1.0\n"}),
    "REPO-218": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"docs/data-card.md": "Source, consent and license.\n"}),
    "REPO-219": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"p.tf": 'resource "aws_sagemaker_project" "p" {\n  project_name = "p"\n}\n'}),
    "REPO-220": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"},
                 {"train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py', encrypt_inter_container_traffic=True)\n"}),
    "REPO-221": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"},
                 {"/requirements.txt": "great-expectations==1.0\n"}),
    "REPO-222": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"},
                 {"/requirements.txt": "adversarial-robustness-toolbox==1.17\n"}),
    "REPO-223": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"g.tf": 'resource "aws_macie2_account" "m" {}\n'}),
    "REPO-224": (_AI, {"docs/human-approval.md": "A person approves refunds.\n"}),
    "REPO-225": (_AI, {"/requirements.txt": "pydantic==2.9\n"}),
    "REPO-226": (_AI, {"docs/tool-registry.md": "Approved tools and owners.\n"}),
    "REPO-227": ({**_AI, "m.tf": 'resource "aws_bedrockagentcore_memory" "m" {\n  name = "m"\n}\n'}, {"app/mem.py": "client.apply_guardrail(source='INPUT')\n"}),
    "REPO-228": (_AI, {"docs/hallucination.md": "Grounding threshold 0.8.\n"}),
    "REPO-229": (_AI, {"docs/agent-changelog.md": "2026-11: new refund tool.\n"}),
    "REPO-230": (_AI, {"docs/config-drift.md": "Drift detection runs nightly.\n"}),
    "REPO-231": (_AI, {"docs/feedback-loop.md": "Weekly review of failed tasks.\n"}),
    "REPO-232": ({"a.tf": _AI["a.tf"].replace("}\n", '  agent_collaboration = "SUPERVISOR"\n}\n')}, {"docs/agent-handoff.md": "What each agent passes on.\n"}),
    "REPO-233": (_AI, {"/tests/test_tool_timeout.py": "def test_x():\n    pass\n"}),
    "REPO-234": (_AI, {"docs/user-journey.md": "Where the assistant advises.\n"}),
    "REPO-235": (_AI, {"docs/accessibility.md": "WCAG 2.2 AA.\n"}),
    "REPO-236": (_AI, {"docs/risk-register.md": "Harms and mitigations.\n"}),
    "REPO-237": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/requirements.txt": "detoxify==0.5\n"}),
    "REPO-238": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/requirements.txt": "ragas==0.2\n"}),
    "REPO-239": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/requirements.txt": "textattack==0.3\n"}),
    "REPO-240": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/requirements.txt": "presidio-analyzer==2.2\n"}),
    "REPO-241": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/evals/instruction_following.yaml": "cases: []\n"}),
    "REPO-242": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/requirements.txt": "shap==0.46\n"}),
    "REPO-243": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: garak --model_type rest\n"}),
    "REPO-244": ({**_AI, "/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}, {"/evals/citations.yaml": "cases: []\n"}),
    "REPO-245": (_AI, {"docs/privacy-notice.md": "Users consent to monitoring.\n"}),
    "REPO-246": (_AI, {"/requirements.txt": "evidently==0.4\n"}),
    "REPO-247": (_AI, {"d.tf": 'resource "aws_cloudwatch_dashboard" "d" {\n  dashboard_name = "d"\n}\n'}),
    "REPO-248": (_AI, {"docs/transparency.md": "What we tell users.\n"}),
    "REPO-249": (_AI, {"docs/user-guide.md": "How to read the outputs.\n"}),
    "REPO-250": ({**_AI, "app.py": _CALL % ""}, {"app.py": "from pydantic import BaseModel\n" + _CALL % ""}),
    "REPO-251": (_AI, {"t.tf": 'resource "aws_cloudtrail" "t" {\n  name = "t"\n}\n'}),
    "REPO-252": ({**_AI, "a.py": "m = 'anthropic.claude-3-haiku-20240307-v1:0'\n", "b.py": "m = 'amazon.titan-text-lite-v1'\n"},
                 {"a.py": "import os\nm = os.environ['MODEL']\n", "b.py": "import os\nm = os.environ['MODEL']\n"}),
    "REPO-253": ({**_AI, "app.py": _CALL % ""}, {"app.py": "from botocore.config import Config\ncfg = Config(retries={'mode': 'adaptive'})\n" + _CALL % ""}),
    "REPO-254": (_AI, {"app.py": "from aws_lambda_powertools import Metrics\n"}),
    "REPO-255": (_AI, {"app.py": "def save_feedback(rating):\n    pass\n"}),
    "REPO-256": ({**_AI, "app.py": _CALL % ""}, {"app.py": "import tiktoken\n" + _CALL % ""}),
    "REPO-257": ({**_AI, "app.py": _CALL % ""}, {"app.py": _CALL % 'system=[{"text": "s"}, {"cachePoint": {"type": "default"}}], '}),
    "REPO-258": ({**_AI, "app.py": _CALL % 'guardrailConfig={"guardrailIdentifier": "g"}, '},
                 {"app.py": _CALL % 'guardrailConfig={"guardrailIdentifier": "g"}, ' + "# guardContent\n"}),
    "REPO-259": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"/requirements.txt": "presidio-analyzer==2.2\n"}),
    "REPO-260": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"/requirements.txt": "mlflow==2.17\n"}),
    "REPO-261": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"l.tf": 'resource "aws_s3_bucket_lifecycle_configuration" "l" {\n  bucket = "b"\n}\n'}),
    "REPO-262": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"docs/human-review.md": "A2I reviews low-confidence cases.\n"}),
    "REPO-263": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"/requirements.txt": "shap==0.46\n"}),
    "REPO-264": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"/requirements.txt": "evidently==0.4\n"}),
    "REPO-265": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"docs/retraining.md": "Retrain weekly.\n"}),
    "REPO-266": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"docs/feature-review.md": "Monthly review.\n"}),
    "REPO-267": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"docs/environment-parity.md": "Same IaC everywhere.\n"}),
    "REPO-268": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"docs/training-design.md": "ml.g5.xlarge because...\n"}),
    "REPO-269": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"/.github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n"}),
    "REPO-270": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"}, {"local.py": "from sagemaker.local import LocalSession\n"}),
    "REPO-271": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"}, {"automl.py": "from sagemaker import AutoML\n"}),
    "REPO-272": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "e.tf": 'resource "aws_instance" "t" {\n  instance_type = "p4d.24xlarge"\n}\n'},
                 {"e.tf": 'resource "aws_instance" "t" {\n  instance_type = "m5.large"\n}\n'}),
    "REPO-273": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"}, {"train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py', distribution={'torch_distributed': {'enabled': True}})\n"}),
    "REPO-274": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"}, {"train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py', checkpoint_s3_uri='s3://b/c')\n"}),
    "REPO-275": ({**{"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, "train.py": "from sagemaker.pytorch import PyTorch\nPyTorch(entry_point='t.py')\n"}, {"tune.py": "from sagemaker.tuner import HyperparameterTuner\n"}),
    "REPO-276": ({"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}, {"b.tf": 'resource "aws_budgets_budget" "b" {\n  budget_type = "COST"\n}\n'}),
    "REPO-210": (_AI, {"/.github/workflows/redteam.yml": "on:\n  schedule:\n    - cron: '0 3 * * 1'\njobs:\n  r:\n    steps:\n      - run: garak --model_type rest\n"}),
    "REPO-193": ({"/ios/Runner/Info.plist": "<plist/>"},
                 {"d.tf": 'resource "aws_devicefarm_project" "p" {\n  name = "p"\n}\n'}),
}


# The one-rule-per-question lens rules (rules/repo_practices.py, LENS_PRACTICE_TABLE): each
# fires on a workload of its gate and is answered by a note named for its first topic.
_SAGEMAKER = {"m.tf": 'resource "aws_sagemaker_model" "m" {\n  name = "m"\n}\n'}
_SUPERVISOR = {"a.tf": _AI["a.tf"].replace("}\n", '  agent_collaboration = "SUPERVISOR"\n}\n')}
# The managed-hosting rule (REPO-311) applies only to self-hosted model serving.
_SELF_HOSTED = {**_AI, "/requirements.txt": "vllm==0.6\n"}
_GATE_FIXTURE = {"ai": _AI, "agent": _AI, "multi": _SUPERVISOR, "sagemaker": _SAGEMAKER}
for _rid, _name, _q, _gate, _title, _terms, *_rest in LENS_PRACTICE_TABLE:
    _lacking = _SELF_HOSTED if _rid == "REPO-311" else _GATE_FIXTURE[_gate]
    CASES[_rid] = (_lacking, {f"docs/{_terms[0].replace(' ', '-')}.md": "Notes.\n"})

def _ids(root: Path, files: dict[str, str]) -> set[str]:
    for rel, text in files.items():
        path = root / (rel[1:] if rel.startswith("/") else f"prod/{rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False, rules_org=True)
    return {f.id for f in findings}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_without_the_control_and_not_with_it(tmp_path: Path, rule_id: str) -> None:
    lacking, answer = CASES[rule_id]
    assert rule_id in _ids(tmp_path / "lacking", lacking)
    assert rule_id not in _ids(tmp_path / "answered", {**lacking, **answer})


def test_every_rule_of_the_batch_has_a_case() -> None:
    from aws_arch_agent.rules.registry import ALL_RULES

    batch = {r.id for r in ALL_RULES if r.id.startswith("REPO-") and int(r.id[5:]) >= 161}
    assert batch == set(CASES)
