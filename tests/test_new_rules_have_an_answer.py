"""Each repo-level rule of the last Well-Architected batch fires on a repo that lacks the
control and stays quiet once the repo has it.

The generic negative snippets in rule_cases.json hold no IaC, so an IaC-gated rule passes them
without being tested. Here the negative is the same repo with the answering note or resource."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1

_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_HOST = {"i.tf": 'resource "aws_instance" "web" {\n  instance_type = "m5.large"\n}\n'}
_BIG = {"main.tf": "".join(f'resource "aws_lambda_function" "f{i}" {{\n}}\n' for i in range(4))
        + "".join(f'resource "aws_dynamodb_table" "t{i}" {{\n}}\n' for i in range(4))}
_MARKET = {"m.tf": 'data "aws_ami" "m" {\n  owners = ["aws-marketplace"]\n}\n'
                   'resource "aws_ec2_host" "h" {\n  instance_type = "m5.large"\n}\n'}
_ADR = ("# Compute\n\nWe considered Lambda and Fargate. The Well-Architected guidance and the "
        "reference architecture favour Lambda. The cost comparison is $40 against $120. The "
        "tradeoff is cold starts. A benchmark gave measured results, the data we used.\n")
_ALIAS = 'provider "aws" {\n  alias  = "east"\n  region = "us-east-1"\n}\n'
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
    "REPO-193": ({"/ios/Runner/Info.plist": "<plist/>"},
                 {"d.tf": 'resource "aws_devicefarm_project" "p" {\n  name = "p"\n}\n'}),
}


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
