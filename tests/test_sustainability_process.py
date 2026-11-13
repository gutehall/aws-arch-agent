"""SUS 6: goals (REPO-190), dependency updates
(REPO-191), build environments (REPO-192) and device testing (REPO-193)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-190", ("SUS06-BP01", "SUS06-BP02")),
          ("REPO-191", ("SUS06-BP03",)), ("REPO-192", ("SUS06-BP04",)),
          ("REPO-193", ("SUS06-BP05",)))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / (rel[1:] if rel.startswith("/") else f"prod/{rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_sus6() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_the_note_and_update_rules(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id in ("REPO-190", "REPO-191"):
        (hit,) = _found(findings, rule_id)
        assert hit.question == "SUS 6" and hit.category == "Sustainability"
        assert hit.evidence.startswith("Holds IaC (")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r in ("REPO-190", "REPO-191", "REPO-192", "REPO-193"))


@pytest.mark.parametrize(
    "files",
    [
        {"docs/sustainability.md": "Cut idle capacity by a third.\n"},
        {"docs/goals.md": "## Carbon\n\nUse Graviton.\n"},
    ],
    ids=["named", "heading"],
)
def test_sustainability_note_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-190")


@pytest.mark.parametrize(
    "files",
    [
        {"/.github/dependabot.yml": "version: 2\n"},
        {"/renovate.json": "{}\n"},
        {"/.github/renovate.json5": "{}\n"},
    ],
    ids=["dependabot", "renovate", "renovate-json5"],
)
def test_dependency_updates_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-191")


@pytest.mark.parametrize(
    "text",
    [
        'resource "aws_instance" "gh_runner" {\n  instance_type = "m5.large"\n}\n',
        'resource "aws_codebuild_fleet" "f" {\n  base_capacity = 2\n}\n',
        '{"Resources": {"JenkinsAgent": {"Type": "AWS::EC2::Instance"}}}',
        "new ec2.Instance(this, 'BuildServer', { instanceType, machineImage, vpc });\n",
    ],
    ids=["tf-runner", "tf-fleet", "cfn-jenkins", "cdk-build-server"],
)
def test_always_on_build_fleet_fires(tmp_path: Path, text: str) -> None:
    name = "f.json" if text.startswith("{") else ("f.ts" if "new ec2" in text else "f.tf")
    (hit,) = _found(_scan(tmp_path, {name: text}), "REPO-192")
    assert hit.question == "SUS 6" and hit.file == f"prod/{name}"


@pytest.mark.parametrize(
    "text",
    [
        'resource "aws_instance" "gh_runner" {\n  instance_market_options {\n'
        '    market_type = "spot"\n  }\n}\n',
        'resource "aws_instance" "web" {\n  instance_type = "m5.large"\n}\n',
    ],
    ids=["spot-runner", "not-a-build-host"],
)
def test_spot_or_unrelated_hosts_pass(tmp_path: Path, text: str) -> None:
    assert not _found(_scan(tmp_path, {"f.tf": text}), "REPO-192")


@pytest.mark.parametrize(
    "mobile",
    [{"/android/app/src/main/AndroidManifest.xml": "<manifest/>"}, {"/ios/Runner/Info.plist": "<plist/>"},
     {"/app/App.xcodeproj/project.pbxproj": "x"}, {"/pubspec.yaml": "name: app\nflutter:\n  uses-material-design: true\n"}],
    ids=["android", "ios-plist", "xcode", "flutter"],
)
def test_mobile_app_without_a_device_farm_fires(tmp_path: Path, mobile: dict) -> None:
    (hit,) = _found(_scan(tmp_path, mobile), "REPO-193")
    assert hit.question == "SUS 6" and hit.file


def test_device_farm_passes(tmp_path: Path) -> None:
    files = {"/ios/Runner/Info.plist": "<plist/>",
             "d.tf": 'resource "aws_devicefarm_project" "p" {\n  name = "p"\n}\n'}
    assert not _found(_scan(tmp_path, files), "REPO-193")
    note = {"/ios/Runner/Info.plist": "<plist/>", "docs/testing.md": "We run on AWS Device Farm.\n"}
    assert not _found(_scan(tmp_path / "n", note), "REPO-193")
