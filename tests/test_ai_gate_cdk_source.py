"""A CDK source scan (no synth) turns the AI lenses on from Bedrock, SageMaker, or AgentCore code."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.rules import ai_gate, lenses

TS_BEDROCK = """import * as cdk from 'aws-cdk-lib';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
new bedrock.CfnGuardrail(this, 'G', { name: 'g' });
"""
PY_SAGEMAKER = """from aws_cdk import Stack, aws_sagemaker as sagemaker
sagemaker.CfnNotebookInstance(self, "Nb", instance_type="ml.t3.medium", role_arn="r")
"""
TS_AGENTCORE = "import * as agentcore from 'aws-cdk-lib/aws-bedrockagentcore';\n"
TS_PLAIN = "import * as s3 from 'aws-cdk-lib/aws-s3';\nnew s3.Bucket(this, 'B');\n"


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "cdk.json").write_text('{"app": "npx ts-node bin/app.ts"}', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies": {"aws-cdk-lib": "2.0.0"}}', encoding="utf-8")
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _v1(repo: Path, lenses_ai: bool | None = None):
    _md, ctx, findings, _w = analyze_v1(repo, use_llm=False, lenses_ai=lenses_ai)
    return ctx, lenses.answers_for(ctx, findings)


@pytest.mark.parametrize("rel,text", [
    ("lib/stack.ts", TS_BEDROCK),
    ("app/stack.py", PY_SAGEMAKER),
    ("lib/agent.ts", TS_AGENTCORE),
])
def test_ai_constructs_in_cdk_source_turn_the_lenses_on(tmp_path: Path, rel: str, text: str) -> None:
    ctx, answers = _v1(_repo(tmp_path, {rel: text, "lib/other.ts": TS_PLAIN}))
    assert ctx.source == "cdk"
    assert ctx.ai_lenses is True and answers


def test_non_ai_cdk_repo_stays_off(tmp_path: Path) -> None:
    ctx, answers = _v1(_repo(tmp_path, {"lib/stack.ts": TS_PLAIN}))
    assert ctx.ai_lenses is False and answers == []


def test_tests_comments_and_readmes_do_not_count(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {
        "lib/stack.ts": TS_PLAIN + "// TODO: add aws-cdk-lib/aws-bedrock later\n",
        "test/stack.test.ts": TS_BEDROCK,
        "lib/stack.spec.ts": TS_BEDROCK,
        "tests/test_stack.py": PY_SAGEMAKER,
        "README.md": TS_BEDROCK,
    })
    ctx, answers = _v1(repo)
    assert ctx.ai_lenses is False and answers == []


def test_config_overrides_source_detection(tmp_path: Path) -> None:
    ctx, answers = _v1(_repo(tmp_path, {"lib/stack.ts": TS_BEDROCK}), lenses_ai=False)
    assert ctx.ai_lenses is False and answers == []
    ctx, answers = _v1(_repo(tmp_path / "plain", {"lib/stack.ts": TS_PLAIN}), lenses_ai=True)
    assert ctx.ai_lenses is True and answers


def test_v2_without_synth_detects_cdk_source(tmp_path: Path) -> None:
    _report, ctx, _f, _w = analyze_v2(_repo(tmp_path, {"lib/stack.ts": TS_BEDROCK}), use_llm=False, skip_synth=True)
    assert ctx.ai_lenses is True


def test_detection_outside_a_scan_records_nothing(tmp_path: Path) -> None:
    path = tmp_path / "s.ts"
    path.write_text(TS_BEDROCK, encoding="utf-8")
    assert ai_gate.cdk_source_is_ai([path])
    ai_gate.observe_cdk_source([path])  # no use() scope: nothing to record into
    assert ai_gate.active() is False


def test_repo_checked_out_under_a_tests_dir_still_counts(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "tests" / "checkout", {"lib/stack.ts": TS_BEDROCK})
    ctx, answers = _v1(repo)
    assert ctx.ai_lenses is True and answers
