"""Tests for V2 LangGraph merge behavior and options."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from aws_arch_agent.agent import v2_graph
from aws_arch_agent.agent.v2_graph import (
    analyze_v2,
    build_graph,
    node_merge,
    node_security,
    node_cost,
    node_reliability,
    node_observability,
    node_performance_efficiency,
    node_sustainability,
)
from aws_arch_agent.cli import app
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC
from aws_arch_agent.tools.llm import LLMResult

# Repo-level rules add Operational Excellence (OPS 5) and Reliability (REL 12: no fault
# injection, no load test) pillars to any bare repo; so do no version control and no quality gate.
REPO_IDS = ["REPO-001", "REPO-002", "REPO-003", "REPO-016", "REPO-017", "REPO-113", "REPO-115"]


def _ok(text: str) -> LLMResult:
    return LLMResult(text, "ok", "ollama", "llama3:8b")


def test_v2_max_files_respected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    for i in range(5):
        (tmp_path / "lib" / f"stack{i}.ts").write_text(f"// file {i}", encoding="utf-8")
    report, ctx, findings, warnings = analyze_v2(tmp_path, max_files=2, use_llm=False, skip_synth=True)
    assert ctx.files_scanned <= 2
    assert isinstance(warnings, list)


def test_v2_compact_llm_mode(tmp_path: Path) -> None:
    _stack_repo(tmp_path)
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = _ok("[]")
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=True, skip_synth=True, llm_mode="compact")
    assert ctx.llm.status == "ok"
    assert mock_cls.return_value.polish.call_count == 1


def test_v2_compact_with_no_findings_makes_no_call(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        _, ctx, findings, _ = analyze_v2(
            tmp_path, use_llm=True, skip_synth=True, llm_mode="compact",
            rules_include=["SEC-001"],
        )
    assert findings == []
    mock_cls.return_value.polish.assert_not_called()
    assert ctx.llm.line == "LLM: skipped (no LLM call made)"


def test_v2_full_llm_mode_calls_pillars_and_not_merge(tmp_path: Path, monkeypatch) -> None:
    """V2 with use_llm=True completes; a reply never becomes report text."""
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'const policy = { Action: "*", Resource: "arn:aws:s3:::foo" };',
        encoding="utf-8",
    )
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = _ok("[]")
        report, _, findings, _ = analyze_v2(
            tmp_path, use_llm=True, skip_synth=True, llm_mode="full"
        )
    assert "## Security" in report
    assert "(skipped LLM)" not in report
    assert mock_cls.return_value.polish.call_count >= 1
    assert any(f.id == "SEC-001" for f in findings)


def test_v2_rag_included_in_pillar_prompt(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    rag_doc = tmp_path / "waf.md"
    rag_doc.write_text("# Security\nUse least privilege IAM.", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('Action: "*"', encoding="utf-8")
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = _ok("[]")
        analyze_v2(
            tmp_path,
            use_llm=True,
            skip_synth=True,
            llm_mode="full",
            rag_path=str(rag_doc),
        )
    prompts = " ".join(str(c.kwargs.get("prompt", c.args[0] if c.args else "")) for c in mock_cls.return_value.polish.call_args_list)
    assert "Reference (RAG)" in prompts


def test_v2_builds_rag_once(tmp_path: Path) -> None:
    """Collect loads RAG once. Pillars and merge retrieve from that instance."""
    rag_doc = tmp_path / "waf.md"
    rag_doc.write_text("# Security\nUse least privilege IAM.", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    calls: list[Path] = []

    def fake_get_rag(path: Path, **kwargs: object):
        from aws_arch_agent.rag.simple import SimpleRAG

        calls.append(path)
        return SimpleRAG(path=path)

    with patch("aws_arch_agent.rag.get_rag", side_effect=fake_get_rag):
        report, _, _, _ = analyze_v2(
            tmp_path, use_llm=False, skip_synth=True, rag_path=str(rag_doc)
        )
    assert calls == [rag_doc]
    assert "least privilege" in report


def test_merge_node_produces_merged_notes() -> None:
    state = {
        "use_llm": False,
        "llm_mode": "full",
        "synth_summary": "summary",
        "observability_notes": "obs",
        "security_notes": "sec",
        "reliability_notes": "rel",
        "performance_efficiency_notes": "perf",
        "cost_notes": "cost",
        "sustainability_notes": "sus",
        "raw_findings": [],
    }
    out = node_merge(state)
    merged = out["merged_notes"]
    assert "obs" in merged
    assert "sec" in merged
    assert "cost" in merged


def test_langgraph_merge_join_receives_all_pillar_notes() -> None:
    """Merge node includes content from all six pillar sections."""
    state = {
        "use_llm": False,
        "llm_mode": "full",
        "synth_summary": "synth-ok",
        "raw_findings": [],
        "observability_notes": "obs",
        "security_notes": "sec",
        "reliability_notes": "rel",
        "performance_efficiency_notes": "perf",
        "cost_notes": "cost",
        "sustainability_notes": "sus",
    }
    merge_out = node_merge(state)  # type: ignore[arg-type]
    merged = merge_out["merged_notes"]
    for key in ("obs", "sec", "rel", "perf", "cost", "sus"):
        assert key in merged


def test_no_llm_merge_is_the_joined_notes_and_never_a_prompt() -> None:
    state = {"use_llm": False, "synth_summary": "s", "security_notes": "sec", "cost_notes": "cost"}
    assert node_merge(state)["merged_notes"] == v2_graph._joined_notes(state)  # type: ignore[arg-type]


def test_no_llm_merge_keeps_the_rag_block_after_the_notes() -> None:
    class Rag:
        def retrieve(self, _query: str, k: int = 3) -> str:
            return "least privilege"

    state = {"use_llm": False, "security_notes": "sec", "rag": Rag()}
    merged = node_merge(state)["merged_notes"]  # type: ignore[arg-type]
    assert merged == v2_graph._joined_notes(state) + "\n\n## Reference (RAG)\nleast privilege"  # type: ignore[arg-type]


def test_pillar_nodes_run_without_error() -> None:
    """Each pillar node executes and returns its state key."""
    state = {
        "use_llm": False,
        "llm_mode": "full",
        "synth_summary": "",
        "raw_findings": [],
        "repo_path": ".",
    }
    for node, key in [
        (node_security, "security_notes"),
        (node_cost, "cost_notes"),
        (node_reliability, "reliability_notes"),
        (node_observability, "observability_notes"),
        (node_performance_efficiency, "performance_efficiency_notes"),
        (node_sustainability, "sustainability_notes"),
    ]:
        out = node(state)  # type: ignore[arg-type]
        assert key in out
        assert out[key]


def test_build_graph_compiles() -> None:
    graph = build_graph()
    assert graph is not None


def _stack_repo(root: Path) -> None:
    (root / "package.json").write_text("{}", encoding="utf-8")
    (root / "lib").mkdir()
    (root / "lib" / "stack.ts").write_text('Action: "*"', encoding="utf-8")


def _failed(prompt: str) -> LLMResult:
    return LLMResult(prompt, "fallback", "ollama", "llama3:8b", "Ollama request failed")


def test_v2_all_calls_ok_reports_responded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    _stack_repo(tmp_path)
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = _ok("[]")
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=True, skip_synth=True, rules_exclude=REPO_IDS)
    assert mock_cls.return_value.polish.call_count == 1  # the one pillar with findings
    assert ctx.llm.line == "LLM: ollama/llama3:8b responded"


def _security_pillar_fails(prompt: str, system: str = "") -> LLMResult:
    return _failed(prompt) if "SEC-001" in prompt else _ok("[]")


def test_v2_partial_failure_never_claims_responded(tmp_path: Path, monkeypatch) -> None:
    """A pillar fails and the others answer: the run is still a fallback."""
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    _stack_repo(tmp_path)
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.side_effect = _security_pillar_fails
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=True, skip_synth=True)
    assert ctx.llm.status == "fallback"
    assert ctx.llm.line == "LLM: fallback (Ollama request failed)"


def test_v2_failed_pillar_is_asked_again(tmp_path: Path, monkeypatch) -> None:
    """A failure must not stick: only ok outcomes are cached, so only the failed pillar reruns."""
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    _stack_repo(tmp_path)
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.side_effect = _security_pillar_fails
        analyze_v2(tmp_path, use_llm=True, skip_synth=True)
        calls = mock_cls.return_value.polish.call_count
        mock_cls.return_value.polish.side_effect = lambda prompt, system="": _ok("[]")
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=True, skip_synth=True)
    assert mock_cls.return_value.polish.call_count == calls + 1
    assert ctx.llm.status == "ok"


def test_v2_compact_failure_is_reported(tmp_path: Path) -> None:
    _stack_repo(tmp_path)
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = _failed("prompt")
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=True, skip_synth=True, llm_mode="compact")
    assert ctx.llm.status == "fallback"


def test_v2_no_llm_is_skipped_with_no_call(tmp_path: Path) -> None:
    _stack_repo(tmp_path)
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=False, skip_synth=True)
    mock_cls.return_value.polish.assert_not_called()
    assert ctx.llm.line == "LLM: skipped (--no-llm)"


# severity_threshold covers template findings too

MIXED_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: none
  Logs:
    Type: AWS::Logs::LogGroup
"""


NO_HIGH_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Logs:
    Type: AWS::Logs::LogGroup
"""


def _template_repo(root: Path) -> str:
    infra = root / "infra"
    infra.mkdir()
    (infra / "stack.yaml").write_text(MIXED_TEMPLATE, encoding="utf-8")
    return str(infra)


def _fake_synth(repo_path: Path, language: str = "typescript") -> tuple[int, str, str]:
    out = repo_path / "cdk.out"
    out.mkdir(exist_ok=True)
    resources = {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketEncryption": {
            "ServerSideEncryptionConfiguration": [
                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "none"}}
            ]
        }}},
        "Logs": {"Type": "AWS::Logs::LogGroup"},
    }
    (out / "Stack.template.json").write_text(
        json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}), encoding="utf-8"
    )
    return 0, "", ""


def _synth_repo(root: Path, monkeypatch) -> None:
    (root / "package.json").write_text("{}", encoding="utf-8")
    (root / "lib").mkdir()
    (root / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");\n', encoding="utf-8")
    monkeypatch.setattr(v2_graph, "run_cdk_synth", _fake_synth)


@pytest.mark.parametrize("threshold, allowed", [("High", {"High"}), ("Medium", {"High", "Medium"})])
def test_templates_path_applies_the_threshold(tmp_path: Path, threshold: str, allowed: set[str]) -> None:
    templates = _template_repo(tmp_path)
    _r, _c, plain, _w = analyze_v2(tmp_path, use_llm=False, templates_path=templates)
    assert {f.severity for f in plain} - allowed
    report, _c, shown, _w = analyze_v2(
        tmp_path, use_llm=False, templates_path=templates, severity_threshold=threshold
    )
    assert shown and {f.severity for f in shown} <= allowed
    assert shown == [f for f in plain if f.severity in allowed]
    for hidden in {f.id for f in plain} - {f.id for f in shown}:
        assert f"[{hidden}]" not in report


def test_synth_path_applies_the_threshold(tmp_path: Path, monkeypatch) -> None:
    _synth_repo(tmp_path, monkeypatch)
    _r, _c, plain, _w = analyze_v2(tmp_path, use_llm=False)
    assert {f.severity for f in plain if f.file and "cdk.out" in f.file} - {"High"}
    _r, _c, shown, _w = analyze_v2(tmp_path, use_llm=False, severity_threshold="High")
    assert shown and {f.severity for f in shown} == {"High"}
    assert shown == [f for f in plain if f.severity == "High"]


def test_a_static_finding_a_hidden_template_finding_covers_stays_dropped(tmp_path: Path, monkeypatch) -> None:
    """Coverage is decided before the threshold, so hiding the template finding cannot revive it."""
    _synth_repo(tmp_path, monkeypatch)
    covering = next(iter(CF_COVERS_STATIC))
    covered = set(CF_COVERS_STATIC[covering])
    template_finding = Finding(id=covering, title="t", severity="Low", category="Security",
                               file="cdk.out/Stack.template.json", line=1, recommendation="r")
    static_finding = Finding(id=next(iter(covered)), title="t", severity="High", category="Security",
                             file="lib/stack.ts", line=1, recommendation="r")
    monkeypatch.setattr(v2_graph, "run_all_rules", lambda *_a, **_k: ([static_finding], []))
    monkeypatch.setattr(v2_graph, "run_cf_rules", lambda *_a, **_k: [template_finding])
    _r, _c, shown, _w = analyze_v2(tmp_path, use_llm=False, severity_threshold="High")
    assert shown == []


def test_cli_fail_on_ignores_template_findings_the_threshold_hid(tmp_path: Path) -> None:
    infra = tmp_path / "infra"
    infra.mkdir()
    (infra / "stack.yaml").write_text(NO_HIGH_TEMPLATE, encoding="utf-8")
    out = tmp_path / "out.md"
    args = ["--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--templates", str(infra),
            "--out", str(out), "--fail-on", "low"]
    assert CliRunner().invoke(app, args).exit_code == 1
    assert "- Severity: **Medium**" in out.read_text(encoding="utf-8")

    config = tmp_path / "arch-agent.json"
    config.write_text(json.dumps({"severity_threshold": "high"}), encoding="utf-8")
    result = CliRunner().invoke(app, [*args, "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "- Severity: **Medium**" not in out.read_text(encoding="utf-8")


def test_no_llm_compact_merge_does_not_repeat_the_rag_block() -> None:
    class Rag:
        def retrieve(self, _query: str, k: int = 3) -> str:
            return "least privilege"

    state = {"use_llm": False, "llm_mode": "compact", "security_notes": "sec", "rag": Rag()}
    assert node_merge(state)["merged_notes"] == v2_graph._joined_notes(state)  # type: ignore[arg-type]
