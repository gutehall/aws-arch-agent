"""Tests for V2 LangGraph merge behavior and options."""
from pathlib import Path
from unittest.mock import patch

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
from aws_arch_agent.tools.llm import LLMResult


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
    assert "Reference (RAG)" in prompts or "least privilege" in prompts


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
        _, ctx, _, _ = analyze_v2(tmp_path, use_llm=True, skip_synth=True)
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
