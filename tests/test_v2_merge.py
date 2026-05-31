"""Tests for V2 LangGraph merge behavior and options."""
from pathlib import Path
from unittest.mock import patch

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


def test_v2_max_files_respected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    for i in range(5):
        (tmp_path / "lib" / f"stack{i}.ts").write_text(f"// file {i}", encoding="utf-8")
    report, ctx, findings, warnings = analyze_v2(tmp_path, max_files=2, use_llm=False, skip_synth=True)
    assert ctx.files_scanned <= 2
    assert isinstance(warnings, list)


def test_v2_compact_llm_mode(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = "## Compact review"
        report, _, _, _ = analyze_v2(
            tmp_path, use_llm=True, skip_synth=True, llm_mode="compact"
        )
    assert "Compact review" in report
    assert mock_cls.return_value.polish.call_count == 1


def test_v2_full_llm_mode_calls_pillar_and_merge(tmp_path: Path) -> None:
    """V2 with use_llm=True completes; pillar + merge LLM calls are mocked."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'const policy = { Action: "*", Resource: "arn:aws:s3:::foo" };',
        encoding="utf-8",
    )
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = "## LLM section"
        report, _, findings, _ = analyze_v2(
            tmp_path, use_llm=True, skip_synth=True, llm_mode="full"
        )
    assert "## LLM section" in report
    assert mock_cls.return_value.polish.call_count >= 1
    assert any(f.id == "SEC-001" for f in findings)


def test_v2_rag_included_in_pillar_prompt(tmp_path: Path) -> None:
    rag_doc = tmp_path / "waf.md"
    rag_doc.write_text("# Security\nUse least privilege IAM.", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('Action: "*"', encoding="utf-8")
    with patch("aws_arch_agent.agent.v2_graph.LLMClient") as mock_cls:
        mock_cls.return_value.polish.return_value = "review"
        analyze_v2(
            tmp_path,
            use_llm=True,
            skip_synth=True,
            llm_mode="full",
            rag_path=str(rag_doc),
        )
    prompts = " ".join(str(c.kwargs.get("prompt", c.args[0] if c.args else "")) for c in mock_cls.return_value.polish.call_args_list)
    assert "Reference (RAG)" in prompts or "least privilege" in prompts


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
