"""V2 LangGraph multi-agent pipeline: collect, synth, six pillars, merge, report."""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Literal, TypedDict, List

from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.agent.v1 import detect_language, _languages_to_scan, _filter_rules
from aws_arch_agent.tools.files import iter_files
from aws_arch_agent.tools.llm import LLMClient
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.tools.cdk_synth import (
    run_cdk_synth,
    summarize_templates,
    list_templates_from_path,
    summarize_templates_from_paths,
)
from aws_arch_agent.rules.cf_template import run_cf_rules, run_cf_rules_from_paths

from langgraph.graph import StateGraph, END

logger = logging.getLogger(__name__)

LLMMode = Literal["full", "compact"]
_pillar_cache: dict[str, str] = {}


class State(TypedDict, total=False):
    repo_path: str
    max_files: int
    ctx: RepoContext
    raw_findings: List[Finding]
    rule_warnings: List[str]
    use_llm: bool
    llm_mode: str
    rules_include: List[str] | None
    rules_exclude: List[str] | None
    severity_threshold: str
    templates_path: str
    skip_synth: bool
    rag_path: str
    rag_use_embeddings: bool
    rag_embedding_provider: str
    rag_embedding_model: str
    synth_ok: bool
    synth_stdout: str
    synth_stderr: str
    synth_summary: str
    security_notes: str
    cost_notes: str
    reliability_notes: str
    observability_notes: str
    performance_efficiency_notes: str
    sustainability_notes: str
    merged_notes: str
    final_report: str


# Map pillar node names to finding categories (static rules use "Operational Excellence", not "Observability")
PILLAR_CATEGORIES: dict[str, list[str]] = {
    "Observability": ["Observability", "Operational Excellence"],
    "Cost": ["Cost", "Cost Optimization"],
}


def _findings_hash(findings: List[Finding], synth_summary: str, role: str) -> str:
    payload = {
        "role": role,
        "synth": synth_summary[:2000],
        "findings": [(f.id, f.file, f.line, f.evidence) for f in findings[:50]],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _load_rag_block(state: State, query: str | None = None) -> str:
    rag_path = state.get("rag_path")
    if not rag_path:
        return ""
    try:
        from aws_arch_agent.rag import get_rag

        use_emb = state.get("rag_use_embeddings", False)
        provider = state.get("rag_embedding_provider") or None
        model = state.get("rag_embedding_model") or None
        rag = get_rag(
            Path(rag_path),
            use_embeddings=use_emb,
            embedding_provider=provider,
            embedding_model=model,
        )
        q = query or "operational excellence security reliability performance cost sustainability"
        return "\n\n## Reference (RAG)\n" + rag.retrieve(q, k=3)
    except Exception as e:
        logger.warning("RAG load or retrieve failed for %s: %s", rag_path, e)
        return ""


def _summarize_role(
    role: str,
    findings: List[Finding],
    synth_summary: str,
    llm: LLMClient,
    use_llm: bool = True,
    rag_block: str = "",
) -> str:
    categories = PILLAR_CATEGORIES.get(role, [role])
    rel = [f for f in findings if f.category.lower() in [c.lower() for c in categories]]
    if not rel:
        return f"## {role}\n\nNo findings in this pillar.\n"
    snippet = "\n".join([f"- [{x.id}] {x.title}: {x.recommendation}" for x in rel[:12]])
    if not use_llm:
        return f"## {role}\n(skipped LLM)\n\n{snippet}\n\nSynth summary: {synth_summary[:500]}"
    cache_key = _findings_hash(rel, synth_summary, role)
    if cache_key in _pillar_cache:
        return _pillar_cache[cache_key]
    prompt = f"""Role: {role} reviewer

You have:
A) Static analysis findings (CDK code heuristics)
B) A brief CloudFormation synth summary (may be missing if synth failed)

Tasks:
1) Top 3 risks
2) 3 concrete remediation steps (CDK-oriented)
3) 1-2 questions to validate assumptions

Static findings:
{snippet}

CloudFormation synth summary:
{synth_summary}
{rag_block}
"""
    result = llm.polish(prompt, system=f"You are a senior AWS {role} reviewer. Return concise Markdown only.")
    _pillar_cache[cache_key] = result
    return result


def node_collect(state: State) -> State:
    repo_path = Path(state["repo_path"])
    max_files = state.get("max_files") or 400
    files = iter_files(repo_path, max_files=max_files)
    ctx = RepoContext(
        repo_path=str(repo_path),
        language=detect_language(repo_path),
        files_scanned=len(files),
        key_files=[p.name for p in files if p.name in {"cdk.json", "package.json", "requirements.txt"}],
        notes={"top_level": [p.name for p in repo_path.iterdir() if p.is_dir()]},
    )

    rules = _filter_rules(
        ALL_RULES,
        state.get("rules_include"),
        state.get("rules_exclude"),
    )
    language = ctx.language
    findings, warnings = run_all_rules(repo_path, rules, _languages_to_scan(language))
    findings = filter_by_severity(findings, state.get("severity_threshold"))

    return {"ctx": ctx, "raw_findings": findings, "rule_warnings": warnings}


def node_synth(state: State) -> State:
    repo_path = Path(state["repo_path"])
    ctx = state.get("ctx")
    templates_path = state.get("templates_path") or ""
    skip_synth = state.get("skip_synth") or False

    if templates_path:
        # Use provided templates path (no CDK synth); run CF rules on discovered templates
        tpath = Path(templates_path).expanduser().resolve()
        template_paths = list_templates_from_path(tpath)
        if not template_paths:
            synth_summary = "No template files found at the given path."
            out_findings = list(state.get("raw_findings", []))
        else:
            synth_summary = summarize_templates_from_paths(template_paths)
            out_findings = list(state.get("raw_findings", []))
            try:
                cf_findings = run_cf_rules_from_paths(template_paths)
                out_findings.extend(cf_findings)
            except Exception as e:
                logger.warning("CF template rules failed: %s", e)
        return {
            "synth_ok": True,
            "synth_stdout": "",
            "synth_stderr": "",
            "synth_summary": synth_summary,
            "raw_findings": out_findings,
        }

    if skip_synth:
        synth_summary = "Synth skipped (--no-synth). Static analysis only."
        logger.info("Synth skipped; continuing with static analysis only")
        return {
            "synth_ok": False,
            "synth_stdout": "",
            "synth_stderr": "",
            "synth_summary": synth_summary,
        }

    # Default: run cdk synth
    language = ctx.language if ctx else "typescript"
    try:
        rc, out, err = run_cdk_synth(repo_path, language=language)
        ok = (rc == 0)
    except Exception as e:
        logger.warning("CDK synth failed: %s", e)
        ok, out, err = False, "", f"{e}"

    if ok:
        cdk_out = repo_path / "cdk.out"
        synth_summary = summarize_templates(cdk_out)
        out_findings = list(state.get("raw_findings", []))
        try:
            cf_findings = run_cf_rules(cdk_out)
            out_findings.extend(cf_findings)
        except Exception as e:
            logger.warning("CF template rules failed: %s", e)
        return {
            "synth_ok": True,
            "synth_stdout": out[-4000:],
            "synth_stderr": err[-4000:],
            "synth_summary": synth_summary,
            "raw_findings": out_findings,
        }
    else:
        synth_summary = "CDK synth did not run successfully. (This is OK for MVP.)"
        logger.info("CDK synth failed or skipped; continuing with static analysis only")

    return {
        "synth_ok": ok,
        "synth_stdout": out[-4000:],
        "synth_stderr": err[-4000:],
        "synth_summary": synth_summary,
    }


def _pillar_node(role: str, state_key: str):
    def _node(state: State) -> State:
        use_llm = state.get("use_llm", True)
        llm_mode = state.get("llm_mode", "full")
        findings = state.get("raw_findings", [])
        synth_summary = state.get("synth_summary", "")
        rag_block = _load_rag_block(state, query=f"{role} AWS Well-Architected best practices")
        if llm_mode == "compact":
            categories = PILLAR_CATEGORIES.get(role, [role])
            rel = [f for f in findings if f.category.lower() in [c.lower() for c in categories]]
            snippet = "\n".join([f"- [{x.id}] {x.title}" for x in rel[:8]]) or "No findings."
            notes = f"## {role}\n\n{snippet}\n{rag_block}\n"
        else:
            llm = LLMClient()
            notes = _summarize_role(
                role, findings, synth_summary, llm, use_llm=use_llm, rag_block=rag_block
            )
        out: State = {}
        out[state_key] = notes  # type: ignore[literal-required]
        return out

    return _node


node_security = _pillar_node("Security", "security_notes")
node_cost = _pillar_node("Cost", "cost_notes")
node_reliability = _pillar_node("Reliability", "reliability_notes")
node_observability = _pillar_node("Observability", "observability_notes")
node_performance_efficiency = _pillar_node("Performance Efficiency", "performance_efficiency_notes")
node_sustainability = _pillar_node("Sustainability", "sustainability_notes")


def node_merge(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm_mode = state.get("llm_mode", "full")
    rag_block = _load_rag_block(state)
    findings = state.get("raw_findings", [])
    synth_summary = state.get("synth_summary", "")

    if llm_mode == "compact" and use_llm:
        snippet = "\n".join([f"- [{f.id}] {f.title} ({f.severity})" for f in findings[:30]])
        prompt = f"""Produce a single architecture review with headings for all 6 AWS Well-Architected pillars.
Be specific, avoid repetition, and keep it to ~350-550 words.

CloudFormation synthesis:
{synth_summary}

Findings:
{snippet}
{rag_block}
"""
        llm = LLMClient()
        merged = llm.polish(prompt, system="You are the lead reviewer. Return Markdown only.")
        return {"merged_notes": merged}

    prompt = f"""Merge these into a single coherent review section with headings (AWS Well-Architected 6 pillars).
Be specific, avoid repetition, and keep it to ~350-550 words.

## CloudFormation synthesis
{synth_summary}

## 1. Operational Excellence (Observability)
{state.get("observability_notes","")}

## 2. Security
{state.get("security_notes","")}

## 3. Reliability
{state.get("reliability_notes","")}

## 4. Performance Efficiency
{state.get("performance_efficiency_notes","")}

## 5. Cost Optimization
{state.get("cost_notes","")}

## 6. Sustainability
{state.get("sustainability_notes","")}
{rag_block}
"""
    if not use_llm:
        merged = prompt
    else:
        llm = LLMClient()
        merged = llm.polish(prompt, system="You are the lead reviewer. Return Markdown only.")
    return {"merged_notes": merged}


def node_report(state: State) -> State:
    ctx = state["ctx"]
    findings = state.get("raw_findings", [])
    warnings = state.get("rule_warnings") or []
    base_report = render_markdown(ctx, findings, warnings=warnings)
    synth_block = state.get("synth_summary", "")
    if state.get("templates_path"):
        synth_status = "Templates: provided (no synth)"
    elif state.get("skip_synth"):
        synth_status = "CDK synth: skipped"
    else:
        synth_status = "success" if state.get("synth_ok") else "failed/skip"
        synth_status = f"CDK synth: {synth_status}"
    final = f"""# AWS Architecture Review Report (V2 Multi-Agent)

**{synth_status}**

{state.get("merged_notes","")}

---

{synth_block}

---

{base_report}
"""
    return {"final_report": final}


def build_graph():
    """Build and compile the LangGraph StateGraph (collect -> synth -> 6 pillars -> merge -> report)."""
    g = StateGraph(State)
    g.add_node("collect", node_collect)
    g.add_node("synth", node_synth)
    g.add_node("security", node_security)
    g.add_node("cost", node_cost)
    g.add_node("reliability", node_reliability)
    g.add_node("observability", node_observability)
    g.add_node("performance_efficiency", node_performance_efficiency)
    g.add_node("sustainability", node_sustainability)
    g.add_node("merge", node_merge)
    g.add_node("report", node_report)

    g.set_entry_point("collect")
    g.add_edge("collect", "synth")

    g.add_edge("synth", "security")
    g.add_edge("synth", "cost")
    g.add_edge("synth", "reliability")
    g.add_edge("synth", "observability")
    g.add_edge("synth", "performance_efficiency")
    g.add_edge("synth", "sustainability")

    g.add_edge("security", "merge")
    g.add_edge("cost", "merge")
    g.add_edge("reliability", "merge")
    g.add_edge("observability", "merge")
    g.add_edge("performance_efficiency", "merge")
    g.add_edge("sustainability", "merge")

    g.add_edge("merge", "report")
    g.add_edge("report", END)
    return g.compile()


def analyze_v2(
    repo_path: Path,
    max_files: int = 400,
    use_llm: bool = True,
    rules_include: List[str] | None = None,
    rules_exclude: List[str] | None = None,
    severity_threshold: str | None = None,
    templates_path: str | None = None,
    skip_synth: bool = False,
    rag_path: str | None = None,
    rag_use_embeddings: bool = False,
    rag_embedding_provider: str | None = None,
    rag_embedding_model: str | None = None,
    llm_mode: LLMMode = "full",
) -> tuple[str, RepoContext, List[Finding], List[str]]:
    """Run V2 graph; return (final_report_md, ctx, findings, warnings)."""
    graph = build_graph()
    initial: State = {
        "repo_path": str(repo_path),
        "max_files": max_files,
        "use_llm": use_llm,
        "llm_mode": llm_mode,
        "rules_include": rules_include if rules_include else None,
        "rules_exclude": rules_exclude if rules_exclude else None,
        "severity_threshold": severity_threshold or "",
        "templates_path": templates_path or "",
        "skip_synth": skip_synth,
        "rag_path": rag_path or "",
        "rag_use_embeddings": rag_use_embeddings,
        "rag_embedding_provider": rag_embedding_provider or "",
        "rag_embedding_model": rag_embedding_model or "",
    }
    out = graph.invoke(initial)
    report = out.get("final_report") or "No report produced."
    ctx = out.get("ctx")
    findings = out.get("raw_findings") or []
    warnings = out.get("rule_warnings") or []
    if ctx is None:
        ctx = RepoContext(repo_path=str(repo_path), language="unknown")
    return report, ctx, findings, warnings
