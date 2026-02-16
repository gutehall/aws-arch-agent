"""V2 LangGraph multi-agent pipeline: collect, synth, six pillars, merge, report."""
from __future__ import annotations
import logging
from pathlib import Path
from typing import TypedDict, List
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.agent.v1 import detect_language, _languages_to_scan, _filter_rules
from aws_arch_agent.tools.files import iter_files
from aws_arch_agent.tools.llm import LLMClient
from aws_arch_agent.rules.registry import ALL_RULES
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


class State(TypedDict, total=False):
    repo_path: str
    ctx: RepoContext
    raw_findings: List[Finding]
    use_llm: bool
    rules_include: List[str]
    rules_exclude: List[str]
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

def _summarize_role(
    role: str,
    findings: List[Finding],
    synth_summary: str,
    llm: LLMClient,
    use_llm: bool = True,
) -> str:
    categories = PILLAR_CATEGORIES.get(role, [role])
    rel = [f for f in findings if f.category.lower() in [c.lower() for c in categories]]
    if not rel:
        rel = findings
    snippet = "\n".join([f"- [{x.id}] {x.title}: {x.recommendation}" for x in rel[:12]])
    if not use_llm:
        return f"## {role}\n(skipped LLM)\n\n{snippet}\n\nSynth summary: {synth_summary[:500]}"
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
"""
    return llm.polish(prompt, system=f"You are a senior AWS {role} reviewer. Return concise Markdown only.")


def node_collect(state: State) -> State:
    repo_path = Path(state["repo_path"])
    files = iter_files(repo_path, max_files=400)
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
    findings: List[Finding] = []
    language = ctx.language
    for lang in _languages_to_scan(language):
        for rule in rules:
            try:
                findings.extend(rule.run(repo_path, lang))
            except Exception as e:
                logger.debug("Rule %s failed for %s: %s", rule.id, lang, e)
                continue
    sev_threshold = state.get("severity_threshold")
    if sev_threshold:
        sev_order = ("Low", "Medium", "High")
        try:
            idx = sev_order.index(sev_threshold.capitalize())
            findings = [f for f in findings if f.severity in set(sev_order[idx:])]
        except ValueError:
            pass

    return {"ctx": ctx, "raw_findings": findings}


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


def node_security(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm = LLMClient()
    notes = _summarize_role(
        "Security", state.get("raw_findings", []), state.get("synth_summary", ""), llm, use_llm=use_llm
    )
    return {"security_notes": notes}


def node_cost(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm = LLMClient()
    notes = _summarize_role(
        "Cost", state.get("raw_findings", []), state.get("synth_summary", ""), llm, use_llm=use_llm
    )
    return {"cost_notes": notes}


def node_reliability(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm = LLMClient()
    notes = _summarize_role(
        "Reliability", state.get("raw_findings", []), state.get("synth_summary", ""), llm, use_llm=use_llm
    )
    return {"reliability_notes": notes}


def node_observability(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm = LLMClient()
    notes = _summarize_role(
        "Observability",
        state.get("raw_findings", []),
        state.get("synth_summary", ""),
        llm,
        use_llm=use_llm,
    )
    return {"observability_notes": notes}


def node_performance_efficiency(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm = LLMClient()
    notes = _summarize_role(
        "Performance Efficiency",
        state.get("raw_findings", []),
        state.get("synth_summary", ""),
        llm,
        use_llm=use_llm,
    )
    return {"performance_efficiency_notes": notes}


def node_sustainability(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm = LLMClient()
    notes = _summarize_role(
        "Sustainability",
        state.get("raw_findings", []),
        state.get("synth_summary", ""),
        llm,
        use_llm=use_llm,
    )
    return {"sustainability_notes": notes}


def node_merge(state: State) -> State:
    use_llm = state.get("use_llm", True)
    rag_block = ""
    rag_path = state.get("rag_path")
    if rag_path:
        try:
            from pathlib import Path
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
            rag_block = "\n\n## Reference (RAG)\n" + rag.retrieve(
                "operational excellence security reliability performance cost sustainability", k=3
            )
        except Exception as e:
            logger.warning("RAG load or retrieve failed for %s: %s", rag_path, e)
    prompt = f"""Merge these into a single coherent review section with headings (AWS Well-Architected 6 pillars).
Be specific, avoid repetition, and keep it to ~350-550 words.

## CloudFormation synthesis
{state.get("synth_summary","")}

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
    base_report = render_markdown(ctx, findings)
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
) -> tuple[str, RepoContext, List[Finding]]:
    """Run V2 graph; return (final_report_md, ctx, findings)."""
    graph = build_graph()
    initial: State = {
        "repo_path": str(repo_path),
        "use_llm": use_llm,
        "rules_include": rules_include or [],
        "rules_exclude": rules_exclude or [],
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
    if ctx is None:
        from aws_arch_agent.models import RepoContext
        ctx = RepoContext(repo_path=str(repo_path), language="unknown")
    return report, ctx, findings
