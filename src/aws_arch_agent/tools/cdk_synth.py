"""CDK synth runner and CloudFormation template listing/summary helpers."""
from __future__ import annotations
from pathlib import Path
from typing import Any, List, cast
import subprocess
import json
import os

import yaml


def _detect_python_app(repo_path: Path) -> str | None:
    """Detect Python CDK app entry for synth. Returns e.g. 'python app.py' or None."""
    # cdk.json may already define "app"
    cdk_json = repo_path / "cdk.json"
    if cdk_json.exists():
        try:
            data = json.loads(cdk_json.read_text(encoding="utf-8"))
            if data.get("app"):
                return str(data["app"])
        except Exception:
            pass
    # Default Python CDK entry points
    for name in ("app.py", "main.py", "cdk_app.py"):
        if (repo_path / name).exists():
            return f"python {name}"
    return None


def run_cdk_synth(
    repo_path: Path,
    app: str | None = None,
    language: str = "typescript",
    timeout_s: int = 180,
) -> tuple[int, str, str]:
    """Run cdk synth in the repo. For Python CDK, uses --app 'python app.py' when needed."""
    env = os.environ.copy()
    cmd: List[str] = ["npx", "cdk", "synth", "--quiet"]
    if app:
        cmd += ["--app", app]
    elif language == "python":
        python_app = _detect_python_app(repo_path)
        if python_app:
            cmd += ["--app", python_app]
    p = subprocess.run(
        cmd,
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
        env=env,
    )
    return p.returncode, p.stdout, p.stderr


TEMPLATE_EXTENSIONS = (".template.json", ".yaml", ".yml")


def _is_template_extension(path: Path) -> bool:
    """True if path has a CloudFormation template extension."""
    suf = path.suffix.lower()
    if suf == ".json" and path.name.endswith(".template.json"):
        return True
    return suf in (".yaml", ".yml")


def list_cf_templates(cdk_out: Path) -> List[Path]:
    """Return sorted paths to *.template.json files under cdk_out (e.g. cdk.out)."""
    if not cdk_out.exists():
        return []
    return sorted([p for p in cdk_out.rglob("*.template.json") if p.is_file()])


def list_templates_from_path(path: Path, allow_yaml: bool = True) -> List[Path]:
    """Return template files from path (file or directory). Supports .template.json, .yaml, .yml."""
    path = path.resolve()
    if not path.exists():
        return []
    if path.is_file():
        if not _is_template_extension(path):
            return []
        return [path]
    # Directory: collect matching files recursively
    exts = ["*.template.json"]
    if allow_yaml:
        exts.extend(["*.yaml", "*.yml"])
    out: List[Path] = []
    for ext in exts:
        out.extend(path.rglob(ext))
    return sorted(set(p for p in out if p.is_file()))


def load_json(path: Path) -> dict[Any, Any]:
    """Load JSON file; return empty dict on parse error or missing file."""
    try:
        return cast(dict[Any, Any], json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}


def load_template(path: Path) -> dict[Any, Any]:
    """Load CloudFormation template from JSON or YAML; return empty dict on error."""
    if not path.exists() or not path.is_file():
        return {}
    suf = path.suffix.lower()
    if suf == ".json" or path.name.endswith(".template.json"):
        return load_json(path)
    if suf in (".yaml", ".yml"):
        try:
            return cast(dict[Any, Any], yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        except Exception:
            return {}
    return {}


def summarize_templates(cdk_out: Path) -> str:
    """Produce a compact Markdown summary of synthesized CloudFormation templates in cdk_out."""
    templates = list_cf_templates(cdk_out)
    if not templates:
        return "No synthesized templates found in `cdk.out/`."

    lines: list[str] = []
    lines.append("## Synthesized CloudFormation Summary")
    lines.append("")
    for t in templates[:10]:
        doc = load_json(t)
        resources = doc.get("Resources", {}) or {}
        types: dict[str, int] = {}
        for _, r in resources.items():
            rt = r.get("Type", "Unknown")
            types[rt] = types.get(rt, 0) + 1

        lines.append(f"### {t.name}")
        lines.append(f"- Resources: **{len(resources)}**")
        top = sorted(types.items(), key=lambda x: x[1], reverse=True)[:12]
        if top:
            lines.append("- Top types: " + ", ".join([f"`{k}`×{v}" for k, v in top]))
        lines.append("")

    lines.append("> Tip: More template-based rules can be added (e.g. PublicAccessBlock on S3, encryption on RDS).")
    lines.append("")
    return "\n".join(lines)


def summarize_templates_from_paths(template_paths: List[Path]) -> str:
    """Produce a compact Markdown summary from a list of template paths (JSON or YAML)."""
    if not template_paths:
        return "No templates provided."
    lines: list[str] = []
    lines.append("## CloudFormation Template Summary")
    lines.append("")
    for t in template_paths[:10]:
        doc = load_template(t)
        resources = doc.get("Resources", {}) or {}
        types: dict[str, int] = {}
        for _, r in resources.items():
            rt = r.get("Type", "Unknown")
            types[rt] = types.get(rt, 0) + 1
        lines.append(f"### {t.name}")
        lines.append(f"- Resources: **{len(resources)}**")
        top = sorted(types.items(), key=lambda x: x[1], reverse=True)[:12]
        if top:
            lines.append("- Top types: " + ", ".join([f"`{k}`×{v}" for k, v in top]))
        lines.append("")
    return "\n".join(lines)
