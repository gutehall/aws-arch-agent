"""CDK synth runner and CloudFormation template listing/summary helpers."""
from __future__ import annotations
from pathlib import Path
from typing import List
import subprocess
import json
import os


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


def list_cf_templates(cdk_out: Path) -> List[Path]:
    """Return sorted paths to *.template.json files under cdk_out (e.g. cdk.out)."""
    if not cdk_out.exists():
        return []
    return sorted([p for p in cdk_out.rglob("*.template.json") if p.is_file()])


def load_json(path: Path) -> dict:
    """Load JSON file; return empty dict on parse error or missing file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
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
