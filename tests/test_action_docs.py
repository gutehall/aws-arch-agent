"""The composite action declares its inputs safely, and the docs drop the old V2 Terraform text."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / ".github" / "actions" / "aws-arch-agent" / "action.yml"
STALE = re.compile(r"terraform exits 1|For Terraform, use V1")


def _doc_files() -> list[Path]:
    files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    files += sorted(p for p in (ROOT / ".github").rglob("*") if p.suffix in {".yml", ".yaml", ".md"})
    return files


def test_docs_drop_the_stale_v2_terraform_text() -> None:
    hits = [str(p.relative_to(ROOT)) for p in _doc_files() if STALE.search(p.read_text(encoding="utf-8"))]
    assert hits == []


def test_action_declares_the_new_inputs() -> None:
    inputs = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["inputs"]
    for name in ("tf-plan", "live-account", "region", "theme", "group-by", "config", "templates", "job-summary"):
        assert name in inputs, name
    assert inputs["job-summary"]["default"] == "false"
    assert inputs["live-account"]["default"] == "false"


def test_action_run_scripts_never_expand_inputs_directly() -> None:
    steps = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
    scripts = [step["run"] for step in steps if "run" in step]
    assert scripts
    for script in scripts:
        assert "${{" not in script


def test_action_installs_the_account_extra_for_live_account() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert '"${ACTION_ROOT}[v2,account]"' in text
    assert '"${ACTION_ROOT}[v2]"' in text
