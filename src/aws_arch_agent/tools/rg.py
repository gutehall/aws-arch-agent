"""Ripgrep wrapper for pattern search in the repo."""
from __future__ import annotations
import re
import subprocess
from pathlib import Path
from typing import List, Tuple


def _fallback_search(
    repo_path: Path, pattern: str, glob: str | None, max_hits: int
) -> List[Tuple[str, int, str]]:
    """Pure-Python fallback when ripgrep is missing or returns no match (e.g. regex dialect)."""
    try:
        regex = re.compile(pattern)
    except re.error:
        return []
    hits: List[Tuple[str, int, str]] = []
    if glob == "**/*.ts":
        files = list(repo_path.rglob("*.ts"))
    elif glob == "**/*.py":
        files = list(repo_path.rglob("*.py"))
    else:
        files = list(repo_path.rglob("*.ts")) + list(repo_path.rglob("*.py"))
    for fp in sorted(files):
        if fp.name.startswith(".") or ".git" in fp.parts:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = fp.relative_to(repo_path)
        except ValueError:
            continue
        rel_str = str(rel).replace("\\", "/")
        for i, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                hits.append((rel_str, i, line.strip()))
                if len(hits) >= max_hits:
                    return hits
    return hits


def rg(repo_path: Path, pattern: str, glob: str | None = None, max_hits: int = 50) -> List[Tuple[str, int, str]]:
    """Run ripgrep in repo_path; return list of (file, line_number, line_text) up to max_hits."""
    cmd = ["rg", "--line-number", "--no-heading", "--hidden", "--glob", "!.git/*"]
    if glob:
        cmd += ["--glob", glob]
    cmd += [pattern, "."]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=str(repo_path))
    except FileNotFoundError:
        return _fallback_search(repo_path, pattern, glob, max_hits)
    hits: List[Tuple[str, int, str]] = []
    for line in p.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        f, ln, txt = parts
        try:
            lni = int(ln)
        except ValueError:
            continue
        hits.append((f, lni, txt.strip()))
        if len(hits) >= max_hits:
            break
    if not hits:
        return _fallback_search(repo_path, pattern, glob, max_hits)
    return hits
