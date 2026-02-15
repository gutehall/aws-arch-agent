"""Ripgrep wrapper for pattern search in the repo."""
from __future__ import annotations
from pathlib import Path
from typing import List, Tuple
import subprocess


def rg(repo_path: Path, pattern: str, glob: str | None = None, max_hits: int = 50) -> List[Tuple[str, int, str]]:
    """Run ripgrep in repo_path; return list of (file, line_number, line_text) up to max_hits."""
    cmd = ["rg", "--line-number", "--no-heading", "--hidden", "--glob", "!.git/*"]
    if glob:
        cmd += ["--glob", glob]
    cmd += [pattern, str(repo_path)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        # rg missing
        return []
    hits: List[Tuple[str, int, str]] = []
    for line in p.stdout.splitlines():
        # format: path:line:match
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
    return hits
