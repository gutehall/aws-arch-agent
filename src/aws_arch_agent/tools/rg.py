"""Ripgrep wrapper for pattern search in the repo."""
from __future__ import annotations
import re
import subprocess
from pathlib import Path
from typing import List, Tuple

from aws_arch_agent.rules.base import DEFAULT_EXCLUDE_GLOBS
from aws_arch_agent.tools.paths import normalize_rel_path

RG_TIMEOUT_S = 30
Hit = tuple[str, int, str]


class RipgrepTimeout(RuntimeError):
    """Ripgrep did not finish. Callers record this as a rule warning."""


def _glob_match(path: str, pattern: str) -> bool:
    """Match a repo-relative path. `**` may cross directories. `*` does not."""
    path = path.strip("/")
    pattern = pattern.strip("/")
    regex: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            regex.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            regex.append(".*")
            i += 2
        elif pattern[i] == "*":
            regex.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            regex.append("[^/]")
            i += 1
        else:
            regex.append(re.escape(pattern[i]))
            i += 1
    return re.fullmatch("".join(regex), path) is not None


def _path_excluded(rel: str, exclude_globs: tuple[str, ...] | list[str]) -> bool:
    """Return True if rel path matches any exclude glob."""
    path = normalize_rel_path(rel) or rel
    return any(_glob_match(path, pattern) for pattern in exclude_globs)


def _fallback_search(
    repo_path: Path,
    pattern: str,
    glob: str | None,
    max_hits: int,
    exclude_globs: tuple[str, ...] | list[str],
) -> List[Tuple[str, int, str]]:
    """Pure-Python fallback when ripgrep is missing or returns no match (e.g. regex dialect)."""
    try:
        regex = re.compile(pattern)
    except re.error:
        return []
    
    # Import iter_files to respect exclusions
    from aws_arch_agent.tools.files import iter_files
    
    hits: List[Tuple[str, int, str]] = []
    
    # Get files respecting exclusions (node_modules, .git, etc.)
    all_files = iter_files(repo_path, max_files=1000)
    
    # Filter by extension based on glob
    if glob == "**/*.ts":
        files = [f for f in all_files if f.suffix in {".ts", ".tsx"}]
    elif glob == "**/*.py":
        files = [f for f in all_files if f.suffix == ".py"]
    else:
        files = [f for f in all_files if f.suffix in {".ts", ".tsx", ".py"}]
    
    for fp in sorted(files):
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = fp.relative_to(repo_path)
        except ValueError:
            continue
        rel_str = normalize_rel_path(str(rel).replace("\\", "/")) or ""
        if _path_excluded(rel_str, exclude_globs):
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                hits.append((rel_str, i, line.strip()))
                if len(hits) >= max_hits:
                    return _stable_hits(hits, max_hits)
    return _stable_hits(hits, max_hits)


def _stable_hits(hits: list[Hit], max_hits: int) -> list[Hit]:
    """Same tree, same first hit. Order is path, then line."""
    return sorted(hits, key=lambda hit: (hit[0], hit[1]))[:max_hits]


def rg(
    repo_path: Path,
    pattern: str,
    glob: str | None = None,
    max_hits: int = 50,
    exclude_globs: tuple[str, ...] | list[str] | None = None,
) -> List[Tuple[str, int, str]]:
    """Run ripgrep in repo_path; return list of (file, line_number, line_text) up to max_hits."""
    effective_excludes = DEFAULT_EXCLUDE_GLOBS if exclude_globs is None else exclude_globs
    cmd = ["rg", "--line-number", "--no-heading", "--hidden", "--glob", "!.git/*"]
    if glob:
        cmd += ["--glob", glob]
    for ex in effective_excludes:
        cmd += ["--glob", f"!{ex}"]
    cmd += [pattern, "."]
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(repo_path),
            timeout=RG_TIMEOUT_S,
        )
    except FileNotFoundError:
        return _fallback_search(repo_path, pattern, glob, max_hits, effective_excludes)
    except subprocess.TimeoutExpired as exc:
        raise RipgrepTimeout(f"ripgrep timed out after {RG_TIMEOUT_S}s") from exc
    hits: List[Tuple[str, int, str]] = []
    for line in p.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        f, ln, txt = parts
        rel = normalize_rel_path(f) or f
        if _path_excluded(rel, effective_excludes):
            continue
        try:
            lni = int(ln)
        except ValueError:
            continue
        hits.append((rel, lni, txt.strip()))
    if not hits:
        return _fallback_search(repo_path, pattern, glob, max_hits, effective_excludes)
    return _stable_hits(hits, max_hits)
