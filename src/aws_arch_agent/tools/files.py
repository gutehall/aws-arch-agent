"""File iteration and safe read helpers for scanning a repo."""
from __future__ import annotations
from pathlib import Path
from typing import List

DEFAULT_EXCLUDES = [
    ".git",
    "node_modules",
    "cdk.out",
    "dist",
    "build",
    ".venv",
]


def iter_files(repo_path: Path, max_files: int = 400) -> List[Path]:
    """Yield paths to relevant files (TS, JS, PY, JSON, YAML, MD) under repo_path, up to max_files."""
    files: List[Path] = []
    for p in repo_path.rglob("*"):
        if len(files) >= max_files:
            break
        if p.is_dir():
            continue
        if any(part in DEFAULT_EXCLUDES for part in p.parts):
            continue
        # keep only "likely relevant" files for MVP
        if p.suffix.lower() in {".ts", ".js", ".py", ".json", ".yaml", ".yml", ".md"}:
            files.append(p)
    return files


def read_text_safe(path: Path, max_bytes: int = 200_000) -> str:
    """Read path as UTF-8 text, truncating at max_bytes; return empty string on error."""
    try:
        data = path.read_bytes()
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""
