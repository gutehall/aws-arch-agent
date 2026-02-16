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
    
    def should_skip_dir(dir_path: Path) -> bool:
        """Check if directory should be skipped based on name."""
        dir_name = dir_path.name
        return dir_name in DEFAULT_EXCLUDES or dir_name.startswith(".")
    
    def walk_with_excludes(path: Path) -> None:
        """Walk directory tree with exclusions."""
        if len(files) >= max_files:
            return
        
        try:
            for p in path.iterdir():
                if len(files) >= max_files:
                    return
                
                # Skip excluded directories early
                if p.is_dir():
                    if not should_skip_dir(p):
                        walk_with_excludes(p)
                    continue
                
                # Check file extension
                if p.suffix.lower() in {".ts", ".js", ".py", ".json", ".yaml", ".yml", ".md"}:
                    files.append(p)
        except (PermissionError, OSError):
            # Skip directories we can't read
            pass
    
    walk_with_excludes(repo_path)
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
