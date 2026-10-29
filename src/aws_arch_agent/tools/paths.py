"""Path normalization helpers for repo-relative file paths."""
from __future__ import annotations

from pathlib import Path


def normalize_rel_path(path: str | None) -> str | None:
    """Normalize repo-relative paths for stable matching (strip ./ prefix)."""
    if path is None:
        return None
    return path.replace("\\", "/").removeprefix("./")


def to_repo_relative(file_path: str, repo_path: Path) -> str:
    """Return a repo-relative posix path. Paths outside the repo stay absolute."""
    path = Path(file_path)
    if not path.is_absolute():
        return path.as_posix().removeprefix("./")
    try:
        return path.resolve().relative_to(repo_path.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()
