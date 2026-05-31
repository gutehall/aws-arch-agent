"""Path normalization helpers for repo-relative file paths."""
from __future__ import annotations


def normalize_rel_path(path: str | None) -> str | None:
    """Normalize repo-relative paths for stable matching (strip ./ prefix)."""
    if path is None:
        return None
    return path.replace("\\", "/").removeprefix("./")
