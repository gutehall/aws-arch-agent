"""File iteration and safe read helpers for scanning a repo."""
from __future__ import annotations
import stat
from pathlib import Path
from typing import Any, Dict, List, Tuple

DEFAULT_EXCLUDES = [
    ".git",
    "node_modules",
    "cdk.out",
    "dist",
    "build",
    ".venv",
]


SCANNED_SUFFIXES = {".ts", ".js", ".py", ".json", ".yaml", ".yml", ".md", ".template", ".tf"}


def walk_files(repo_path: Path, max_files: int = 400) -> Tuple[List[Path], bool]:
    """Relevant files under repo_path in name order, up to max_files, and whether the limit cut the walk short.

    Entries are sorted by name at every directory level, so the same repo yields the same
    files on every OS and filesystem.
    """
    files: List[Path] = []
    truncated = False

    def should_skip_dir(dir_path: Path) -> bool:
        dir_name = dir_path.name
        return dir_name in DEFAULT_EXCLUDES or dir_name.startswith(".")

    def walk(path: Path) -> None:
        nonlocal truncated
        try:
            entries = sorted(path.iterdir(), key=lambda p: p.name)
        except (PermissionError, OSError):
            return  # skip directories we can't read
        for p in entries:
            if truncated:
                return
            try:
                is_dir = p.is_dir()
                is_link = p.is_symlink()
            except OSError:
                continue
            if is_link and (is_dir or not resolves_inside(p, root)):
                # A symlinked dir can loop forever; any link can point outside the repo.
                continue
            if is_dir:
                if not should_skip_dir(p):
                    walk(p)
                continue
            if p.suffix.lower() in SCANNED_SUFFIXES:
                if len(files) >= max_files:
                    truncated = True  # a further file exists past the limit
                    return
                files.append(p)

    root = repo_path.resolve()
    walk(repo_path)
    return files, truncated


def resolves_inside(path: Path, root: Path) -> bool:
    """True when path, with symlinks resolved, is root or lies under it."""
    try:
        path.resolve().relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def iter_files(repo_path: Path, max_files: int = 400) -> List[Path]:
    """Relevant files (TS, JS, PY, JSON, YAML, MD, CloudFormation, Terraform) under repo_path, up to max_files."""
    return walk_files(repo_path, max_files)[0]


def truncation_notes(truncated: bool, max_files: int) -> Dict[str, Any]:
    """RepoContext notes recording that the file walk stopped at max_files; empty when it did not."""
    return {"files_truncated": True, "max_files": max_files} if truncated else {}


def truncation_message(notes: Dict[str, Any]) -> str | None:
    """One line telling the user the file walk was truncated, or None when it was not."""
    if not notes.get("files_truncated"):
        return None
    limit = notes.get("max_files")
    return (
        f"File walk stopped at --max-files {limit}: files past that were not scanned. "
        "Raise --max-files to scan the whole repo."
    )


class FileTooLargeError(ValueError):
    """A file passed the size cap of read_text_capped; it was not parsed."""


def read_text_capped(path: Path, max_chars: int, errors: str = "strict") -> str:
    """Read path as UTF-8 text, like Path.read_text, but refuse files over max_chars.

    Only a regular file is read: a FIFO would block and a device such as /dev/zero never
    ends, so both raise OSError. The read itself is bounded, so a huge file cannot exhaust
    memory. Raises FileTooLargeError when the file is over the cap, and OSError or
    UnicodeDecodeError as Path.read_text would.
    """
    if not stat.S_ISREG(path.stat().st_mode):
        raise OSError(f"{path.name} is not a regular file")
    with path.open(encoding="utf-8", errors=errors) as handle:
        text = handle.read(max_chars + 1)
    if len(text) > max_chars:
        raise FileTooLargeError(f"{path.name} is larger than the {max_chars:,}-character limit")
    return text


def read_text_safe(path: Path, max_bytes: int = 200_000) -> str:
    """Read path as UTF-8 text, truncating at max_bytes; return empty string on error."""
    try:
        data = path.read_bytes()
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""
