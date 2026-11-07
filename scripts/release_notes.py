#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a release tag.

Used by .github/workflows/release.yml as the GitHub release notes:

    python scripts/release_notes.py v0.1.0 > notes.md

Exits 1 when the tag is not vX.Y.Z, when it does not match __version__ in
src/aws_arch_agent/__init__.py, or when CHANGELOG.md has no section for it. Reads files
only; it needs no install.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ReleaseNotesError(Exception):
    pass


def package_version(root: Path = ROOT) -> str:
    text = (root / "src" / "aws_arch_agent" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE)
    if not match:
        raise ReleaseNotesError("no __version__ in src/aws_arch_agent/__init__.py")
    return match.group(1)


def notes_for(tag: str, root: Path = ROOT) -> str:
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)", tag)
    if not match:
        raise ReleaseNotesError(f"tag {tag!r} is not vX.Y.Z")
    version = match.group(1)
    if version != package_version(root):
        raise ReleaseNotesError(
            f"tag {tag} does not match __version__ {package_version(root)}"
        )
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.compile(rf"^## v{re.escape(version)}(?=\s|$).*$", re.MULTILINE)
    start = heading.search(changelog)
    if not start:
        raise ReleaseNotesError(f"CHANGELOG.md has no '## {tag}' section")
    rest = changelog[start.end():]
    end = re.search(r"^## ", rest, re.MULTILINE)
    body = (rest[: end.start()] if end else rest).strip()
    if not body:
        raise ReleaseNotesError(f"CHANGELOG.md section for {tag} is empty")
    return body + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: release_notes.py vX.Y.Z", file=sys.stderr)
        return 2
    try:
        sys.stdout.write(notes_for(argv[0]))
    except ReleaseNotesError as exc:
        print(f"release_notes: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
