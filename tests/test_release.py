"""Release notes come from CHANGELOG.md and the release workflow never touches tags."""
import importlib.util
import re
from pathlib import Path

import pytest
import yaml

from aws_arch_agent import __version__

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts" / "release_notes.py")
assert _spec and _spec.loader
release_notes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_notes)

CHANGELOG = """# Changelog

## v0.2.0 - 2026-12-01

### Features

- New check (#80)

## v0.1.0 - 2026-11-07

### Fixes

- Old fix (#1)
"""


def _repo(tmp_path: Path, version: str, changelog: str = CHANGELOG) -> Path:
    pkg = tmp_path / "src" / "aws_arch_agent"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(f"__version__ = '{version}'\n", encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


def test_notes_are_only_the_matching_section(tmp_path: Path) -> None:
    notes = release_notes.notes_for("v0.2.0", _repo(tmp_path, "0.2.0"))
    assert notes == "### Features\n\n- New check (#80)\n"


def test_last_section_runs_to_end_of_file(tmp_path: Path) -> None:
    notes = release_notes.notes_for("v0.1.0", _repo(tmp_path, "0.1.0"))
    assert notes == "### Fixes\n\n- Old fix (#1)\n"


@pytest.mark.parametrize(
    ("tag", "version", "message"),
    [
        ("0.2.0", "0.2.0", "not vX.Y.Z"),
        ("v0.2.0-rc1", "0.2.0", "not vX.Y.Z"),
        ("v0.2.0", "0.1.0", "does not match __version__"),
        ("v0.3.0", "0.3.0", "no '## v0.3.0' section"),
    ],
)
def test_bad_tags_fail(tmp_path: Path, tag: str, version: str, message: str) -> None:
    with pytest.raises(release_notes.ReleaseNotesError, match=re.escape(message)):
        release_notes.notes_for(tag, _repo(tmp_path, version))


def test_current_version_has_notes() -> None:
    assert release_notes.notes_for(f"v{__version__}").strip()


def test_main_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert release_notes.main([]) == 2
    assert release_notes.main(["nope"]) == 1
    assert "not vX.Y.Z" in capsys.readouterr().err


def test_workflow_runs_on_version_tags_and_never_touches_tags() -> None:
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    # PyYAML reads the bare `on:` key as True.
    assert workflow[True] == {"push": {"tags": ["v*"]}}
    assert "git tag" not in text
    assert "git push" not in text
    assert "--clobber" not in text
    assert "gh release edit" not in text
    assert "gh release view" in text
    assert "--verify-tag" in text
    # Tag name reaches shell only through env, never inlined into a run script.
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            assert "${{" not in step.get("run", ""), step
