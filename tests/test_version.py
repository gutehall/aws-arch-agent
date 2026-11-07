"""The version lives in one place and the CLI prints it."""
import re
import tomllib
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent import __version__
from aws_arch_agent.cli import app

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_reads_version_from_package() -> None:
    """pyproject.toml must not hardcode a second copy of the version."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in data["project"], "set the version in __init__.py, not pyproject.toml"
    assert "version" in data["project"]["dynamic"]
    assert data["tool"]["hatch"]["version"]["path"] == "src/aws_arch_agent/__init__.py"


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), __version__


def test_cli_prints_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == __version__


def test_changelog_top_entry_matches_version() -> None:
    """The newest CHANGELOG.md entry is the version being released."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(r"^## v(\d+\.\d+\.\d+)\b", text, re.MULTILINE)
    assert match, "CHANGELOG.md has no '## vX.Y.Z' entry"
    assert match.group(1) == __version__
