"""File walk: deterministic order and max-files truncation."""
import json
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent.cli import app
from aws_arch_agent.tools import files as files_mod
from aws_arch_agent.tools.files import iter_files, truncation_message, walk_files


def _tree(root: Path) -> None:
    for rel in ["b/z.ts", "b/a.ts", "a/y.py", "c.json", "a.md", "node_modules/x.ts", ".hidden/x.ts"]:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}", encoding="utf-8")


def test_walk_sorts_entries_at_every_level(tmp_path: Path, monkeypatch) -> None:
    _tree(tmp_path)
    real = Path.iterdir
    # Reverse the filesystem order: the walk must not depend on it.
    monkeypatch.setattr(Path, "iterdir", lambda self: iter(sorted(real(self), reverse=True)))
    names = [p.relative_to(tmp_path).as_posix() for p in iter_files(tmp_path)]
    assert names == ["a/y.py", "a.md", "b/a.ts", "b/z.ts", "c.json"]


def test_walk_reports_truncation_only_when_files_remain(tmp_path: Path) -> None:
    _tree(tmp_path)
    found, truncated = walk_files(tmp_path, max_files=2)
    assert [p.name for p in found] == ["y.py", "a.md"] and truncated
    found, truncated = walk_files(tmp_path, max_files=5)
    assert len(found) == 5 and not truncated


def test_truncation_notes_and_message() -> None:
    assert files_mod.truncation_notes(False, 10) == {}
    notes = files_mod.truncation_notes(True, 10)
    assert notes == {"files_truncated": True, "max_files": 10}
    assert "--max-files 10" in truncation_message(notes)
    assert truncation_message({}) is None


def test_cli_reports_truncation_without_failing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "lib").mkdir()
    for i in range(3):
        (repo / "lib" / f"s{i}.ts").write_text("export {};", encoding="utf-8")
    md = tmp_path / "r.md"
    result = CliRunner().invoke(
        app, ["--repo", str(repo), "--no-llm", "--max-files", "2", "--out", str(md)]
    )
    assert result.exit_code == 0, result.output
    assert "Raise --max-files" in result.output
    assert "File walk stopped at --max-files 2" in md.read_text(encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(
        app, ["--repo", str(repo), "--no-llm", "--max-files", "2", "--format", "json", "--out", str(out)]
    )
    notes = json.loads(out.read_text(encoding="utf-8"))["context"]["notes"]
    assert notes["files_truncated"] is True and notes["max_files"] == 2
