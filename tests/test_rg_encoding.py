"""ripgrep output is decoded as UTF-8 regardless of the OS locale."""
import shutil
import subprocess
from pathlib import Path

import pytest

from aws_arch_agent.tools import rg as rg_mod


def test_rg_decodes_output_as_utf8(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "lib\\stack.ts:3:const név = 1;\n", "")

    monkeypatch.setattr(rg_mod.subprocess, "run", fake_run)
    hits = rg_mod.rg(tmp_path, "név")
    assert seen["encoding"] == "utf-8"
    assert seen["errors"] == "replace"
    # Windows ripgrep prints backslash paths; they are normalized to forward slashes.
    assert hits == [("lib/stack.ts", 3, "const név = 1;")]


def test_rg_reads_non_ascii_source(tmp_path: Path) -> None:
    if shutil.which("rg") is None:  # pragma: no cover
        pytest.skip("ripgrep not installed")
    (tmp_path / "stack.ts").write_text("// Ångström café\nnew s3.Bucket(this, 'B');\n", encoding="utf-8")
    hits = rg_mod.rg(tmp_path, "Ångström")
    assert hits == [("stack.ts", 1, "// Ångström café")]
