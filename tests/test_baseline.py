"""Tests for baseline suppressions."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.baseline import (
    BaselineError,
    filter_new_findings,
    load_baseline,
    merge_into_baseline,
    save_baseline,
    finding_fingerprint,
)
from aws_arch_agent.models import Finding


def test_baseline_roundtrip(tmp_path: Path) -> None:
    f = Finding(id="SEC-001", title="t", severity="High", recommendation="r", file="a.ts", line=1)
    fp = finding_fingerprint(f)
    path = tmp_path / "baseline.json"
    save_baseline(path, {fp})
    loaded = load_baseline(path)
    assert fp in loaded


def test_filter_new_findings() -> None:
    f1 = Finding(id="SEC-001", title="t", severity="High", recommendation="r", file="a.ts", line=1)
    f2 = Finding(id="SEC-002", title="t2", severity="High", recommendation="r2", file="b.ts", line=2)
    baseline = {finding_fingerprint(f1)}
    new_only = filter_new_findings([f1, f2], baseline)
    assert len(new_only) == 1
    assert new_only[0].id == "SEC-002"


def test_merge_into_baseline() -> None:
    f = Finding(id="SEC-001", title="t", severity="High", recommendation="r")
    merged = merge_into_baseline(set(), [f])
    assert finding_fingerprint(f) in merged


def test_baseline_matches_ripgrep_path_prefix() -> None:
    """Ripgrep reports ./file.ts; baseline stores file.ts — both must match."""
    baseline = {("SEC-001", "src/a.ts", 15)}
    finding = Finding(
        id="SEC-001",
        title="t",
        severity="High",
        recommendation="r",
        file="./src/a.ts",
        line=15,
    )
    assert filter_new_findings([finding], baseline) == []


def test_load_baseline_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "missing.json") == set()


def test_load_baseline_corrupt_raises(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_baseline_coerces_numeric_line_string(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps({"accepted": [{"id": "SEC-001", "file": "a.ts", "line": "15"}]}),
        encoding="utf-8",
    )
    assert ("SEC-001", "a.ts", 15) in load_baseline(path)


def test_save_baseline_sorts_none_and_int_lines(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    fingerprints = {("SEC-001", "a.ts", None), ("SEC-001", "a.ts", 15)}
    save_baseline(path, fingerprints)
    assert load_baseline(path) == fingerprints


def test_save_baseline_replace_failure_keeps_original(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "baseline.json"
    original = '{"accepted": []}\n'
    path.write_text(original, encoding="utf-8")

    def boom(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("aws_arch_agent.baseline.os.replace", boom)
    with pytest.raises(OSError):
        save_baseline(path, {("SEC-001", "a.ts", 1)})
    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("*.tmp")) == []

