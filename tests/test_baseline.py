"""Tests for baseline suppressions."""
from pathlib import Path

from aws_arch_agent.baseline import (
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
