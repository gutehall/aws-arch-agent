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


def _cf_finding(evidence: str, file: str = "cdk.out/stack.template.json") -> Finding:
    return Finding(
        id="CF-S3-001",
        title="t",
        severity="High",
        recommendation="r",
        file=file,
        line=None,
        evidence=evidence,
    )


def test_cf_fingerprint_includes_evidence_and_roundtrips(tmp_path: Path) -> None:
    bucket_a = _cf_finding("BucketA (AWS::S3::Bucket)")
    bucket_b = _cf_finding("BucketB (AWS::S3::Bucket)")
    fp_a = finding_fingerprint(bucket_a)
    fp_b = finding_fingerprint(bucket_b)
    assert fp_a != fp_b
    assert fp_a[3] == "BucketA (AWS::S3::Bucket)"

    path = tmp_path / "baseline.json"
    save_baseline(path, {fp_a, fp_b})
    assert load_baseline(path) == {fp_a, fp_b}
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert {item["logical_id"] for item in saved["accepted"]} == {
        "BucketA (AWS::S3::Bucket)",
        "BucketB (AWS::S3::Bucket)",
    }


def test_relative_paths_do_not_match_by_suffix() -> None:
    finding = Finding(
        id="SEC-001",
        title="t",
        severity="High",
        recommendation="r",
        file="lib/app.py",
        line=10,
    )
    baseline = {("SEC-001", "app.py", 10)}
    assert filter_new_findings([finding], baseline) == [finding]
    nested = _cf_finding("BucketA (AWS::S3::Bucket)", file="cdk.out/mystack.template.json")
    short = {
        (
            "CF-S3-001",
            "mystack.template.json",
            None,
            "BucketA (AWS::S3::Bucket)",
        )
    }
    assert filter_new_findings([nested], short) == [nested]


def test_absolute_baseline_path_matches_relative_finding() -> None:
    finding = _cf_finding("BucketA (AWS::S3::Bucket)")
    baseline = {
        (
            "CF-S3-001",
            "/Users/other/checkout/cdk.out/stack.template.json",
            None,
            "BucketA (AWS::S3::Bucket)",
        )
    }
    assert filter_new_findings([finding], baseline) == []
    other = _cf_finding("BucketB (AWS::S3::Bucket)")
    assert filter_new_findings([other], baseline) == [other]


def test_baseline_without_logical_id_does_not_suppress_every_bucket() -> None:
    bucket_a = _cf_finding("BucketA (AWS::S3::Bucket)")
    bucket_b = _cf_finding("BucketB (AWS::S3::Bucket)")
    baseline = {("CF-S3-001", "cdk.out/stack.template.json", None)}
    assert filter_new_findings([bucket_a, bucket_b], baseline) == [bucket_a, bucket_b]

