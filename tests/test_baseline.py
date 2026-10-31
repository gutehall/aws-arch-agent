"""Tests for baseline suppressions."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.baseline import (
    BaselineError,
    Fingerprint,
    filter_new_findings,
    finding_fingerprint,
    load_baseline,
    merge_into_baseline,
    save_baseline,
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
    finding = Finding(
        id="SEC-001",
        title="t",
        severity="High",
        recommendation="r",
        file="./src/a.ts",
        line=15,
        evidence="const bucket = new s3.Bucket()",
    )
    moved = finding.model_copy(update={"line": 40})
    baseline = {finding_fingerprint(finding)._replace(file="src/a.ts")}
    assert filter_new_findings([moved], baseline) == []


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
    loaded = load_baseline(path)
    assert loaded == {Fingerprint("SEC-001", "a.ts", None, None, True)}
    moved = Finding(
        id="SEC-001",
        title="t",
        severity="High",
        recommendation="r",
        file="a.ts",
        line=40,
        evidence="changed",
    )
    assert filter_new_findings([moved], loaded) == []


def test_same_evidence_ignores_line_number() -> None:
    first = Finding(
        id="SEC-001",
        title="t",
        severity="High",
        recommendation="r",
        file="a.ts",
        line=10,
        evidence="Action: \"*\"",
    )
    moved = first.model_copy(update={"line": 11})
    other = first.model_copy(update={"line": 12, "evidence": "Action: \"s3:*\""})
    assert finding_fingerprint(first) == finding_fingerprint(moved)
    assert finding_fingerprint(first) != finding_fingerprint(other)
    assert filter_new_findings([moved, other], {finding_fingerprint(first)}) == [other]


def test_save_baseline_writes_evidence_hash_not_line(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    bare = Finding(id="SEC-001", title="t", severity="High", recommendation="r", file="a.ts", line=1)
    detailed = bare.model_copy(update={"evidence": "bucket"})
    save_baseline(path, {finding_fingerprint(bare), finding_fingerprint(detailed)})
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert all("line" not in item for item in saved["accepted"])
    assert load_baseline(path) == {finding_fingerprint(bare), finding_fingerprint(detailed)}


def test_save_baseline_replace_failure_keeps_original(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "baseline.json"
    original = '{"accepted": []}\n'
    path.write_text(original, encoding="utf-8")

    def boom(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("aws_arch_agent.baseline.os.replace", boom)
    with pytest.raises(OSError):
        save_baseline(path, {Fingerprint("SEC-001", "a.ts", None)})
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
    baseline = {Fingerprint("SEC-001", "app.py", None, None, True)}
    assert filter_new_findings([finding], baseline) == [finding]
    nested = _cf_finding("BucketA (AWS::S3::Bucket)", file="cdk.out/mystack.template.json")
    short = {finding_fingerprint(nested)._replace(file="mystack.template.json")}
    assert filter_new_findings([nested], short) == [nested]


def test_absolute_baseline_path_matches_relative_finding() -> None:
    finding = _cf_finding("BucketA (AWS::S3::Bucket)")
    baseline = {
        finding_fingerprint(finding)._replace(
            file="/Users/other/checkout/cdk.out/stack.template.json"
        )
    }
    assert filter_new_findings([finding], baseline) == []
    other = _cf_finding("BucketB (AWS::S3::Bucket)")
    assert filter_new_findings([other], baseline) == [other]


def test_legacy_logical_id_matches_without_evidence_hash(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "accepted": [
                    {
                        "id": "CF-S3-001",
                        "file": "cdk.out/stack.template.json",
                        "line": None,
                        "logical_id": "BucketA (AWS::S3::Bucket)",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    bucket_a = _cf_finding("BucketA (AWS::S3::Bucket)")
    bucket_b = _cf_finding("BucketB (AWS::S3::Bucket)")
    loaded = load_baseline(path)
    assert filter_new_findings([bucket_a, bucket_b], loaded) == [bucket_b]


def test_baseline_without_logical_id_does_not_suppress_every_bucket() -> None:
    bucket_a = _cf_finding("BucketA (AWS::S3::Bucket)")
    bucket_b = _cf_finding("BucketB (AWS::S3::Bucket)")
    baseline = {Fingerprint("CF-S3-001", "cdk.out/stack.template.json", None)}
    assert filter_new_findings([bucket_a, bucket_b], baseline) == [bucket_a, bucket_b]

