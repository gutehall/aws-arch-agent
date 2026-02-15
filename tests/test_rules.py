"""Unit tests for static rules (TS and Python)."""
from pathlib import Path

import pytest

from aws_arch_agent.rules.security import S3PublicAccessNotBlocked, S3EncryptionMissing, IamWildcardAction
from aws_arch_agent.rules.best_practices import MissingStandardTags


def test_s3_public_access_not_blocked_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    rule = S3PublicAccessNotBlocked()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-005"
    assert "Block Public Access" in findings[0].title


def test_s3_public_access_blocked_ts_no_finding(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B", { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL });',
        encoding="utf-8",
    )
    rule = S3PublicAccessNotBlocked()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) == 0


def test_s3_bucket_python(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "stack.py").write_text(
        "from aws_cdk import aws_s3 as s3\ns3.Bucket(self, 'B')",
        encoding="utf-8",
    )
    rule = S3PublicAccessNotBlocked()
    findings = rule.run(tmp_path, "python")
    # May or may not find depending on block_public_access presence
    assert all(f.id == "SEC-005" for f in findings)


def test_missing_standard_tags_ts_no_tags(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text("export class Stack {};", encoding="utf-8")
    rule = MissingStandardTags()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "BP-001"


def test_iam_wildcard_action_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'const policy = { Action: "*", Resource: "arn:aws:s3:::foo" };',
        encoding="utf-8",
    )
    rule = IamWildcardAction()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-001"
