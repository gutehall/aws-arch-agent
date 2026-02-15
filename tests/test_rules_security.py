"""Security-rule-specific tests. Main rule coverage (S3 public access, IAM wildcard, etc.) is in test_rules.py."""
from pathlib import Path

from aws_arch_agent.rules.security import S3EncryptionMissing


def test_s3_encryption_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B");',
        encoding="utf-8",
    )
    rule = S3EncryptionMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-006"
