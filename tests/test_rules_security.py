"""Security-rule-specific tests. Main rule coverage (S3 public access, IAM wildcard, etc.) is in test_rules.py."""
from pathlib import Path

from aws_arch_agent.rules.security import (
    S3EncryptionMissing,
    IamWildcardResource,
    OpenSshToWorld,
    OpenDbPortsToWorld,
    KmsKeyPolicyWildcard,
)


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


def test_iam_wildcard_resource_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'const p = { Action: "s3:GetObject", Resource: "*" };',
        encoding="utf-8",
    )
    rule = IamWildcardResource()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-002"


def test_open_ssh_to_world_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "ec2.SecurityGroup.fromLookup(this, 'SG', { allowAllOutbound: true });\n"
        "connections.allowFrom(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));",
        encoding="utf-8",
    )
    rule = OpenSshToWorld()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-003"


def test_open_db_ports_to_world_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(3306));",
        encoding="utf-8",
    )
    rule = OpenDbPortsToWorld()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-004"


def test_kms_key_policy_wildcard_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "const key = new kms.Key(this, 'Key');\n"
        "key.addToResourcePolicy(new iam.PolicyStatement({ Principal: '*', Action: 'kms:*' }));",
        encoding="utf-8",
    )
    rule = KmsKeyPolicyWildcard()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-007"
