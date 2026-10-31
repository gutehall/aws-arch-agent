"""Security-rule-specific tests. Main rule coverage (S3 public access, IAM wildcard, etc.) is in test_rules.py."""
from pathlib import Path

from aws_arch_agent.rules.security import (
    AlbHttpsRedirect,
    AlbSslPolicy,
    CloudFrontHttpsOnly,
    IamWildcardAction,
    IamWildcardResource,
    KmsKeyPolicyWildcard,
    OpenDbPortsToWorld,
    OpenSshToWorld,
    RdsPubliclyAccessible,
    S3EncryptionMissing,
)


def test_s3_omitted_encryption_is_not_a_finding(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B");\n'
        'new s3.Bucket(this, "M", { encryption: s3.BucketEncryption.S3_MANAGED });\n'
        'new s3.Bucket(this, "K", { encryption: s3.BucketEncryption.KMS });',
        encoding="utf-8",
    )
    findings = S3EncryptionMissing().run(tmp_path, "typescript")
    assert findings == []


def test_s3_unencrypted_is_a_finding(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B", { encryption: s3.BucketEncryption.UNENCRYPTED });',
        encoding="utf-8",
    )
    findings = S3EncryptionMissing().run(tmp_path, "typescript")
    assert len(findings) == 1
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


def test_iam_actions_list_and_service_wildcard(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "actions: ['*'],\nactions: ['s3:*'],\n",
        encoding="utf-8",
    )
    findings = IamWildcardAction().run(tmp_path, "typescript")
    assert len(findings) == 2
    assert {f.id for f in findings} == {"SEC-001"}


def test_iam_python_actions_list(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'statement = iam.PolicyStatement(actions=["*"])\n',
        encoding="utf-8",
    )
    findings = IamWildcardAction().run(tmp_path, "python")
    assert any(f.id == "SEC-001" for f in findings)


def test_specific_iam_action_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'actions: ["s3:GetObject"], resources: ["arn:aws:s3:::bucket/*"]\n',
        encoding="utf-8",
    )
    assert IamWildcardAction().run(tmp_path, "typescript") == []
    assert IamWildcardResource().run(tmp_path, "typescript") == []


def test_open_ssh_on_separate_lines(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "const peer = ec2.Peer.anyIpv4();\nconst port = ec2.Port.SSH;\n",
        encoding="utf-8",
    )
    findings = OpenSshToWorld().run(tmp_path, "typescript")
    assert len(findings) == 1
    assert findings[0].line == 2


def test_private_ssh_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "connections.allowFrom(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(22));\n",
        encoding="utf-8",
    )
    assert OpenSshToWorld().run(tmp_path, "typescript") == []


def test_open_mongo_to_world(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(27017));\n",
        encoding="utf-8",
    )
    findings = OpenDbPortsToWorld().run(tmp_path, "typescript")
    assert any(f.id == "SEC-004" for f in findings)


def test_kms_wildcard_in_another_file_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "key.ts").write_text("const key = new kms.Key(this, 'Key');\n", encoding="utf-8")
    (tmp_path / "lib" / "other.ts").write_text("Principal: '*'\n", encoding="utf-8")
    assert KmsKeyPolicyWildcard().run(tmp_path, "typescript") == []


def test_https_listener_without_redirect_fires(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });\n"
        "listener.addTargets('App', { protocol: elbv2.ApplicationProtocol.HTTPS });\n",
        encoding="utf-8",
    )
    findings = AlbHttpsRedirect().run(tmp_path, "typescript")
    assert any(f.id == "SEC-011" for f in findings)


def test_real_http_redirect_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });\n"
        "listener.addRedirect({ protocol: 'HTTPS' });\n",
        encoding="utf-8",
    )
    assert AlbHttpsRedirect().run(tmp_path, "typescript") == []


def test_recommended_tls_and_tls12_ext_do_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });\n"
        "sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS,\n"
        "sslPolicy: elbv2.SslPolicy.TLS12_EXT,\n",
        encoding="utf-8",
    )
    assert AlbSslPolicy().run(tmp_path, "typescript") == []


def test_legacy_elb_policy_fires(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new elbv2.ApplicationLoadBalancer(this, 'Alb', { sslPolicy: 'ELBSecurityPolicy-2016-08' });\n",
        encoding="utf-8",
    )
    findings = AlbSslPolicy().run(tmp_path, "typescript")
    assert any(f.id == "SEC-012" for f in findings)


def test_https_only_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new cloudfront.Distribution(this, 'Cf', { viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY });\n",
        encoding="utf-8",
    )
    assert CloudFrontHttpsOnly().run(tmp_path, "typescript") == []


def test_rds_public_false_and_omitted_do_not_fire(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new rds.DatabaseInstance(this, "DB", { publiclyAccessible: false, vpc });\n',
        encoding="utf-8",
    )
    assert RdsPubliclyAccessible().run(tmp_path, "typescript") == []
    (tmp_path / "app.py").write_text(
        "rds.DatabaseInstance(self, 'DB', publicly_accessible=False, vpc=vpc)\n",
        encoding="utf-8",
    )
    assert RdsPubliclyAccessible().run(tmp_path, "python") == []
    (tmp_path / "lib" / "omitted.ts").write_text(
        'new rds.DatabaseInstance(this, "DB", { vpc });\n',
        encoding="utf-8",
    )
    assert RdsPubliclyAccessible().run(tmp_path, "typescript") == []


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
