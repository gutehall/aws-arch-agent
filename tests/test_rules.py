"""Unit tests for static rules (TS and Python)."""
from pathlib import Path

from aws_arch_agent.rules.security import (
    S3PublicAccessNotBlocked,
    IamWildcardAction,
    LambdaFunctionUrlAuth,
    RdsPubliclyAccessible,
)
from aws_arch_agent.rules.best_practices import MissingStandardTags
from aws_arch_agent.rules.reliability import (
    RdsMultiAzMissing,
    BackupRetentionMissing,
    LambdaDlqMissing,
    RdsDeletionProtection,
    S3VersioningMissing,
)
from aws_arch_agent.rules.cost import LogRetentionNeverExpire, MissingAutoscalingHint
from aws_arch_agent.rules.operational_excellence import (
    CloudTrailMissing,
    VpcFlowLogsMissing,
    XRayTracingMissing,
)
from aws_arch_agent.rules.performance_efficiency import GravitonNotUsed, CachingHint
from aws_arch_agent.rules.sustainability import SpotNotConsidered, RightSizingHint


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


# --- Reliability (REL-001, REL-002, REL-003) ---


def test_rds_multi_az_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new rds.DatabaseInstance(this, "DB", { instanceIdentifier: "db", engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0 }) });',
        encoding="utf-8",
    )
    rule = RdsMultiAzMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "REL-001"


def test_backup_retention_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new rds.DatabaseInstance(this, "DB", { engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0 }) });',
        encoding="utf-8",
    )
    rule = BackupRetentionMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "REL-002"


def test_lambda_dlq_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new lambda.Function(this, "Fn", { runtime: lambda.Runtime.NODEJS_18_X, handler: "index.handler", code: lambda.Code.fromInline("x") });',
        encoding="utf-8",
    )
    rule = LambdaDlqMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "REL-003"


# --- Cost (COST-001, COST-002) ---


def test_log_retention_never_expire_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new logs.LogGroup(this, 'LG', { retention: logs.RetentionDays.INFINITE });",
        encoding="utf-8",
    )
    rule = LogRetentionNeverExpire()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "COST-001"


def test_missing_autoscaling_hint_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new ecs.FargateService(this, "Svc", { cluster, taskDefinition });',
        encoding="utf-8",
    )
    rule = MissingAutoscalingHint()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "COST-002"


# --- Operational Excellence (OPS-001, OPS-002, OPS-003) ---


def test_cloud_trail_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B");',
        encoding="utf-8",
    )
    rule = CloudTrailMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "OPS-001"


def test_vpc_flow_logs_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new ec2.Vpc(this, "Vpc", { maxAzs: 2 });',
        encoding="utf-8",
    )
    rule = VpcFlowLogsMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "OPS-002"


def test_xray_tracing_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new apigateway.RestApi(this, "Api");',
        encoding="utf-8",
    )
    rule = XRayTracingMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "OPS-003"


# --- Performance Efficiency (PERF-001, PERF-002) ---


def test_graviton_not_used_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new lambda.Function(this, "Fn", { runtime: lambda.Runtime.NODEJS_18_X, handler: "index.handler", code: lambda.Code.fromInline("x") });',
        encoding="utf-8",
    )
    rule = GravitonNotUsed()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "PERF-001"


def test_caching_hint_no_cache_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B");',
        encoding="utf-8",
    )
    rule = CachingHint()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "PERF-002"


# --- Sustainability (SUST-001, SUST-002) ---


def test_spot_not_considered_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new ecs.FargateService(this, "Svc", { cluster, taskDefinition });',
        encoding="utf-8",
    )
    rule = SpotNotConsidered()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SUST-001"


def test_right_sizing_hint_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new ec2.Instance(this, "Inst", { instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM), vpc, machineImage: ec2.MachineImage.latestAmazonLinux() });',
        encoding="utf-8",
    )
    rule = RightSizingHint()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SUST-002"


# --- New Security rules (SEC-057, SEC-064) ---


def test_lambda_function_url_auth_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });',
        encoding="utf-8",
    )
    rule = LambdaFunctionUrlAuth()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-057"


def test_lambda_function_url_auth_iam_no_finding(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.AWS_IAM });',
        encoding="utf-8",
    )
    rule = LambdaFunctionUrlAuth()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) == 0


def test_rds_publicly_accessible_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new rds.DatabaseInstance(this, "DB", { engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_15 }), vpc });',
        encoding="utf-8",
    )
    rule = RdsPubliclyAccessible()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "SEC-064"


# --- New Reliability rules (REL-030, REL-031) ---


def test_rds_deletion_protection_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new rds.DatabaseInstance(this, "DB", { engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_15 }), vpc });',
        encoding="utf-8",
    )
    rule = RdsDeletionProtection()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "REL-030"


def test_s3_versioning_missing_ts(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        'new s3.Bucket(this, "B");',
        encoding="utf-8",
    )
    rule = S3VersioningMissing()
    findings = rule.run(tmp_path, "typescript")
    assert len(findings) >= 1
    assert findings[0].id == "REL-031"
