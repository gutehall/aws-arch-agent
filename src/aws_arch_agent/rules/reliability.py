from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class RdsMultiAzMissing(Rule):
    id = "REL-001"
    title = "RDS may miss Multi-AZ"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        rds = rg(repo_path, rds_pat, glob=code_glob(language))
        maz = rg(repo_path, r'multi_az\s*:\s*True|multiAz\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if rds and not maz:
            f, ln, txt = rds[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider Multi-AZ for higher availability (especially in production).",
            ))
        return out


class BackupRetentionMissing(Rule):
    id = "REL-002"
    title = "RDS may miss backup retention"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        rds = rg(repo_path, rds_pat, glob=code_glob(language))
        br = rg(repo_path, r'backup_retention|backupRetention\s*:', glob=code_glob(language))
        out: List[Finding] = []
        if rds and not br:
            f, ln, txt = rds[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set backupRetention per RPO/RTO (e.g. 7–35 days).",
            ))
        return out


class LambdaDlqMissing(Rule):
    id = "REL-003"
    title = "Lambda may miss DLQ / on-failure destination"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Updated to catch NodejsFunction, PythonFunction, DockerImageFunction, etc.
        lambda_pat = r'new\s+(lambda\.Function|NodejsFunction|PythonFunction|DockerImageFunction)\(' if language == "typescript" else r'(lambda_.Function|aws_lambda_python_alpha.PythonFunction|aws_lambda.Function)\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        dlq = rg(repo_path, r'dead_letter_queue|deadLetterQueue|on_failure|onFailure', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not dlq:
            f, ln, txt = lambdas[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider DLQ or onFailure destinations for better error handling.",
            ))
        return out


class DynamoDbPitrMissing(Rule):
    id = "REL-004"
    title = "DynamoDB may miss point-in-time recovery"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ddb_pat = r'new\s+(dynamodb\.Table|Table)\(' if language == "typescript" else r'(dynamodb.Table|aws_dynamodb.Table)\('
        tables = rg(repo_path, ddb_pat, glob=code_glob(language))
        pitr = rg(repo_path, r'point_in_time_recovery|pointInTimeRecovery\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if tables and not pitr:
            f, ln, txt = tables[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable point-in-time recovery (PITR) for DynamoDB tables to protect against accidental deletes/updates. In CDK: pointInTimeRecovery: true",
            ))
        return out


class DynamoDbBackupMissing(Rule):
    id = "REL-005"
    title = "DynamoDB may miss automated backups"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ddb_pat = r'new\s+(dynamodb\.Table|Table)\(' if language == "typescript" else r'(dynamodb.Table|aws_dynamodb.Table)\('
        tables = rg(repo_path, ddb_pat, glob=code_glob(language))
        # Check for AWS Backup, backup plans, or point-in-time recovery
        backup = rg(repo_path, r'BackupPlan|backup.*Table|pointInTimeRecovery', glob=code_glob(language))
        out: List[Finding] = []
        if tables and not backup:
            f, ln, txt = tables[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider AWS Backup or point-in-time recovery for DynamoDB tables to meet RPO/RTO requirements.",
            ))
        return out


class ApiGatewayThrottling(Rule):
    id = "REL-006"
    title = "API Gateway throttling not configured"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        api_pat = r'new\s+(apigateway\.(RestApi|HttpApi)|RestApi|HttpApi)\(' if language == "typescript" else r'(apigateway\.(RestApi|HttpApi)|RestApi|HttpApi)\('
        apis = rg(repo_path, api_pat, glob=code_glob(language))
        throttle = rg(repo_path, r'throttle|rateLimit|burstLimit', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not throttle:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure throttling limits for API Gateway to prevent overwhelming backend services. In CDK: throttle with rateLimit and burstLimit",
            ))
        return out


class AlbHealthCheck(Rule):
    id = "REL-007"
    title = "ALB health check configuration missing"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        target_pat = r'new\s+elbv2\.(ApplicationTargetGroup|NetworkTargetGroup)\(' if language == "typescript" else r'elbv2\.(ApplicationTargetGroup|NetworkTargetGroup)\('
        targets = rg(repo_path, target_pat, glob=code_glob(language))
        health = rg(repo_path, r'healthCheck\s*:|configureHealthCheck', glob=code_glob(language))
        out: List[Finding] = []
        if targets and not health:
            f, ln, txt = targets[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure health checks for ALB/NLB target groups with appropriate path, interval, and thresholds. In CDK: healthCheck property",
            ))
        return out


class SqsDlqMissing(Rule):
    id = "REL-008"
    title = "SQS missing dead-letter queue configuration"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sqs_pat = r'new\s+sqs\.Queue\(' if language == "typescript" else r'sqs\.Queue\('
        queues = rg(repo_path, sqs_pat, glob=code_glob(language))
        dlq = rg(repo_path, r'deadLetterQueue\s*:|redrivePolicy', glob=code_glob(language))
        out: List[Finding] = []
        if queues and not dlq:
            f, ln, txt = queues[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure dead-letter queue for SQS to handle failed message processing. In CDK: deadLetterQueue with maxReceiveCount",
            ))
        return out


class LambdaTimeout(Rule):
    id = "REL-009"
    title = "Lambda timeout may be too low or too high"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+(lambda\.Function|NodejsFunction|PythonFunction|DockerImageFunction)\(' if language == "typescript" else r'(lambda_.Function|aws_lambda_python_alpha.PythonFunction|aws_lambda.Function)\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        timeout = rg(repo_path, r'timeout\s*:\s*Duration\.(seconds|minutes)\(', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not timeout:
            f, ln, txt = lambdas[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set appropriate Lambda timeout based on function workload (avoid default 3s or max 15min unless needed). In CDK: timeout: Duration.seconds(30)",
            ))
        return out


class LambdaVpcAccess(Rule):
    id = "REL-010"
    title = "Lambda not in VPC when accessing RDS/ElastiCache"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+(lambda\.Function|NodejsFunction|PythonFunction|DockerImageFunction)\(' if language == "typescript" else r'(lambda_.Function|aws_lambda_python_alpha.PythonFunction|aws_lambda.Function)\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        rds_or_cache = rg(repo_path, r'DatabaseInstance|DatabaseCluster|CfnCacheCluster', glob=code_glob(language))
        vpc_config = rg(repo_path, r'vpc\s*:\s*|vpcSubnets', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and rds_or_cache and not vpc_config:
            f, ln, txt = lambdas[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Lambda functions accessing RDS/ElastiCache should be in VPC for security and connectivity. In CDK: vpc and vpcSubnets properties",
            ))
        return out


class RdsReadReplicas(Rule):
    id = "REL-011"
    title = "RDS read replicas missing for read-heavy workloads"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        dbs = rg(repo_path, rds_pat, glob=code_glob(language))
        replicas = rg(repo_path, r'addReadReplica|readReplica', glob=code_glob(language))
        out: List[Finding] = []
        if dbs and not replicas:
            f, ln, txt = dbs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider RDS read replicas for read-heavy workloads to improve performance and availability",
            ))
        return out


class NatGatewaySingleAz(Rule):
    id = "REL-012"
    title = "NAT Gateway single point of failure (need multi-AZ)"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        nat_pat = r'natGateways\s*:\s*1(?![0-9])|maxAzs\s*:\s*1(?![0-9])' if language == "typescript" else r'nat_gateways\s*=\s*1(?![0-9])'
        single_nat = rg(repo_path, nat_pat, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in single_nat[:1]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Use NAT Gateways in multiple AZs for high availability. In CDK: natGateways: 2 or higher (matches maxAzs)",
            ))
        return out


class BackupVaultMissing(Rule):
    id = "REL-013"
    title = "AWS Backup vault not configured"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        resources = rg(repo_path, r'DatabaseInstance|DynamoDB|EFS|EC2', glob=code_glob(language))
        backup = rg(repo_path, r'backup\.BackupVault|backup\.BackupPlan', glob=code_glob(language))
        out: List[Finding] = []
        if resources and not backup:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider AWS Backup for centralized backup management across services (RDS, DynamoDB, EFS, EC2)",
            )]
        return out


class CrossRegionBackup(Rule):
    id = "REL-014"
    title = "Cross-region backup replication missing"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        backup = rg(repo_path, r'backup\.BackupVault|backup\.BackupPlan', glob=code_glob(language))
        cross_region = rg(repo_path, r'copyActions|destinationBackupVault', glob=code_glob(language))
        out: List[Finding] = []
        if backup and not cross_region:
            f, ln, txt = backup[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider cross-region backup replication for disaster recovery. In AWS Backup: configure copy actions",
            ))
        return out


class StepFunctionsRetry(Rule):
    id = "REL-015"
    title = "Step Functions retry/catch not configured"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sfn_pat = r'new\s+sfn\.StateMachine\(' if language == "typescript" else r'sfn\.StateMachine\('
        sfns = rg(repo_path, sfn_pat, glob=code_glob(language))
        retry = rg(repo_path, r'addRetry|addCatch|retryOnServiceExceptions', glob=code_glob(language))
        out: List[Finding] = []
        if sfns and not retry:
            f, ln, txt = sfns[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Add retry and catch blocks to Step Functions for better error handling. In CDK: addRetry() and addCatch()",
            ))
        return out


class ElastiCacheMultiAz(Rule):
    id = "REL-016"
    title = "ElastiCache not using multi-AZ"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cache_pat = r'new\s+elasticache\.(CfnCacheCluster|CfnReplicationGroup)\(' if language == "typescript" else r'elasticache\.(CfnCacheCluster|CfnReplicationGroup)\('
        caches = rg(repo_path, cache_pat, glob=code_glob(language))
        multi_az = rg(repo_path, r'automaticFailoverEnabled|multiAzEnabled', glob=code_glob(language))
        out: List[Finding] = []
        if caches and not multi_az:
            f, ln, txt = caches[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable multi-AZ for ElastiCache for high availability. Set automaticFailoverEnabled to true",
            ))
        return out


class EfsBackupPolicy(Rule):
    id = "REL-017"
    title = "EFS backup policy not configured"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        efs_pat = r'new\s+efs\.FileSystem\(' if language == "typescript" else r'efs\.FileSystem\('
        filesystems = rg(repo_path, efs_pat, glob=code_glob(language))
        backup = rg(repo_path, r'enableAutomaticBackups|backupPolicy', glob=code_glob(language))
        out: List[Finding] = []
        if filesystems and not backup:
            f, ln, txt = filesystems[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable automatic backups for EFS file systems. In CDK: enableAutomaticBackups: true",
            ))
        return out


class EfsLifecyclePolicy(Rule):
    id = "REL-018"
    title = "EFS lifecycle policy not configured"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        efs_pat = r'new\s+efs\.FileSystem\(' if language == "typescript" else r'efs\.FileSystem\('
        filesystems = rg(repo_path, efs_pat, glob=code_glob(language))
        lifecycle = rg(repo_path, r'lifecyclePolicy|transitionToIA', glob=code_glob(language))
        out: List[Finding] = []
        if filesystems and not lifecycle:
            f, ln, txt = filesystems[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure lifecycle policy for EFS to transition infrequently accessed files to IA storage class for cost savings",
            ))
        return out


class KinesisRetention(Rule):
    id = "REL-019"
    title = "Kinesis stream retention period too short"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kinesis_pat = r'new\s+kinesis\.(Stream|CfnStream)\(' if language == "typescript" else r'kinesis\.(Stream|CfnStream)\('
        streams = rg(repo_path, kinesis_pat, glob=code_glob(language))
        retention = rg(repo_path, r'retentionPeriod.*days\([7-9]|[1-9][0-9]|[1-3][0-9][0-9]\)', glob=code_glob(language))
        out: List[Finding] = []
        if streams and not retention:
            f, ln, txt = streams[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set appropriate retention period for Kinesis streams (default 24h may be too short). In CDK: retentionPeriod: Duration.days(7)",
            ))
        return out


class GlobalAcceleratorHealthChecks(Rule):
    id = "REL-020"
    title = "Global Accelerator health checks not configured"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ga_pat = r'new\s+globalaccelerator\.(Accelerator|CfnAccelerator)\(' if language == "typescript" else r'globalaccelerator\.(Accelerator|CfnAccelerator)\('
        accelerators = rg(repo_path, ga_pat, glob=code_glob(language))
        health = rg(repo_path, r'healthCheckProtocol|healthCheckPath', glob=code_glob(language))
        out: List[Finding] = []
        if accelerators and not health:
            f, ln, txt = accelerators[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure health checks for Global Accelerator endpoints for automatic failover",
            ))
        return out


class CodePipelineApproval(Rule):
    id = "REL-021"
    title = "CodePipeline missing manual approval for production"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pipeline_pat = r'new\s+codepipeline\.(Pipeline|CfnPipeline)\(' if language == "typescript" else r'codepipeline\.(Pipeline|CfnPipeline)\('
        pipelines = rg(repo_path, pipeline_pat, glob=code_glob(language))
        approval = rg(repo_path, r'ManualApprovalAction|approval', glob=code_glob(language))
        production = rg(repo_path, r'prod|production', glob=code_glob(language))
        out: List[Finding] = []
        if pipelines and production and not approval:
            f, ln, txt = pipelines[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Add manual approval stage before production deployments in CodePipeline. In CDK: new ManualApprovalAction()",
            ))
        return out


class AcmCertificateValidation(Rule):
    id = "REL-022"
    title = "ACM certificate validation method not specified"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        acm_pat = r'new\s+acm\.(Certificate|DnsValidatedCertificate)\(' if language == "typescript" else r'acm\.(Certificate|DnsValidatedCertificate)\('
        certs = rg(repo_path, acm_pat, glob=code_glob(language))
        validation = rg(repo_path, r'validation.*CertificateValidation\.(fromDns|fromEmail)', glob=code_glob(language))
        out: List[Finding] = []
        if certs and not validation:
            f, ln, txt = certs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Specify DNS validation for ACM certificates for automatic renewal. In CDK: validation: acm.CertificateValidation.fromDns()",
            ))
        return out
