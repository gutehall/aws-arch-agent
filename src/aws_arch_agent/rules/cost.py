from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class LogRetentionNeverExpire(Rule):
    id = "COST-001"
    title = "Log retention may be infinite (cost risk)"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pattern = r'RetentionDays\.INFINITE|retention\s*:\s*logs\.RetentionDays\.INFINITE' if language == "typescript" else r'INFINITE|retention.*infinite'
        logs = rg(repo_path, pattern, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in logs:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set log retention to a reasonable level (e.g. 14/30/90 days) to control costs.",
            ))
        return out


class MissingAutoscalingHint(Rule):
    id = "COST-002"
    title = "Compute resources may miss autoscaling"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        asg = rg(repo_path, r'AutoScalingGroup|add_auto_scaling|addAutoScaling', glob=code_glob(language))
        ecs_pat = r'new\s+ecs\.(FargateService|Ec2Service)\(' if language == "typescript" else r'ecs\.(FargateService|Ec2Service)\('
        ecs = rg(repo_path, ecs_pat, glob=code_glob(language))
        out: List[Finding] = []
        if ecs and not asg:
            f, ln, txt = ecs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider autoscaling policies (CPU/Memory/Queue depth) to reduce cost and improve performance.",
            ))
        return out


class DynamoDbAutoscalingMissing(Rule):
    id = "COST-003"
    title = "DynamoDB provisioned capacity may miss autoscaling"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Check for provisioned capacity without autoscaling
        provisioned = rg(repo_path, r'billingMode\s*:\s*(dynamodb\.BillingMode\.)?PROVISIONED|readCapacity|writeCapacity', glob=code_glob(language))
        autoscaling = rg(repo_path, r'autoScaleReadCapacity|autoScaleWriteCapacity|auto_scale_read|auto_scale_write', glob=code_glob(language))
        out: List[Finding] = []
        if provisioned and not autoscaling:
            hits = rg(repo_path, r'new\s+(dynamodb\.Table|Table)\(', glob=code_glob(language), max_hits=1)
            if hits:
                f, ln, txt = hits[0]
                out.append(Finding(
                    id=self.id,
                    title=self.title,
                    severity="Low",
                    category=self.category,
                    file=f,
                    line=ln,
                    evidence=txt,
                    recommendation="Enable autoscaling for DynamoDB provisioned capacity to optimize costs during low-traffic periods. In CDK: table.autoScaleReadCapacity() / autoScaleWriteCapacity()",
                ))
        return out


class LambdaProvisionedConcurrency(Rule):
    id = "COST-004"
    title = "Lambda provisioned concurrency may be overprovisioned"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        provisioned = rg(repo_path, r'provisionedConcurrentExecutions|reservedConcurrentExecutions', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in provisioned[:2]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Review Lambda provisioned concurrency settings. Use Application Auto Scaling to adjust based on utilization to reduce costs.",
            ))
        return out


class RdsReservedInstances(Rule):
    id = "COST-005"
    title = "RDS not using Reserved Instances (savings opportunity)"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        dbs = rg(repo_path, rds_pat, glob=code_glob(language))
        out: List[Finding] = []
        if dbs:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="For production RDS instances with steady-state usage, consider Reserved Instances for up to 72% cost savings vs on-demand",
            )]
        return out


class NatGatewayCosts(Rule):
    id = "COST-006"
    title = "NAT Gateway incurs data processing costs"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        nat_pat = r'natGateways\s*:\s*[1-9]|NatProvider\.gateway' if language == "typescript" else r'nat_gateways\s*=\s*[1-9]'
        nats = rg(repo_path, nat_pat, glob=code_glob(language))
        endpoints = rg(repo_path, r'InterfaceVpcEndpoint|GatewayVpcEndpoint', glob=code_glob(language))
        out: List[Finding] = []
        if nats and not endpoints:
            f, ln, txt = nats[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="NAT Gateways charge for data processing ($0.045/GB). Use VPC endpoints for S3, DynamoDB, and other AWS services to reduce costs.",
            ))
        return out


class S3IntelligentTiering(Rule):
    id = "COST-007"
    title = "S3 Intelligent-Tiering not enabled"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        s3_pat = r'new\s+s3\.(Bucket|CfnBucket)\(' if language == "typescript" else r's3\.(Bucket|CfnBucket)\('
        buckets = rg(repo_path, s3_pat, glob=code_glob(language))
        intelligent = rg(repo_path, r'INTELLIGENT_TIERING|IntelligentTiering', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not intelligent:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider S3 Intelligent-Tiering for automatic cost optimization (moves objects between access tiers based on usage)",
            )]
        return out


class EbsGp2ToGp3(Rule):
    id = "COST-008"
    title = "EBS volumes using gp2 instead of gp3"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        gp2 = rg(repo_path, r'EbsDeviceVolumeType\.GP2|gp2', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in gp2[:2]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Migrate EBS volumes from gp2 to gp3 for 20% cost savings and better performance. In CDK: EbsDeviceVolumeType.GP3",
            ))
        return out


class ElastiCacheReservedNodes(Rule):
    id = "COST-009"
    title = "ElastiCache may benefit from reserved nodes"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        elasticache = rg(repo_path, r'elasticache\.(CfnCacheCluster|CfnReplicationGroup)', glob=code_glob(language))
        out: List[Finding] = []
        if elasticache:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="For predictable ElastiCache workloads, consider reserved nodes for up to 55% cost savings vs on-demand",
            )]
        return out


class RdsGraviton(Rule):
    id = "COST-010"
    title = "RDS not using Graviton instances"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        rdss = rg(repo_path, rds_pat, glob=code_glob(language))
        graviton = rg(repo_path, r'\.r7g\.|\.m7g\.|\.t4g\.', glob=code_glob(language))
        out: List[Finding] = []
        if rdss and not graviton:
            f, ln, txt = rdss[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider Graviton-based RDS instances (r7g, m7g, t4g) for up to 35% better price-performance",
            ))
        return out


class CloudFrontPriceClass(Rule):
    id = "COST-011"
    title = "CloudFront using all edge locations (Price Class All)"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cf_pat = r'new\s+cloudfront\.(Distribution|CloudFrontWebDistribution)\(' if language == "typescript" else r'cloudfront\.(Distribution|CloudFrontWebDistribution)\('
        distros = rg(repo_path, cf_pat, glob=code_glob(language))
        price_class = rg(repo_path, r'priceClass.*PRICE_CLASS_(100|200)', glob=code_glob(language))
        out: List[Finding] = []
        if distros and not price_class:
            f, ln, txt = distros[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider CloudFront Price Class 100 or 200 instead of All to reduce costs if global edge coverage is not required. In CDK: priceClass: cloudfront.PriceClass.PRICE_CLASS_100",
            ))
        return out


class UnusedEips(Rule):
    id = "COST-012"
    title = "Elastic IP allocated but may not be used"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        eip = rg(repo_path, r'new\s+ec2\.(CfnEIP|CfnEIPAssociation)\(', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in eip[:2]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Unattached Elastic IPs incur charges. Ensure EIPs are associated with running resources or release them",
            ))
        return out


class S3LifecycleMissing(Rule):
    id = "COST-013"
    title = "S3 lifecycle policy not configured for cost optimization"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        s3_pat = r'new\s+s3\.(Bucket|CfnBucket)\(' if language == "typescript" else r's3\.(Bucket|CfnBucket)\('
        buckets = rg(repo_path, s3_pat, glob=code_glob(language))
        lifecycle = rg(repo_path, r'addLifecycleRule|lifecycleRules', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not lifecycle:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Add S3 lifecycle policies to transition objects to cheaper storage classes (IA, Glacier) or delete old versions. In CDK: bucket.addLifecycleRule()",
            )]
        return out


class AwsBudgetsMissing(Rule):
    id = "COST-014"
    title = "AWS Budgets not configured"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        budgets = rg(repo_path, r'budgets\.CfnBudget|CfnBudget', glob=code_glob(language))
        if not budgets:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Configure AWS Budgets for cost monitoring and alerts. Consider budget alerts at 80% and 100%.",
            )]
        return []


class CostAllocationTags(Rule):
    id = "COST-015"
    title = "Cost allocation tags may not be configured"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        tags = rg(repo_path, r'tags\s*:|tags\s*=', glob=code_glob(language))
        cost_tags = rg(repo_path, r'CostCenter|cost-center|Project|Environment', glob=code_glob(language))
        out: List[Finding] = []
        if tags and not cost_tags:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Add cost allocation tags (CostCenter, Project, Environment) for AWS Cost Explorer and billing reports.",
            )]
        return out


class SavingsPlansOpportunity(Rule):
    id = "COST-016"
    title = "Savings Plans opportunity for compute workloads"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = rg(repo_path, r'FargateService|Ec2Service|ec2\.Instance|lambda\.Function', glob=code_glob(language))
        if compute:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="For steady-state compute, consider Compute or EC2 Instance Savings Plans for up to 66% savings.",
            )]
        return []


class LambdaPowerTuning(Rule):
    id = "COST-017"
    title = "Lambda memory/CPU may not be optimized"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+(lambda\.Function|NodejsFunction|PythonFunction)\(' if language == "typescript" else r'(lambda_.Function|aws_lambda.Function)\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        memory = rg(repo_path, r'memorySize\s*:\s*\d+', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not memory:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Use AWS Lambda Power Tuning to find optimal memory/CPU configuration for cost and performance.",
            )]
        return out


class S3StorageLens(Rule):
    id = "COST-018"
    title = "S3 Storage Lens not enabled"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        buckets = rg(repo_path, r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\(', glob=code_glob(language))
        storage_lens = rg(repo_path, r'StorageLens|CfnStorageLens', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not storage_lens:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Enable S3 Storage Lens for storage optimization insights and cost analysis.",
            )]
        return out
