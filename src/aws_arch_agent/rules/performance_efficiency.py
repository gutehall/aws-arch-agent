"""Performance Efficiency pillar: caching, compute choice, scaling."""
from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.rules.scope import findings_for_unmatched
from aws_arch_agent.tools.rg import rg

# Request path that benefits from a cache. A bucket or queue does not.
_CACHE_WORKLOAD = (
    r"(?:aws_)?apigateway\.(?:RestApi|HttpApi|LambdaRestApi)\(|"
    r"apigwv2\.HttpApi\(|(?:aws_)?apigatewayv2\.HttpApi\(|"
    r"elbv2\.ApplicationLoadBalancer\(|"
    r"aws_elasticloadbalancingv2\.ApplicationLoadBalancer\(|"
    r"ApplicationLoadBalancedFargateService\("
)
_CACHE_LAYER = (
    r"(?:aws_)?cloudfront\.Distribution|CloudFrontWebDistribution|"
    r"(?:aws_)?elasticache\.|\bElastiCache\b|\bRedis\b|\bMemcached\b|"
    r"cachingEnabled|cache_cluster_enabled|(?:aws_)?dax\.Cluster"
)


_RDS_CONSTRUCT = r"rds\.(?:DatabaseInstance|DatabaseCluster|DatabaseInstanceFromSnapshot|DatabaseClusterFromSnapshot|DatabaseInstanceReadReplica|ClusterInstance)\b"


class GravitonNotUsed(Rule):
    id = "PERF-001"
    title = "Compute may not use Graviton/ARM (cost and performance)"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Consider Graviton/ARM (e.g. Lambda ARM64, ECS arm64) for better price-performance. In "
        "CDK Lambda: architecture: lambda.Architecture.ARM_64"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Lambda: ARCH_ARM64; EC2/ECS: arm64, graviton
        graviton = rg(repo_path, r"ARM64|arm64|architecture.*arm|Graviton|graviton|Architecture\.ARM_64", glob=code_glob(language))
        # Updated to include NodejsFunction, PythonFunction, etc.
        compute = rg(repo_path, r"(lambda\.Function|NodejsFunction|PythonFunction|DockerImageFunction|ec2\.Instance|FargateService|Ec2Service)", glob=code_glob(language))
        if compute and not graviton:
            f, ln, txt = compute[0]
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            )]
        return []


class CachingHint(Rule):
    id = "PERF-002"
    title = "No caching layer detected (performance)"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = "This API or load balancer has no CloudFront, ElastiCache, API cache, or DAX."

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glob = code_glob(language)
        workloads = rg(repo_path, _CACHE_WORKLOAD, glob=glob)
        caches = rg(repo_path, _CACHE_LAYER, glob=glob)
        return findings_for_unmatched(
            self,
            workloads,
            caches,
            self.recommendation,
        )


class ApiGatewayCaching(Rule):
    id = "PERF-004"
    title = "API Gateway caching not enabled"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Enable API Gateway caching to reduce latency and backend load. In CDK: cachingEnabled: "
        "true with cacheClusterSize"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        api_pat = r'new\s+(apigateway\.(RestApi|Stage)|RestApi)\(' if language == "typescript" else r'(apigateway\.(RestApi|Stage)|RestApi)\('
        apis = rg(repo_path, api_pat, glob=code_glob(language))
        caching = rg(repo_path, r'cachingEnabled|cacheClusterEnabled', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not caching:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out


class CloudFrontCaching(Rule):
    id = "PERF-006"
    title = "CloudFront caching strategy not optimized"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Configure CloudFront caching with appropriate TTLs and cache policies. In CDK: "
        "defaultBehavior.cachePolicy"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cf_pat = r'new\s+cloudfront\.(Distribution|CloudFrontWebDistribution)\(' if language == "typescript" else r'cloudfront\.(Distribution|CloudFrontWebDistribution)\('
        distros = rg(repo_path, cf_pat, glob=code_glob(language))
        caching = rg(repo_path, r'cachePolicyId|CachePolicy|defaultTtl|maxTtl', glob=code_glob(language))
        out: List[Finding] = []
        if distros and not caching:
            f, ln, txt = distros[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out


class EcsTaskSizing(Rule):
    id = "PERF-007"
    title = "ECS task sizing (CPU/memory) may need review"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Set appropriate CPU and memory for ECS tasks based on workload requirements. In CDK: cpu"
        " and memoryLimitMiB"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        task_pat = r'new\s+ecs\.(FargateTaskDefinition|Ec2TaskDefinition)\(' if language == "typescript" else r'ecs\.(FargateTaskDefinition|Ec2TaskDefinition)\('
        tasks = rg(repo_path, task_pat, glob=code_glob(language))
        sizing = rg(repo_path, r'cpu\s*:\s*\d+|memory\s*:\s*["\']?\d+', glob=code_glob(language))
        out: List[Finding] = []
        if tasks and not sizing:
            f, ln, txt = tasks[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out


class RdsInstanceSizing(Rule):
    id = "PERF-008"
    title = "RDS instance class may be oversized"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Review RDS instance class against actual workload metrics (CPU, memory, IOPS). Consider "
        "right-sizing to reduce costs."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Large instance classes, in files that define an RDS instance or cluster: an EC2 or
        # cache instance type is not an RDS class (CF-PERF-003 reads the same on DBInstanceClass).
        glob = code_glob(language)
        rds_files = {f for f, _ln, _txt in rg(repo_path, _RDS_CONSTRUCT, glob=glob, max_hits=10_000)}
        large_instances = [
            hit for hit in rg(repo_path, r'instanceType.*\.(xlarge|2xlarge|4xlarge|8xlarge|12xlarge|16xlarge)', glob=glob,
               max_hits=10_000)
            if hit[0] in rds_files
        ]
        out: List[Finding] = []
        for f, ln, txt in large_instances[:2]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out


class GlobalAcceleratorOptimization(Rule):
    id = "PERF-011"
    title = "Global Accelerator not used for global traffic"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Consider AWS Global Accelerator for global applications to reduce latency (up to 60% "
        "improvement)"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Answered by the usage file (rules/usage_signals.py); quiet when it states nothing.
        from aws_arch_agent.rules import usage_signals

        return usage_signals.global_accelerator(self, repo_path)


class AppSyncCaching(Rule):
    id = "PERF-013"
    title = "AppSync API caching not enabled"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Enable caching for AppSync APIs to reduce latency and backend load. Configure "
        "cachingConfig"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        appsync_pat = r'new\s+appsync\.(GraphqlApi|CfnGraphQLApi)\(' if language == "typescript" else r'appsync\.(GraphqlApi|CfnGraphQLApi)\('
        apis = rg(repo_path, appsync_pat, glob=code_glob(language))
        caching = rg(repo_path, r'cachingConfig|apiCachingBehavior', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not caching:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out


class S3TransferAcceleration(Rule):
    id = "PERF-014"
    title = "S3 Transfer Acceleration not enabled for global uploads"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Consider S3 Transfer Acceleration for faster uploads from geographically dispersed users"
        " (50-500% faster)"
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Answered by the usage file (rules/usage_signals.py); quiet when it states nothing.
        from aws_arch_agent.rules import usage_signals

        return usage_signals.transfer_acceleration(self, repo_path)


class LambdaSnapStart(Rule):
    id = "PERF-015"
    title = "Lambda SnapStart not enabled for Java functions"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Enable Lambda SnapStart for Java functions to reduce cold start latency by up to 10x."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        java_lambda = rg(repo_path, r'Runtime\.JAVA|runtime.*java|JAVA_\d+', glob=code_glob(language))
        snapstart = rg(repo_path, r'snapStart|snap_start', glob=code_glob(language))
        out: List[Finding] = []
        if java_lambda and not snapstart:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation=self.recommendation,
            )]
        return out


