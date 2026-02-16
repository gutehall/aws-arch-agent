"""Performance Efficiency pillar: caching, compute choice, scaling."""
from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class GravitonNotUsed(Rule):
    id = "PERF-001"
    title = "Compute may not use Graviton/ARM (cost and performance)"
    category = "Performance Efficiency"
    severity = "Low"

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
                recommendation="Consider Graviton/ARM (e.g. Lambda ARM64, ECS arm64) for better price-performance. In CDK Lambda: architecture: lambda.Architecture.ARM_64",
            )]
        return []


class CachingHint(Rule):
    id = "PERF-002"
    title = "No caching layer detected (performance)"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Check for caching layers including DynamoDB (which can act as cache), CloudFront, ElastiCache, API Gateway caching
        cache = rg(repo_path, r"CloudFront|Distribution|ElastiCache|Redis|Memcached|(dynamodb\.Table|Table)\(|api\.(RestApi|HttpApi)", glob=code_glob(language))
        if not cache:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider CloudFront, ElastiCache, DynamoDB, or API caching for latency and efficiency.",
            )]
        return []


class DynamoDbProvisionedCapacity(Rule):
    id = "PERF-003"
    title = "DynamoDB table may use provisioned capacity (consider on-demand)"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ddb_pat = r'new\s+(dynamodb\.Table|Table)\(' if language == "typescript" else r'(dynamodb.Table|aws_dynamodb.Table)\('
        tables = rg(repo_path, ddb_pat, glob=code_glob(language))
        # Check for PROVISIONED billing mode
        provisioned = rg(repo_path, r'billingMode\s*:\s*(dynamodb\.BillingMode\.)?PROVISIONED|readCapacity|writeCapacity', glob=code_glob(language))
        on_demand = rg(repo_path, r'billingMode\s*:\s*(dynamodb\.BillingMode\.)?PAY_PER_REQUEST', glob=code_glob(language))
        out: List[Finding] = []
        # If tables exist and using provisioned (or not specified which defaults to provisioned)
        if tables and (provisioned or not on_demand):
            f, ln, txt = tables[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider PAY_PER_REQUEST (on-demand) billing for unpredictable workloads to optimize cost and eliminate capacity planning. In CDK: billingMode: dynamodb.BillingMode.PAY_PER_REQUEST",
            ))
        return out


class ApiGatewayCaching(Rule):
    id = "PERF-004"
    title = "API Gateway caching not enabled"
    category = "Performance Efficiency"
    severity = "Low"

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
                recommendation="Enable API Gateway caching to reduce latency and backend load. In CDK: cachingEnabled: true with cacheClusterSize",
            ))
        return out


class LambdaMemoryOptimization(Rule):
    id = "PERF-005"
    title = "Lambda memory not optimized (too low/high)"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+(lambda\.Function|NodejsFunction|PythonFunction|DockerImageFunction)\(' if language == "typescript" else r'(lambda_.Function|aws_lambda_python_alpha.PythonFunction|aws_lambda.Function)\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        memory = rg(repo_path, r'memorySize\s*:\s*\d+', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not memory:
            f, ln, txt = lambdas[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set appropriate Lambda memory size (128-10240 MB). Use Lambda Power Tuning to find optimal value. In CDK: memorySize: 1024",
            ))
        return out


class CloudFrontCaching(Rule):
    id = "PERF-006"
    title = "CloudFront caching strategy not optimized"
    category = "Performance Efficiency"
    severity = "Low"

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
                recommendation="Configure CloudFront caching with appropriate TTLs and cache policies. In CDK: defaultBehavior.cachePolicy",
            ))
        return out


class EcsTaskSizing(Rule):
    id = "PERF-007"
    title = "ECS task sizing (CPU/memory) may need review"
    category = "Performance Efficiency"
    severity = "Low"

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
                recommendation="Set appropriate CPU and memory for ECS tasks based on workload requirements. In CDK: cpu and memoryLimitMiB",
            ))
        return out


class RdsInstanceSizing(Rule):
    id = "PERF-008"
    title = "RDS instance class may be oversized"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Look for large instance classes
        large_instances = rg(repo_path, r'instanceType.*\.(xlarge|2xlarge|4xlarge|8xlarge|12xlarge|16xlarge)', glob=code_glob(language))
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
                recommendation="Review RDS instance class against actual workload metrics (CPU, memory, IOPS). Consider right-sizing to reduce costs.",
            ))
        return out


class KinesisEnhancedFanout(Rule):
    id = "PERF-009"
    title = "Kinesis enhanced fan-out not used"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kinesis_consumer = rg(repo_path, r'StreamConsumer|registerStreamConsumer', glob=code_glob(language))
        streams = rg(repo_path, r'new\s+kinesis\.(Stream|CfnStream)\(', glob=code_glob(language))
        out: List[Finding] = []
        if streams and not kinesis_consumer:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enhanced fan-out for Kinesis consumers with high throughput requirements (dedicated throughput per consumer)",
            )]
        return out


class OpenSearchInstanceTypes(Rule):
    id = "PERF-010"
    title = "OpenSearch instance types not optimized"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        os_pat = r'new\s+opensearch\.(Domain|CfnDomain)\(' if language == "typescript" else r'opensearch\.(Domain|CfnDomain)\('
        domains = rg(repo_path, os_pat, glob=code_glob(language))
        optimized = rg(repo_path, r'r6g\.|c6g\.|i3\.|r5\.', glob=code_glob(language))
        out: List[Finding] = []
        if domains and not optimized:
            f, ln, txt = domains[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider current-gen instance types for OpenSearch (r6g/c6g for Graviton, i3 for storage, r5 for memory)",
            ))
        return out


class GlobalAcceleratorOptimization(Rule):
    id = "PERF-011"
    title = "Global Accelerator not used for global traffic"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alb_pat = r'new\s+elbv2\.(ApplicationLoadBalancer|NetworkLoadBalancer)\(' if language == "typescript" else r'elbv2\.(ApplicationLoadBalancer|NetworkLoadBalancer)\('
        lbs = rg(repo_path, alb_pat, glob=code_glob(language))
        ga = rg(repo_path, r'globalaccelerator\.(Accelerator|CfnAccelerator)', glob=code_glob(language))
        out: List[Finding] = []
        if lbs and not ga:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider AWS Global Accelerator for global applications to reduce latency (up to 60% improvement)",
            )]
        return out


class EfsPerformanceMode(Rule):
    id = "PERF-012"
    title = "EFS performance mode not configured"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        efs_pat = r'new\s+efs\.FileSystem\(' if language == "typescript" else r'efs\.FileSystem\('
        filesystems = rg(repo_path, efs_pat, glob=code_glob(language))
        perf = rg(repo_path, r'performanceMode.*MAX_IO|throughputMode.*PROVISIONED', glob=code_glob(language))
        out: List[Finding] = []
        if filesystems and not perf:
            f, ln, txt = filesystems[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure EFS performance mode (generalPurpose vs maxIO) and throughput mode based on workload. Consider PROVISIONED for consistent high throughput",
            ))
        return out


class AppSyncCaching(Rule):
    id = "PERF-013"
    title = "AppSync API caching not enabled"
    category = "Performance Efficiency"
    severity = "Low"

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
                recommendation="Enable caching for AppSync APIs to reduce latency and backend load. Configure cachingConfig",
            ))
        return out


class S3TransferAcceleration(Rule):
    id = "PERF-014"
    title = "S3 Transfer Acceleration not enabled for global uploads"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        s3_pat = r'new\s+s3\.(Bucket|CfnBucket)\(' if language == "typescript" else r's3\.(Bucket|CfnBucket)\('
        buckets = rg(repo_path, s3_pat, glob=code_glob(language))
        acceleration = rg(repo_path, r'transferAcceleration.*true', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not acceleration:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider S3 Transfer Acceleration for faster uploads from geographically dispersed users (50-500% faster)",
            )]
        return out


class LambdaSnapStart(Rule):
    id = "PERF-015"
    title = "Lambda SnapStart not enabled for Java functions"
    category = "Performance Efficiency"
    severity = "Low"

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
                recommendation="Enable Lambda SnapStart for Java functions to reduce cold start latency by up to 10x.",
            )]
        return out


class AuroraIoOptimized(Rule):
    id = "PERF-016"
    title = "Aurora not using I/O-Optimized for high I/O workloads"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        aurora = rg(repo_path, r'DatabaseInstance|DatabaseCluster|rds\.', glob=code_glob(language))
        io_optimized = rg(repo_path, r'ioOptimized|storageType.*aurora-io', glob=code_glob(language))
        out: List[Finding] = []
        if aurora and not io_optimized:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider Aurora I/O-Optimized for workloads with high I/O requirements.",
            )]
        return out


class EbsIo2BlockExpress(Rule):
    id = "PERF-017"
    title = "EBS io2 Block Express not used for high IOPS"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ebs = rg(repo_path, r'EbsDeviceVolumeType|volume_type|gp3|io1', glob=code_glob(language))
        io2 = rg(repo_path, r'io2|IO2', glob=code_glob(language))
        out: List[Finding] = []
        if ebs and not io2:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="For workloads requiring >64K IOPS, consider io2 Block Express volumes.",
            )]
        return out


class CloudWatchContributorInsights(Rule):
    id = "PERF-018"
    title = "CloudWatch Contributor Insights not enabled"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        dynamodb = rg(repo_path, r'dynamodb\.Table|DynamoDB', glob=code_glob(language))
        contributor = rg(repo_path, r'ContributorInsights|contributorInsights', glob=code_glob(language))
        out: List[Finding] = []
        if dynamodb and not contributor:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Enable Contributor Insights for DynamoDB to identify top contributors to consumed capacity.",
            )]
        return out


class RdsProxyMissing(Rule):
    id = "PERF-019"
    title = "RDS Proxy not used for connection pooling"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds = rg(repo_path, r'rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\(', glob=code_glob(language))
        proxy = rg(repo_path, r'DatabaseProxy|DatabaseProxyBase', glob=code_glob(language))
        out: List[Finding] = []
        if rds and not proxy:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider RDS Proxy for database connection pooling when using serverless (Lambda).",
            )]
        return out
