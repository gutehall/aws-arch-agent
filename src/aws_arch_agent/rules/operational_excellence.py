"""Operational Excellence pillar: CloudTrail, Flow Logs, audit."""
from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class CloudTrailMissing(Rule):
    id = "OPS-001"
    title = "CloudTrail / audit trail may be missing"
    category = "Operational Excellence"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        trail_pat = r"cloudtrail\.(Trail|CfnTrail)|CloudTrail|aws_cloudtrail" if language == "typescript" else r"cloudtrail|CloudTrail|aws_cloudtrail"
        trails = rg(repo_path, trail_pat, glob=code_glob(language))
        if not trails:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling CloudTrail for API audit and security analysis.",
            )]
        return []


class VpcFlowLogsMissing(Rule):
    id = "OPS-002"
    title = "VPC Flow Logs may be missing"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        vpc_pat = r"new\s+ec2\.Vpc\(" if language == "typescript" else r"ec2\.Vpc\("
        flow_pat = r"FlowLog|flow_log|FlowLogDestination"
        vpcs = rg(repo_path, vpc_pat, glob=code_glob(language))
        flow_logs = rg(repo_path, flow_pat, glob=code_glob(language))
        if vpcs and not flow_logs:
            f, ln, txt = vpcs[0]
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider VPC Flow Logs for network troubleshooting and security analysis.",
            )]
        return []


class XRayTracingMissing(Rule):
    id = "OPS-003"
    title = "X-Ray / distributed tracing may be missing"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if language == "typescript":
            api_pat = r"apigateway\.(RestApi|HttpApi)|new\s+apigateway\.|ApiGateway"
            lambda_pat = r"lambda\.Function|new\s+lambda\.Function"
            tracing_pat = r"TracingConfig|tracing\.ACTIVE|activeTracing|X-Ray|xray|DataTraceEnabled"
        else:
            api_pat = r"apigateway\.(RestApi|HttpApi)|aws_apigateway|ApiGateway"
            lambda_pat = r"lambda_.*Function|aws_lambda"
            tracing_pat = r"tracing|TracingConfig|xray|X-Ray|data_trace"
        apis = rg(repo_path, api_pat, glob=code_glob(language))
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        tracing_refs = rg(repo_path, tracing_pat, glob=code_glob(language))
        if (apis or lambdas) and not tracing_refs:
            evidence = None
            if apis:
                evidence = apis[0][2]
            elif lambdas:
                evidence = lambdas[0][2]
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=evidence,
                recommendation="Enable X-Ray or distributed tracing (Lambda TracingConfig, API Gateway DataTraceEnabled) for observability.",
            )]
        return []


class DynamoDbStreamsMissing(Rule):
    id = "OPS-004"
    title = "DynamoDB table may benefit from streams for event-driven patterns"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ddb_pat = r'new\s+(dynamodb\.Table|Table)\(' if language == "typescript" else r'(dynamodb.Table|aws_dynamodb.Table)\('
        tables = rg(repo_path, ddb_pat, glob=code_glob(language))
        streams = rg(repo_path, r'stream\s*:\s*(StreamViewType|dynamodb\.StreamViewType)|stream_view_type', glob=code_glob(language))
        out: List[Finding] = []
        if tables and not streams:
            f, ln, txt = tables[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider enabling DynamoDB Streams for event-driven patterns, change data capture, or cross-region replication. In CDK: stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES",
            ))
        return out


class ApiGatewayAccessLogs(Rule):
    id = "OPS-005"
    title = "API Gateway access logging not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        api_pat = r'new\s+(apigateway\.(RestApi|HttpApi|Stage)|RestApi|HttpApi)\(' if language == "typescript" else r'(apigateway\.(RestApi|HttpApi|Stage)|RestApi|HttpApi)\('
        apis = rg(repo_path, api_pat, glob=code_glob(language))
        logs = rg(repo_path, r'accessLogDestination|accessLogFormat|deployOptions.*accessLog', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not logs:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable access logging for API Gateway for audit and troubleshooting. In CDK: accessLogDestination and accessLogFormat",
            ))
        return out


class AlbAccessLogs(Rule):
    id = "OPS-006"
    title = "ALB/NLB access logs not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alb_pat = r'new\s+elbv2\.(ApplicationLoadBalancer|NetworkLoadBalancer)\(' if language == "typescript" else r'elbv2\.(ApplicationLoadBalancer|NetworkLoadBalancer)\('
        albs = rg(repo_path, alb_pat, glob=code_glob(language))
        logs = rg(repo_path, r'logAccessLogs|accessLogging', glob=code_glob(language))
        out: List[Finding] = []
        if albs and not logs:
            f, ln, txt = albs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable access logs for ALB/NLB to S3 for audit and troubleshooting. In CDK: logAccessLogs(bucket)",
            ))
        return out


class CloudFrontAccessLogs(Rule):
    id = "OPS-007"
    title = "CloudFront access logging not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cf_pat = r'new\s+cloudfront\.(Distribution|CloudFrontWebDistribution)\(' if language == "typescript" else r'cloudfront\.(Distribution|CloudFrontWebDistribution)\('
        distros = rg(repo_path, cf_pat, glob=code_glob(language))
        logs = rg(repo_path, r'loggingConfig|enableLogging|logBucket', glob=code_glob(language))
        out: List[Finding] = []
        if distros and not logs:
            f, ln, txt = distros[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable access logging for CloudFront to S3. In CDK: enableLogging with logBucket",
            ))
        return out


class EcsContainerInsights(Rule):
    id = "OPS-008"
    title = "ECS container insights not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cluster_pat = r'new\s+ecs\.Cluster\(' if language == "typescript" else r'ecs\.Cluster\('
        clusters = rg(repo_path, cluster_pat, glob=code_glob(language))
        insights = rg(repo_path, r'containerInsights\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if clusters and not insights:
            f, ln, txt = clusters[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable Container Insights for ECS clusters for better observability. In CDK: containerInsights: true",
            ))
        return out


class RdsEnhancedMonitoring(Rule):
    id = "OPS-009"
    title = "RDS enhanced monitoring not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        dbs = rg(repo_path, rds_pat, glob=code_glob(language))
        monitoring = rg(repo_path, r'monitoringInterval\s*:\s*Duration|enableEnhancedMonitoring', glob=code_glob(language))
        out: List[Finding] = []
        if dbs and not monitoring:
            f, ln, txt = dbs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable enhanced monitoring for RDS for detailed OS-level metrics. In CDK: monitoringInterval: Duration.seconds(60)",
            ))
        return out


class CloudWatchAlarmsMissing(Rule):
    id = "OPS-010"
    title = "CloudWatch alarms not configured for critical resources"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        resources = rg(repo_path, r'DatabaseInstance|ApplicationLoadBalancer|lambda\.Function|DynamoDB', glob=code_glob(language))
        alarms = rg(repo_path, r'new\s+cloudwatch\.Alarm\(|Alarm\(|metricAlarm', glob=code_glob(language))
        out: List[Finding] = []
        if resources and not alarms:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Configure CloudWatch alarms for critical resources (CPU, memory, errors, latency) to detect issues early",
            )]
        return out


class SnsAlarmNotifications(Rule):
    id = "OPS-011"
    title = "No SNS topics for alarm notifications"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alarms = rg(repo_path, r'new\s+cloudwatch\.Alarm\(', glob=code_glob(language))
        sns_action = rg(repo_path, r'addAlarmAction|SnsAction', glob=code_glob(language))
        out: List[Finding] = []
        if alarms and not sns_action:
            f, ln, txt = alarms[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure SNS topics for CloudWatch alarm notifications to alert teams. In CDK: alarm.addAlarmAction(new SnsAction(topic))",
            ))
        return out


class StepFunctionsXRay(Rule):
    id = "OPS-012"
    title = "Step Functions not using X-Ray tracing"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sfn_pat = r'new\s+sfn\.StateMachine\(' if language == "typescript" else r'sfn\.StateMachine\('
        sfns = rg(repo_path, sfn_pat, glob=code_glob(language))
        xray = rg(repo_path, r'tracingEnabled\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if sfns and not xray:
            f, ln, txt = sfns[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable X-Ray tracing for Step Functions for better observability. In CDK: tracingEnabled: true",
            ))
        return out


class EventBridgeDlq(Rule):
    id = "OPS-013"
    title = "EventBridge rules not using DLQ"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rule_pat = r'new\s+events\.Rule\(' if language == "typescript" else r'events\.Rule\('
        rules = rg(repo_path, rule_pat, glob=code_glob(language))
        dlq = rg(repo_path, r'deadLetterQueue\s*:|retryPolicy', glob=code_glob(language))
        out: List[Finding] = []
        if rules and not dlq:
            f, ln, txt = rules[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure dead-letter queue for EventBridge rules to capture failed events. In CDK: deadLetterQueue property",
            ))
        return out


class ConfigNotEnabled(Rule):
    id = "OPS-014"
    title = "AWS Config not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        config = rg(repo_path, r'config\.CfnConfigurationRecorder|aws_config', glob=code_glob(language))
        if not config:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling AWS Config for resource configuration tracking and compliance",
            )]
        return []


class GlueJobMetrics(Rule):
    id = "OPS-015"
    title = "Glue job CloudWatch metrics not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glue_pat = r'new\s+glue\.(Job|CfnJob)\(' if language == "typescript" else r'glue\.(Job|CfnJob)\('
        jobs = rg(repo_path, glue_pat, glob=code_glob(language))
        metrics = rg(repo_path, r'--enable-metrics|enableMetrics', glob=code_glob(language))
        out: List[Finding] = []
        if jobs and not metrics:
            f, ln, txt = jobs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable CloudWatch metrics for Glue jobs for better monitoring. Add --enable-metrics to job parameters",
            ))
        return out


class TransitGatewayFlowLogs(Rule):
    id = "OPS-016"
    title = "Transit Gateway flow logs not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        tgw_pat = r'new\s+ec2\.(CfnTransitGateway|TransitGateway)\(' if language == "typescript" else r'ec2\.(CfnTransitGateway|TransitGateway)\('
        tgws = rg(repo_path, tgw_pat, glob=code_glob(language))
        flow = rg(repo_path, r'FlowLog.*TransitGateway', glob=code_glob(language))
        out: List[Finding] = []
        if tgws and not flow:
            f, ln, txt = tgws[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable flow logs for Transit Gateway for network monitoring and troubleshooting",
            ))
        return out


class CodePipelineNotifications(Rule):
    id = "OPS-017"
    title = "CodePipeline notifications not configured"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pipeline_pat = r'new\s+codepipeline\.(Pipeline|CfnPipeline)\(' if language == "typescript" else r'codepipeline\.(Pipeline|CfnPipeline)\('
        pipelines = rg(repo_path, pipeline_pat, glob=code_glob(language))
        notifications = rg(repo_path, r'notifyOn|onStateChange', glob=code_glob(language))
        out: List[Finding] = []
        if pipelines and not notifications:
            f, ln, txt = pipelines[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure notifications for CodePipeline state changes (success, failure). In CDK: onStateChange() or notifyOn()",
            ))
        return out


class AppRunnerObservability(Rule):
    id = "OPS-018"
    title = "App Runner observability not configured"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        apprunner_pat = r'new\s+apprunner\.(Service|CfnService)\(' if language == "typescript" else r'apprunner\.(Service|CfnService)\('
        services = rg(repo_path, apprunner_pat, glob=code_glob(language))
        observability = rg(repo_path, r'observabilityConfiguration|tracing', glob=code_glob(language))
        out: List[Finding] = []
        if services and not observability:
            f, ln, txt = services[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable observability for App Runner services (X-Ray tracing). Configure observabilityConfiguration",
            ))
        return out


class GlueJobBookmarks(Rule):
    id = "OPS-019"
    title = "Glue job bookmarks not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glue_pat = r'new\s+glue\.(Job|CfnJob)\(' if language == "typescript" else r'glue\.(Job|CfnJob)\('
        jobs = rg(repo_path, glue_pat, glob=code_glob(language))
        bookmarks = rg(repo_path, r'--job-bookmark-option.*enabled|jobBookmarksEncryption', glob=code_glob(language))
        out: List[Finding] = []
        if jobs and not bookmarks:
            f, ln, txt = jobs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable job bookmarks for Glue to track processed data and prevent reprocessing. Add --job-bookmark-option enabled",
            ))
        return out


class CodeBuildLogging(Rule):
    id = "OPS-020"
    title = "CodeBuild project logging not configured"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        codebuild_pat = r'new\s+codebuild\.(Project|PipelineProject)\(' if language == "typescript" else r'codebuild\.(Project|PipelineProject)\('
        projects = rg(repo_path, codebuild_pat, glob=code_glob(language))
        logging = rg(repo_path, r'logging\s*:|cloudWatchLogs|s3Logs', glob=code_glob(language))
        out: List[Finding] = []
        if projects and not logging:
            f, ln, txt = projects[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure logging for CodeBuild projects (CloudWatch Logs or S3). In CDK: logging property",
            ))
        return out


class CloudWatchDashboardMissing(Rule):
    id = "OPS-021"
    title = "CloudWatch dashboards not configured"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        resources = rg(repo_path, r'DatabaseInstance|ApplicationLoadBalancer|lambda\.Function|FargateService', glob=code_glob(language))
        dashboards = rg(repo_path, r'new\s+cloudwatch\.Dashboard\(|Dashboard\(', glob=code_glob(language))
        out: List[Finding] = []
        if resources and not dashboards:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Create CloudWatch dashboards for key metrics to improve operational visibility.",
            )]
        return out


class ResourceTaggingStrategy(Rule):
    id = "OPS-022"
    title = "Resource tagging strategy may be incomplete"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        tags = rg(repo_path, r'tags\s*:\s*\{|tags\s*=\s*\{', glob=code_glob(language))
        cost_center = rg(repo_path, r'CostCenter|cost_center|CostCenter', glob=code_glob(language))
        project = rg(repo_path, r'Project|project', glob=code_glob(language))
        out: List[Finding] = []
        if tags and not (cost_center or project):
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider adding CostCenter and Project tags for cost allocation and resource management.",
            )]
        return out


class SsmParameterAdvancedTier(Rule):
    id = "OPS-023"
    title = "SSM Parameter Store not using advanced tier for high throughput"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        param_pat = r'new\s+ssm\.(StringParameter|CfnParameter)\(' if language == "typescript" else r'ssm\.(StringParameter|CfnParameter)\('
        params = rg(repo_path, param_pat, glob=code_glob(language))
        advanced = rg(repo_path, r'parameterTier.*ADVANCED|advanced|tier.*Advanced', glob=code_glob(language))
        out: List[Finding] = []
        if params and not advanced:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="For high-throughput (>10 TPS) parameter access, consider Parameter Store advanced tier.",
            )]
        return out


class LambdaReservedConcurrencyHint(Rule):
    id = "OPS-024"
    title = "Lambda function may benefit from reserved concurrency"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+(lambda\.Function|NodejsFunction|PythonFunction)\(' if language == "typescript" else r'(lambda_.Function|aws_lambda.Function)\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        reserved = rg(repo_path, r'reservedConcurrentExecutions|reserved_concurrent_executions', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not reserved:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider reserved concurrency for critical latency-sensitive functions.",
            )]
        return out


class S3ReplicationMetrics(Rule):
    id = "OPS-025"
    title = "S3 replication metrics not enabled"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        replication = rg(repo_path, r'replicationRule|replicationConfiguration|ReplicationRule', glob=code_glob(language))
        metrics = rg(repo_path, r'ReplicationTime|replicationMetrics|metrics', glob=code_glob(language))
        out: List[Finding] = []
        if replication and not metrics:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Enable S3 replication metrics for monitoring replication status.",
            )]
        return out
