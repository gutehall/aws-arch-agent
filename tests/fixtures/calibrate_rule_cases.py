"""Calibrate rule_cases.json by probing each rule against candidate snippets."""
from __future__ import annotations

import inspect
import json
import re
import tempfile
from pathlib import Path

from aws_arch_agent.rules.registry import ALL_RULES

OUT = Path(__file__).parent / "rule_cases.json"

# Verified snippets from tests/test_rules*.py and rule heuristics.
KNOWN: dict[str, dict[str, str]] = {
    "SEC-001": {"positive_ts": 'Action: "*" ', "negative_ts": 'const policy = { actions: ["s3:GetObject"], resources: ["arn:aws:s3:::bucket/*"] }'},
    "SEC-002": {"positive_ts": 'Resource: "*"', "negative_ts": 'resources: ["arn:aws:s3:::bucket/*"]'},
    "SEC-003": {"positive_ts": "connections.allowFrom(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));", "negative_ts": "// clean"},
    "SEC-004": {"positive_ts": "sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(3306));", "negative_ts": "// clean"},
    "SEC-005": {"positive_ts": 'new s3.Bucket(this, "B");', "negative_ts": "blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL"},
    "SEC-006": {"positive_ts": 'new s3.Bucket(this, "B");', "negative_ts": "encryption: s3.BucketEncryption.S3_MANAGED"},
    "SEC-007": {"positive_ts": "key.addToResourcePolicy(new iam.PolicyStatement({ Principal: '*', Action: 'kms:*' }));", "negative_ts": "Principal: { AWS: 'arn:aws:iam::123:root' }"},
    "SEC-008": {"positive_ts": "new dynamodb.Table(this, 'T', { partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING } });", "negative_ts": "encryption: dynamodb.TableEncryption.AWS_MANAGED"},
    "SEC-009": {"positive_ts": "new apigateway.RestApi(this, 'Api');", "negative_ts": "authorizer: cognitoAuthorizer"},
    "SEC-010": {"positive_ts": "new apigateway.RestApi(this, 'Api');", "negative_ts": "securityPolicy: apigateway.SecurityPolicy.TLS_1_2"},
    "SEC-011": {"positive_ts": "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });", "negative_ts": "redirect: true"},
    "SEC-012": {"positive_ts": "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });", "negative_ts": "sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS"},
    "SEC-013": {"positive_ts": "new sqs.Queue(this, 'Q');", "negative_ts": "encryption: sqs.QueueEncryption.KMS_MANAGED"},
    "SEC-014": {"positive_ts": "new sns.Topic(this, 'T');", "negative_ts": "masterKey: kmsKey"},
    "SEC-016": {"positive_ts": 'const access_key = "AKIAIOSFODNN7EXAMPLE";', "negative_ts": "// clean"},
    "SEC-057": {"positive_ts": "fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });", "negative_ts": "authType: lambda.FunctionUrlAuthType.AWS_IAM"},
    "SEC-064": {"positive_ts": "new rds.DatabaseInstance(this, 'DB', { engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_15 }), vpc });", "negative_ts": "publiclyAccessible: false"},
    "BP-001": {"positive_ts": "export class Stack {};", "negative_ts": "tags: { Environment: 'prod' }"},
    "REL-001": {"positive_ts": 'new rds.DatabaseInstance(this, "DB", { instanceIdentifier: "db", engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0 }) });', "negative_ts": "multiAz: true"},
    "REL-002": {"positive_ts": 'new rds.DatabaseInstance(this, "DB", { engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0 }) });', "negative_ts": "backupRetention: Duration.days(7)"},
    "REL-003": {"positive_ts": 'new lambda.Function(this, "Fn", { runtime: lambda.Runtime.NODEJS_18_X, handler: "index.handler", code: lambda.Code.fromInline("x") });', "negative_ts": "deadLetterQueue: dlq"},
    "REL-030": {"positive_ts": "new rds.DatabaseInstance(this, 'DB', { engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_15 }), vpc });", "negative_ts": "deletionProtection: true"},
    "REL-031": {"positive_ts": 'new s3.Bucket(this, "B");', "negative_ts": "versioned: true"},
    "COST-001": {"positive_ts": "new logs.LogGroup(this, 'LG', { retention: logs.RetentionDays.INFINITE });", "negative_ts": "retention: logs.RetentionDays.ONE_MONTH"},
    "COST-002": {"positive_ts": 'new ecs.FargateService(this, "Svc", { cluster, taskDefinition });', "negative_ts": "autoScalingGroup"},
    "OPS-001": {"positive_ts": 'new s3.Bucket(this, "B");', "negative_ts": "new cloudtrail.Trail(this, 'Trail')"},
    "OPS-002": {"positive_ts": 'new ec2.Vpc(this, "Vpc", { maxAzs: 2 });', "negative_ts": "new ec2.FlowLog(this, 'FL')"},
    "OPS-003": {"positive_ts": 'new apigateway.RestApi(this, "Api");', "negative_ts": "tracingEnabled: true"},
    "PERF-001": {"positive_ts": 'new lambda.Function(this, "Fn", { runtime: lambda.Runtime.NODEJS_18_X, handler: "index.handler", code: lambda.Code.fromInline("x") });', "negative_ts": "architecture: lambda.Architecture.ARM_64"},
    "PERF-002": {"positive_ts": 'new s3.Bucket(this, "B");', "negative_ts": "new cloudfront.Distribution(this, 'Cf')"},
    "SUST-001": {"positive_ts": 'new ecs.FargateService(this, "Svc", { cluster, taskDefinition });', "negative_ts": "capacityProviderStrategy"},
    "SUST-002": {"positive_ts": "new ec2.Instance(this, 'Inst', { instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM), vpc, machineImage: ec2.MachineImage.latestAmazonLinux() });", "negative_ts": "// right-sized"},
}

TS_POSITIVE_EXTRA = [
    "new kms.Key(this, 'Key');",
    "new secretsmanager.Secret(this, 'S');",
    "new lambda.Function(this, 'Fn', { environment: { PASSWORD: 'secret123456789' } });",
    "new cloudfront.Distribution(this, 'Cf', { defaultBehavior: { origin } });",
    "new ecs.TaskDefinition(this, 'Td', { compatibility: ecs.Compatibility.FARGATE });",
    "new ecr.Repository(this, 'R');",
    "new elasticache.CfnReplicationGroup(this, 'C', {});",
    "new opensearch.Domain(this, 'D', { version: opensearch.EngineVersion.OPENSEARCH_2_3 });",
    "new kinesis.Stream(this, 'S');",
    "new glue.CfnJob(this, 'J', { command: { name: 'glueetl' }, role: role.roleArn });",
    "new msk.CfnCluster(this, 'M', { clusterName: 'c', kafkaVersion: '2.8.1', numberOfBrokerNodes: 2, brokerNodeGroupInfo: {} });",
    "new sagemaker.CfnNotebookInstance(this, 'N', { roleArn: role.roleArn, instanceType: 'ml.t3.medium' });",
    "new appsync.GraphqlApi(this, 'A', { name: 'api', schema: schema });",
    "new fsx.CfnFileSystem(this, 'F', { fileSystemType: 'LUSTRE', storageCapacity: 1200, subnetIds: ['s'] });",
    "new transfer.CfnServer(this, 'T', { identityProviderType: 'SERVICE_MANAGED' });",
    "new codepipeline.Pipeline(this, 'P');",
    "new codebuild.Project(this, 'P', { environment: { privileged: true } });",
    "new ec2.Vpc(this, 'Vpc');",
    "new wafv2.CfnWebACL(this, 'W', { scope: 'REGIONAL', defaultAction: { allow: {} }, visibilityConfig: { cloudWatchMetricsEnabled: true, metricName: 'm', sampledRequestsEnabled: true } });",
    "new route53.CfnHealthCheck(this, 'H', { healthCheckConfig: { type: 'HTTP', port: 80, resourcePath: '/' } });",
    "new cognito.UserPool(this, 'Pool');",
    "new ssm.StringParameter(this, 'P', { parameterName: '/x', stringValue: 'v' });",
    "new backup.BackupVault(this, 'V');",
    "new redshift.CfnCluster(this, 'C', { clusterType: 'single-node', dbName: 'd', masterUsername: 'u', nodeType: 'dc2.large' });",
    "new neptune.CfnDBCluster(this, 'C', {});",
    "new docdb.CfnDBCluster(this, 'C', {});",
    "new macie.CfnSession(this, 'S', { status: 'ENABLED' });",
    "new guardduty.CfnDetector(this, 'D', { enable: true });",
    "new securityhub.CfnHub(this, 'H', {});",
    "new autoscaling.AutoScalingGroup(this, 'Asg', { vpc, instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM), machineImage: ec2.MachineImage.latestAmazonLinux() });",
    "new cloudwatch.Alarm(this, 'A', { metric: metric, threshold: 1, evaluationPeriods: 1 });",
    "new events.Rule(this, 'R', { eventPattern: { source: ['aws.ec2'] } });",
    "new stepfunctions.StateMachine(this, 'SM', { definitionBody: DefinitionBody.fromChainable(new stepfunctions.Pass(this, 'Pass')) });",
    "new config.CfnConfigurationRecorder(this, 'R', { roleArn: role.roleArn, recordingGroup: { allSupported: true, includeGlobalResourceTypes: true } });",
    "new budgets.CfnBudget(this, 'B', { budget: { budgetType: 'COST', timeUnit: 'MONTHLY', budgetLimit: { amount: 100, unit: 'USD' } } });",
    "new globalaccelerator.Accelerator(this, 'A');",
    "new efs.FileSystem(this, 'Fs', { vpc });",
    "new athena.CfnWorkGroup(this, 'W', { name: 'wg', workGroupConfiguration: {} });",
    "// empty",
    "export class Stack {};",
]

TS_NEGATIVE_EXTRA = [
    "// clean compliant stack",
    "authorizer:",
    "encryption:",
    "encryptionMasterKey",
    "multiAz: true",
    "deadLetterQueue:",
    "blockPublicAccess:",
    "enableKeyRotation: true",
    "versioned: true",
    "accessLogs:",
    "tracingEnabled: true",
    "cloudtrail.Trail",
    "FlowLog",
    "securityPolicy:",
    "minimumTlsVersion",
    "publiclyAccessible: false",
    "deletionProtection: true",
    "capacityProviderStrategy",
    "Spot",
    "Graviton",
    "ARM_64",
    "CloudFront",
    "ElastiCache",
    "Aspects.of",
    "cdk.Aspects",
]


def _extract_patterns(source: str) -> list[str]:
    return [m[2] for m in re.findall(r"rg\(repo_path,\s*(r?)(['\"])(.*?)\2", source, re.DOTALL)]


def _pattern_snippets(pattern: str, lang: str) -> list[str]:
    out: list[str] = []
    if "dynamodb" in pattern or "Table" in pattern:
        out.append("new dynamodb.Table(this, 'T', { partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING } });")
    if "sqs" in pattern:
        out.append("new sqs.Queue(this, 'Q');")
    if "sns" in pattern:
        out.append("new sns.Topic(this, 'T');")
    if "apigateway" in pattern or "RestApi" in pattern:
        out.append("new apigateway.RestApi(this, 'Api');")
    if "Vpc" in pattern:
        out.append("new ec2.Vpc(this, 'Vpc');")
    if "lambda" in pattern:
        out.append("new lambda.Function(this, 'Fn', { runtime: lambda.Runtime.NODEJS_18_X, handler: 'h', code: lambda.Code.fromInline('x') });")
    if "rds" in pattern or "DatabaseInstance" in pattern:
        out.append("new rds.DatabaseInstance(this, 'DB', { engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_15 }), vpc });")
    if "s3" in pattern or "Bucket" in pattern:
        out.append('new s3.Bucket(this, "B");')
    if "cloudfront" in pattern:
        out.append("new cloudfront.Distribution(this, 'Cf', { defaultBehavior: { origin } });")
    if "ecs" in pattern:
        out.append("new ecs.FargateService(this, 'Svc', { cluster, taskDefinition });")
    if "ecr" in pattern:
        out.append("new ec2.Vpc(this, 'Vpc');\nnew ecr.Repository(this, 'R');")
    if "0\\.0\\.0\\.0" in pattern or "22" in pattern:
        out.append("connections.allowFrom(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));")
    if "3306" in pattern or "5432" in pattern:
        out.append("sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(3306));")
    if "Action" in pattern and "\\*" in pattern:
        out.append('Action: "*"')
    if "Resource" in pattern and "\\*" in pattern:
        out.append('Resource: "*"')
    if "AKIA" in pattern:
        out.append('const access_key = "AKIAIOSFODNN7EXAMPLE";')
    if "password" in pattern.lower():
        out.append("password: 'supersecretpassword123'")
    if "cloudtrail" in pattern.lower():
        out.append('new s3.Bucket(this, "B");')
    if not out:
        m = re.search(r"new\\s+([\w.]+)", pattern)
        if m:
            out.append(f"new {m.group(1).replace(chr(92), '')}(this, 'X');")
    return out


def _repo(content: str, lang: str, base: Path) -> Path:
    root = base / "repo"
    if root.exists():
        import shutil
        shutil.rmtree(root)
    root.mkdir(exist_ok=True)
    if lang == "typescript":
        (root / "package.json").write_text("{}", encoding="utf-8")
        (root / "lib").mkdir(exist_ok=True)
        (root / "lib" / "stack.ts").write_text(content, encoding="utf-8")
    else:
        (root / "requirements.txt").write_text("", encoding="utf-8")
        (root / "app.py").write_text(content, encoding="utf-8")
    return root


def _fires(rule, repo: Path, lang: str) -> bool:
    return any(f.id == rule.id for f in rule.run(repo, lang))


def _candidates_for_rule(rule) -> list[tuple[str, str]]:
    if rule.id in KNOWN:
        k = KNOWN[rule.id]
        lang = "typescript"
        return [(k["positive_ts"], lang)]
    src = inspect.getsource(rule.run)
    cands: list[tuple[str, str]] = []
    for pat in _extract_patterns(src):
        for snip in _pattern_snippets(pat, "typescript"):
            cands.append((snip, "typescript"))
    for snip in TS_POSITIVE_EXTRA:
        cands.append((snip, "typescript"))
    # absence rules: empty repos
    if "if not " in src and "return [Finding" in src:
        cands.insert(0, ("// empty", "typescript"))
        cands.insert(0, ("# empty", "python"))
    return cands


def calibrate_rule(rule) -> dict[str, str | None]:
    if rule.id in KNOWN:
        return dict(KNOWN[rule.id])
    case: dict[str, str | None] = {}
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        pos_snip = None
        pos_lang = None
        for snip, lang in _candidates_for_rule(rule):
            repo = _repo(snip, lang, base)
            if _fires(rule, repo, lang):
                pos_snip = snip
                pos_lang = lang
                key = "positive_ts" if lang == "typescript" else "positive_py"
                case[key] = snip
                break
        if not pos_snip:
            return case
        for neg in TS_NEGATIVE_EXTRA:
            repo = _repo(neg, pos_lang, base)
            if not _fires(rule, repo, pos_lang):
                case["negative_ts" if pos_lang == "typescript" else "negative_py"] = neg
                break
    return case


def main() -> None:
    cases: dict[str, dict[str, str | None]] = {}
    for rule in ALL_RULES:
        c = calibrate_rule(rule)
        if c.get("positive_ts") or c.get("positive_py"):
            cases[rule.id] = c
    missing = [r.id for r in ALL_RULES if r.id not in cases]
    OUT.write_text(json.dumps(cases, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Calibrated {len(cases)}/170; missing {len(missing)}")
    if missing:
        print(", ".join(missing))


if __name__ == "__main__":
    main()
