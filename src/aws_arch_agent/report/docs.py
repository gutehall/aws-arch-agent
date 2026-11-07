"""AWS documentation links for findings: one service page and one Well-Architected page.

A rule listed in doc_topics.RULE_TOPICS links to the docs page for its control and to the
Well-Architected best practice it supports. Any other finding falls back to a service start
page matched from the title (first matching keyword wins, so specific keywords come before
broad ones) and the pillar overview for its category. Only docs.aws.amazon.com URLs are
produced.
"""
from __future__ import annotations

import re

from aws_arch_agent.models import Finding
from aws_arch_agent.report.doc_topics import RULE_TOPICS, TOPICS

_DOCS = "https://docs.aws.amazon.com"
_WA = f"{_DOCS}/wellarchitected/latest"

PILLAR_DOCS: dict[str, tuple[str, str]] = {
    "Security": ("Well-Architected: Security pillar", f"{_WA}/security-pillar/welcome.html"),
    "Reliability": ("Well-Architected: Reliability pillar", f"{_WA}/reliability-pillar/welcome.html"),
    "Performance Efficiency": (
        "Well-Architected: Performance Efficiency pillar",
        f"{_WA}/performance-efficiency-pillar/welcome.html",
    ),
    "Cost Optimization": (
        "Well-Architected: Cost Optimization pillar",
        f"{_WA}/cost-optimization-pillar/welcome.html",
    ),
    "Cost": (
        "Well-Architected: Cost Optimization pillar",
        f"{_WA}/cost-optimization-pillar/welcome.html",
    ),
    "Operational Excellence": (
        "Well-Architected: Operational Excellence pillar",
        f"{_WA}/operational-excellence-pillar/welcome.html",
    ),
    "Observability": (
        "Well-Architected: Operational Excellence pillar",
        f"{_WA}/operational-excellence-pillar/welcome.html",
    ),
    "Sustainability": (
        "Well-Architected: Sustainability pillar",
        f"{_WA}/sustainability-pillar/sustainability-pillar.html",
    ),
}
_FRAMEWORK = ("AWS Well-Architected Framework", f"{_WA}/framework/welcome.html")

# (pattern matched case-insensitively against the rule title, link label, docs path).
# Order matters: the first match wins, so put narrow services before the broad ones
# they mention (e.g. "VPC endpoint" before "VPC", "Aurora" before "RDS").
_SERVICES: list[tuple[str, str, str]] = [
    (r"\bVPC endpoints?\b", "AWS PrivateLink and VPC endpoints", "/vpc/latest/privatelink/"),
    (r"\bflow logs?\b", "VPC Flow Logs", "/vpc/latest/userguide/flow-logs.html"),
    (r"\bNAT Gateways?\b", "NAT gateways", "/vpc/latest/userguide/vpc-nat-gateway.html"),
    (r"\bNetwork ACLs?\b", "Network ACLs", "/vpc/latest/userguide/vpc-network-acls.html"),
    (r"\bSecurity Groups?\b", "Security groups", "/vpc/latest/userguide/vpc-security-groups.html"),
    (r"\bTransit Gateway\b", "AWS Transit Gateway", "/vpc/latest/tgw/"),
    (r"\bCloudWatch Logs\b|\blog groups?\b|\blog retention\b", "Amazon CloudWatch Logs", "/AmazonCloudWatch/latest/logs/"),
    (r"\bContributor Insights\b|\bCloudWatch\b|\balarms?\b|\bdashboards?\b",
     "Amazon CloudWatch", "/AmazonCloudWatch/latest/monitoring/"),
    (r"\bCloudTrail\b|\baudit trail\b", "AWS CloudTrail", "/awscloudtrail/latest/userguide/"),
    (r"\bX-Ray\b|\btracing\b", "AWS X-Ray", "/xray/latest/devguide/"),
    (r"\bIMDSv2\b", "Instance Metadata Service", "/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"),
    (r"\bAurora\b", "Amazon Aurora", "/AmazonRDS/latest/AuroraUserGuide/"),
    (r"\bRDS Proxy\b", "Amazon RDS Proxy", "/AmazonRDS/latest/UserGuide/rds-proxy.html"),
    (r"\bLambda\b", "AWS Lambda", "/lambda/latest/dg/"),
    (r"\bStep Functions\b", "AWS Step Functions", "/step-functions/latest/dg/"),
    (r"\bEventBridge\b", "Amazon EventBridge", "/eventbridge/latest/userguide/"),
    (r"\bWAF\b", "AWS WAF", "/waf/latest/developerguide/"),
    (r"\bAppSync\b", "AWS AppSync", "/appsync/latest/devguide/"),
    (r"\bAPI Gateway\b|\bHTTP API\b|\bREST API\b", "Amazon API Gateway", "/apigateway/latest/developerguide/"),
    (r"\bCloudFront\b", "Amazon CloudFront", "/AmazonCloudFront/latest/DeveloperGuide/"),
    (r"\bGlobal Accelerator\b", "AWS Global Accelerator", "/global-accelerator/latest/dg/"),
    (r"\bRoute 53\b", "Amazon Route 53", "/Route53/latest/DeveloperGuide/"),
    (r"\bACM\b|\bcertificate\b", "AWS Certificate Manager", "/acm/latest/userguide/"),
    (r"\bClassic Load Balancers?\b", "Classic Load Balancers", "/elasticloadbalancing/latest/classic/"),
    (r"\bALB\b|\bload balancer\b", "Application Load Balancers", "/elasticloadbalancing/latest/application/"),
    (r"\bNLB\b", "Network Load Balancers", "/elasticloadbalancing/latest/network/"),
    (r"\bStorage Lens\b", "Amazon S3 Storage Lens", "/AmazonS3/latest/userguide/storage_lens.html"),
    (r"\bS3\b|\bbucket\b", "Amazon S3", "/AmazonS3/latest/userguide/"),
    (r"\bDynamoDB\b", "Amazon DynamoDB", "/amazondynamodb/latest/developerguide/"),
    (r"\bElastiCache\b|\bcaching layer\b", "Amazon ElastiCache", "/AmazonElastiCache/latest/dg/"),
    (r"\bDocumentDB\b", "Amazon DocumentDB", "/documentdb/latest/developerguide/"),
    (r"\bNeptune\b", "Amazon Neptune", "/neptune/latest/userguide/"),
    (r"\bRedshift\b", "Amazon Redshift", "/redshift/latest/mgmt/"),
    (r"\bRDS\b|\bdatabase\b|\bDB\b", "Amazon RDS", "/AmazonRDS/latest/UserGuide/"),
    (r"\bOpenSearch\b", "Amazon OpenSearch Service", "/opensearch-service/latest/developerguide/"),
    (r"\bAthena\b", "Amazon Athena", "/athena/latest/ug/"),
    (r"\bGlue\b", "AWS Glue", "/glue/latest/dg/"),
    (r"\bMSK\b", "Amazon MSK", "/msk/latest/developerguide/"),
    (r"\bKinesis\b", "Amazon Kinesis Data Streams", "/streams/latest/dev/"),
    (r"\bSQS\b|\bqueue\b|\bdead-letter\b", "Amazon SQS", "/AWSSimpleQueueService/latest/SQSDeveloperGuide/"),
    (r"\bSNS\b", "Amazon SNS", "/sns/latest/dg/"),
    (r"\bEKS\b", "Amazon EKS", "/eks/latest/userguide/"),
    (r"\bECR\b", "Amazon ECR", "/AmazonECR/latest/userguide/"),
    (r"\bECS\b|\bcontainer\b", "Amazon ECS", "/AmazonECS/latest/developerguide/"),
    (r"\bApp Runner\b", "AWS App Runner", "/apprunner/latest/dg/"),
    (r"\bSageMaker\b", "Amazon SageMaker AI", "/sagemaker/latest/dg/"),
    (r"\bEFS\b", "Amazon EFS", "/efs/latest/ug/"),
    (r"\bFSx\b", "Amazon FSx", "/fsx/"),
    (r"\bTransfer Family\b", "AWS Transfer Family", "/transfer/latest/userguide/"),
    (r"\bEBS\b", "Amazon EBS", "/ebs/latest/userguide/"),
    (r"\bElastic IP\b|\bGraviton\b|\binstance types?\b|\bSpot\b",
     "Amazon EC2", "/AWSEC2/latest/UserGuide/"),
    (r"\bAWS Backup\b|\bBackup vault\b|\bcross-region backup\b", "AWS Backup", "/aws-backup/latest/devguide/"),
    (r"\bCodePipeline\b", "AWS CodePipeline", "/codepipeline/latest/userguide/"),
    (r"\bCodeBuild\b", "AWS CodeBuild", "/codebuild/latest/userguide/"),
    (r"\bKMS\b", "AWS KMS", "/kms/latest/developerguide/"),
    (r"\bSecrets Manager\b|\bsecrets?\b|\bcredentials\b", "AWS Secrets Manager", "/secretsmanager/latest/userguide/"),
    (r"\bSSM\b|\bParameter Store\b", "AWS Systems Manager Parameter Store",
     "/systems-manager/latest/userguide/systems-manager-parameter-store.html"),
    (r"\bIAM\b", "IAM security best practices", "/IAM/latest/UserGuide/best-practices.html"),
    (r"\bCognito\b", "Amazon Cognito", "/cognito/latest/developerguide/"),
    (r"\bSecurity Hub\b", "AWS Security Hub", "/securityhub/latest/userguide/"),
    (r"\bGuardDuty\b", "Amazon GuardDuty", "/guardduty/latest/ug/"),
    (r"\bMacie\b", "Amazon Macie", "/macie/latest/user/"),
    (r"\bAWS Config\b", "AWS Config", "/config/latest/developerguide/"),
    (r"\bBudgets\b|\bSavings Plans?\b|\bReserved\b|\bcost allocation tags?\b",
     "AWS Cost Management", "/cost-management/latest/userguide/"),
    (r"\bCDK\b", "AWS CDK", "/cdk/v2/guide/"),
    (r"\btermination protection\b|\bstack\b", "AWS CloudFormation", "/AWSCloudFormation/latest/UserGuide/"),
    (r"\btags?\b|\btagging\b", "Tagging AWS resources", "/tag-editor/latest/userguide/tagging.html"),
    (r"\bVPC\b", "Amazon VPC", "/vpc/latest/userguide/"),
    (r"\bautoscaling\b|\bscaling\b", "Amazon EC2 Auto Scaling", "/autoscaling/ec2/userguide/"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), label, path) for p, label, path in _SERVICES]


def doc_links(finding: Finding) -> list[dict[str, str]]:
    """Return documentation links for a finding: service page first, then Well-Architected."""
    topic = RULE_TOPICS.get(finding.id)
    if topic:
        label, path, wa_label, wa_path = TOPICS[topic]
        return [
            {"label": label, "url": _DOCS + path},
            {"label": wa_label, "url": _DOCS + wa_path},
        ]
    links: list[dict[str, str]] = []
    for pattern, label, path in _COMPILED:
        if pattern.search(finding.title):
            links.append({"label": label, "url": _DOCS + path})
            break
    label, url = PILLAR_DOCS.get(finding.category, _FRAMEWORK)
    links.append({"label": label, "url": url})
    return links
