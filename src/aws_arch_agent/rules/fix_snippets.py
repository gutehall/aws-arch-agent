"""Suggested fixes for CF-* findings, written in the language of the source they came from.

A raw CloudFormation template gets a CloudFormation snippet and a Terraform root module
gets an HCL snippet, so the reader edits the file the finding points at. Findings on
`cdk synth` output are left alone: the fix belongs in the CDK app, and their
recommendations already carry the CDK hint.
"""
from __future__ import annotations

import re
from string import Template
from typing import Literal

from aws_arch_agent.models import Finding

FixLanguage = Literal["cloudformation", "terraform"]

# "Logical (AWS::Type)" or "aws_type.name (aws_type)"; template-level evidence ends "(aws_type.name)".
_RESOURCE_EVIDENCE = re.compile(r"^(?P<name>\S+) \((?P<type>[^)]+)\)$")
_ANCHOR_EVIDENCE = re.compile(r"\((?P<address>aws_[a-z0-9_]+\.[A-Za-z0-9_-]+)\)$")
_CDK_HINT = re.compile(r"\s*In CDK:[^.]*(?:\.[A-Za-z_][^.]*)*\.?\s*$")

# $name: CloudFormation logical id; $tf_type / $tf_name: Terraform resource address parts.
_CLOUDFORMATION: dict[str, str] = {
    "CF-S3-001": """$name:
  Type: AWS::S3::Bucket
  Properties:
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
      IgnorePublicAcls: true
      BlockPublicPolicy: true
      RestrictPublicBuckets: true""",
    "CF-S3-002": """$name:
  Type: AWS::S3::Bucket
  Properties:
    BucketEncryption:
      ServerSideEncryptionConfiguration:
        - ServerSideEncryptionByDefault:
            SSEAlgorithm: AES256""",
    "CF-S3-003": """$name:
  Type: AWS::S3::Bucket
  Properties:
    VersioningConfiguration:
      Status: Enabled""",
    "CF-S3-004": """$name:
  Type: AWS::S3::Bucket
  Properties:
    LoggingConfiguration:
      DestinationBucketName: !Ref AccessLogBucket
      LogFilePrefix: $name/""",
    "CF-RDS-001": """$name:
  Type: $type
  Properties:
    StorageEncrypted: true""",
    "CF-RDS-002": """$name:
  Type: $type
  Properties:
    BackupRetentionPeriod: 7""",
    "CF-RDS-003": """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    MultiAZ: true""",
    "CF-RDS-004": """$name:
  Type: $type
  Properties:
    PubliclyAccessible: false""",
    "CF-RDS-005": """$name:
  Type: $type
  Properties:
    DeletionProtection: true""",
    "CF-PERF-003": """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceClass: db.m6g.large  # size to measured load""",
    "CF-EC2-001": """$name:
  Type: AWS::EC2::Instance
  Properties:
    MetadataOptions:
      HttpTokens: required
      HttpEndpoint: enabled""",
    "CF-EC2-001:AWS::EC2::LaunchTemplate": """$name:
  Type: AWS::EC2::LaunchTemplate
  Properties:
    LaunchTemplateData:
      MetadataOptions:
        HttpTokens: required
        HttpEndpoint: enabled""",
    "CF-PERF-004": """$name:
  Type: AWS::EC2::Instance
  Properties:
    InstanceType: m7g.large  # size to measured load""",
    "CF-ALB-001": """$name:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties:
    LoadBalancerAttributes:
      - Key: access_logs.s3.enabled
        Value: "true"
      - Key: access_logs.s3.bucket
        Value: !Ref AccessLogBucket""",
    "CF-CT-001": """$name:
  Type: AWS::CloudTrail::Trail
  Properties:
    EnableLogFileValidation: true""",
    "CF-CT-002": """$name:
  Type: AWS::CloudTrail::Trail
  Properties:
    IsMultiRegionTrail: true""",
    "CF-CT-003": """$name:
  Type: AWS::CloudTrail::Trail
  Properties:
    KmsKeyId: !Ref TrailKey""",
    "CF-KMS-001": """$name:
  Type: AWS::KMS::Key
  Properties:
    KeyPolicy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: !Sub "arn:$${AWS::Partition}:iam::$${AWS::AccountId}:root"
          Action: kms:*
          Resource: "*\"""",
    "CF-LAM-001": """$name:
  Type: AWS::Lambda::Function
  Properties:
    DeadLetterConfig:
      TargetArn: !GetAtt DeadLetterQueue.Arn""",
    "CF-LAM-002": """$name:
  Type: AWS::Lambda::Function
  Properties:
    TracingConfig:
      Mode: Active""",
    "CF-PERF-001": """$name:
  Type: AWS::Lambda::Function
  Properties:
    Architectures:
      - arm64""",
    "CF-DDB-001": """$name:
  Type: AWS::DynamoDB::Table
  Properties:
    PointInTimeRecoverySpecification:
      PointInTimeRecoveryEnabled: true""",
    "CF-DDB-002": """$name:
  Type: AWS::DynamoDB::Table
  Properties:
    SSESpecification:
      SSEEnabled: true""",
    "CF-SG-001": """$name:
  Type: AWS::EC2::SecurityGroup
  Properties:
    # Replace the 0.0.0.0/0 (or ::/0) entry on the flagged port with a known range.
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 22  # the flagged port
        ToPort: 22
        CidrIp: 10.0.0.0/16""",
    "CF-SG-001:AWS::EC2::SecurityGroupIngress": """$name:
  Type: AWS::EC2::SecurityGroupIngress
  Properties:
    GroupId: !Ref SecurityGroup
    IpProtocol: tcp
    FromPort: 22  # the flagged port
    ToPort: 22
    CidrIp: 10.0.0.0/16  # a known range, not 0.0.0.0/0 or ::/0""",
    "CF-CW-001": """$name:
  Type: AWS::Logs::LogGroup
  Properties:
    RetentionInDays: 30""",
    "CF-CW-002": """$name:
  Type: AWS::Logs::LogGroup
  Properties:
    # The key policy must allow the logs.<region>.amazonaws.com service principal.
    KmsKeyId: !GetAtt LogsKey.Arn""",
    "CF-SQS-001": """$name:
  Type: AWS::SQS::Queue
  Properties:
    SqsManagedSseEnabled: true""",
    "CF-SQS-002": """$name:
  Type: AWS::SQS::Queue
  Properties:
    RedrivePolicy:
      deadLetterTargetArn: !GetAtt DeadLetterQueue.Arn
      maxReceiveCount: 5""",
    "CF-APIGW-001": """$name:
  Type: AWS::ApiGateway::Stage
  Properties:
    AccessLogSetting:
      DestinationArn: !GetAtt AccessLogGroup.Arn""",
    "CF-APIGW-002": """$name:
  Type: AWS::ApiGateway::Stage
  Properties:
    TracingEnabled: true""",
    "CF-APIGW-V2-001": """$name:
  Type: AWS::ApiGatewayV2::Stage
  Properties:
    AccessLogSettings:
      DestinationArn: !GetAtt AccessLogGroup.Arn
      Format: '$$context.requestId $$context.status'""",
    "CF-SUST-001": """$name:
  Type: AWS::AutoScaling::AutoScalingGroup
  Properties:
    # Move the top-level LaunchTemplate into the policy.
    MixedInstancesPolicy:
      LaunchTemplate:
        LaunchTemplateSpecification:
          LaunchTemplateId: !Ref LaunchTemplate
          Version: !GetAtt LaunchTemplate.LatestVersionNumber
      InstancesDistribution:
        SpotAllocationStrategy: price-capacity-optimized""",
    "CF-SUST-002": """$name:
  Type: AWS::ECS::Service
  Properties:
    # Drop LaunchType: it cannot be set together with CapacityProviderStrategy.
    CapacityProviderStrategy:
      - CapacityProvider: FARGATE_SPOT
        Weight: 1""",
    "CF-EKS-001": """$name:
  Type: AWS::EKS::Cluster
  Properties:
    Logging:
      ClusterLogging:
        EnabledTypes:
          - Type: api
          - Type: audit""",
    "CF-VPC-001": """S3Endpoint:
  Type: AWS::EC2::VPCEndpoint
  Properties:
    VpcId: !Ref Vpc
    ServiceName: !Sub com.amazonaws.$${AWS::Region}.s3
    VpcEndpointType: Gateway
    RouteTableIds:
      - !Ref PrivateRouteTable""",
    "CF-FL-001": """VpcFlowLog:
  Type: AWS::EC2::FlowLog
  Properties:
    ResourceId: !Ref Vpc
    ResourceType: VPC
    TrafficType: ALL
    LogDestinationType: cloud-watch-logs
    LogGroupName: /vpc/flow-logs
    DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn""",
    "CF-SUST-003": """$name:
  Type: AWS::EC2::LaunchTemplate
  Properties:
    LaunchTemplateData:
      InstanceMarketOptions:
        MarketType: spot""",
}

_TERRAFORM: dict[str, str] = {
    "CF-S3-001": """resource "aws_s3_bucket_public_access_block" "$tf_name" {
  bucket                  = aws_s3_bucket.$tf_name.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}""",
    "CF-S3-002": """resource "aws_s3_bucket_server_side_encryption_configuration" "$tf_name" {
  bucket = aws_s3_bucket.$tf_name.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}""",
    "CF-S3-003": """resource "aws_s3_bucket_versioning" "$tf_name" {
  bucket = aws_s3_bucket.$tf_name.id
  versioning_configuration {
    status = "Enabled"
  }
}""",
    "CF-S3-004": """resource "aws_s3_bucket_logging" "$tf_name" {
  bucket        = aws_s3_bucket.$tf_name.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "$tf_name/"
}""",
    "CF-RDS-001": """resource "$tf_type" "$tf_name" {
  storage_encrypted = true
}""",
    "CF-RDS-002": """resource "$tf_type" "$tf_name" {
  backup_retention_period = 7
}""",
    "CF-RDS-003": """resource "aws_db_instance" "$tf_name" {
  multi_az = true
}""",
    "CF-RDS-004": """resource "$tf_type" "$tf_name" {
  publicly_accessible = false
}""",
    "CF-RDS-005": """resource "$tf_type" "$tf_name" {
  deletion_protection = true
}""",
    "CF-PERF-003": """resource "aws_db_instance" "$tf_name" {
  instance_class = "db.m6g.large" # size to measured load
}""",
    "CF-EC2-001": """resource "aws_instance" "$tf_name" {
  # keep the other arguments as they are
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}""",
    "CF-EC2-001:aws_launch_template": """resource "aws_launch_template" "$tf_name" {
  # keep the other arguments as they are
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}""",
    "CF-PERF-004": """resource "aws_instance" "$tf_name" {
  instance_type = "m7g.large" # size to measured load
}""",
    "CF-ALB-001": """resource "$tf_type" "$tf_name" {
  access_logs {
    bucket  = aws_s3_bucket.access_logs.id
    enabled = true
  }
}""",
    "CF-CT-001": """resource "aws_cloudtrail" "$tf_name" {
  enable_log_file_validation = true
}""",
    "CF-CT-002": """resource "aws_cloudtrail" "$tf_name" {
  is_multi_region_trail = true
}""",
    "CF-CT-003": """resource "aws_cloudtrail" "$tf_name" {
  kms_key_id = aws_kms_key.trail.arn
}""",
    "CF-KMS-001": """data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_kms_key" "$tf_name" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:$${data.aws_partition.current.partition}:iam::$${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}""",
    "CF-LAM-001": """resource "aws_lambda_function" "$tf_name" {
  dead_letter_config {
    target_arn = aws_sqs_queue.dead_letter.arn
  }
}""",
    "CF-LAM-002": """resource "aws_lambda_function" "$tf_name" {
  tracing_config {
    mode = "Active"
  }
}""",
    "CF-PERF-001": """resource "aws_lambda_function" "$tf_name" {
  architectures = ["arm64"]
}""",
    "CF-DDB-001": """resource "aws_dynamodb_table" "$tf_name" {
  point_in_time_recovery {
    enabled = true
  }
}""",
    "CF-DDB-002": """resource "aws_dynamodb_table" "$tf_name" {
  server_side_encryption {
    enabled = true
  }
}""",
    "CF-SG-001": """# Replace the 0.0.0.0/0 (or ::/0) ingress on the flagged port with a known range.
resource "aws_security_group" "$tf_name" {
  ingress {
    protocol    = "tcp"
    from_port   = 22 # the flagged port
    to_port     = 22
    cidr_blocks = ["10.0.0.0/16"]
  }
}""",
    "CF-SG-001:aws_security_group_rule": """resource "aws_security_group_rule" "$tf_name" {
  type              = "ingress"
  security_group_id = aws_security_group.example.id
  protocol          = "tcp"
  from_port         = 22 # the flagged port
  to_port           = 22
  cidr_blocks       = ["10.0.0.0/16"] # a known range, not 0.0.0.0/0 or ::/0
}""",
    "CF-SG-001:aws_vpc_security_group_ingress_rule": """resource "aws_vpc_security_group_ingress_rule" "$tf_name" {
  security_group_id = aws_security_group.example.id
  ip_protocol       = "tcp"
  from_port         = 22 # the flagged port
  to_port           = 22
  cidr_ipv4         = "10.0.0.0/16" # a known range, not 0.0.0.0/0 or ::/0
}""",
    "CF-CW-001": """resource "aws_cloudwatch_log_group" "$tf_name" {
  retention_in_days = 30
}""",
    "CF-CW-002": """resource "aws_cloudwatch_log_group" "$tf_name" {
  # The key policy must allow the logs.<region>.amazonaws.com service principal.
  kms_key_id = aws_kms_key.logs.arn
}""",
    "CF-SQS-001": """resource "aws_sqs_queue" "$tf_name" {
  sqs_managed_sse_enabled = true
}""",
    "CF-SQS-002": """resource "aws_sqs_queue" "$tf_name" {
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = 5
  })
}""",
    "CF-APIGW-001": """resource "aws_api_gateway_stage" "$tf_name" {
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format          = "$$context.requestId $$context.status"
  }
}""",
    "CF-APIGW-002": """resource "aws_api_gateway_stage" "$tf_name" {
  xray_tracing_enabled = true
}""",
    "CF-APIGW-V2-001": """resource "aws_apigatewayv2_stage" "$tf_name" {
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format          = "$$context.requestId $$context.status"
  }
}""",
    "CF-SUST-001": """resource "aws_autoscaling_group" "$tf_name" {
  mixed_instances_policy {
    instances_distribution {
      spot_allocation_strategy = "price-capacity-optimized"
    }
    # Move the top-level launch_template block in here.
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.example.id
        version            = "$$Latest"
      }
    }
  }
}""",
    "CF-SUST-002": """resource "aws_ecs_service" "$tf_name" {
  # Drop launch_type: it cannot be set together with capacity_provider_strategy.
  capacity_provider_strategy {
    capacity_provider = "FARGATE_SPOT"
    weight            = 1
  }
}""",
    "CF-EKS-001": """resource "aws_eks_cluster" "$tf_name" {
  enabled_cluster_log_types = ["api", "audit"]
}""",
    "CF-VPC-001": """data "aws_region" "current" {}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.$tf_name.id
  service_name      = "com.amazonaws.$${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}""",
    "CF-FL-001": """resource "aws_flow_log" "$tf_name" {
  vpc_id          = aws_vpc.$tf_name.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}""",
    "CF-SUST-003": """resource "aws_launch_template" "$tf_name" {
  instance_market_options {
    market_type = "spot"
  }
}""",
}

SNIPPETS: dict[FixLanguage, dict[str, str]] = {
    "cloudformation": _CLOUDFORMATION,
    "terraform": _TERRAFORM,
}


def _names(finding: Finding) -> dict[str, str]:
    evidence = finding.evidence or ""
    match = _RESOURCE_EVIDENCE.match(evidence)
    if match:
        name, source_type = match.group("name"), match.group("type")
        tf_type, _, tf_name = name.partition(".")
        return {
            "name": name,
            "type": source_type,
            "tf_type": tf_type if tf_name else source_type,
            "tf_name": tf_name or name,
        }
    anchor = _ANCHOR_EVIDENCE.search(evidence)
    if anchor:
        tf_type, _, tf_name = anchor.group("address").partition(".")
        return {"name": "Resource", "type": "", "tf_type": tf_type, "tf_name": tf_name}
    return {"name": "Resource", "type": "", "tf_type": "", "tf_name": "this"}


def strip_cdk_hint(recommendation: str) -> str:
    """Drop a trailing "In CDK: ..." sentence; it points at code this source does not have."""
    return _CDK_HINT.sub("", recommendation).rstrip()


def attach_fixes(findings: list[Finding], language: FixLanguage) -> list[Finding]:
    """Set suggested_code in the source's language and drop CDK hints. Mutates and returns."""
    table = SNIPPETS[language]
    for finding in findings:
        names = _names(finding)
        # A "<id>:<source type>" entry fits a resource shape the plain entry does not.
        snippet = table.get(f"{finding.id}:{names['type']}") or table.get(finding.id)
        if snippet is not None:
            finding.suggested_code = Template(snippet).substitute(names)
        finding.recommendation = strip_cdk_hint(finding.recommendation)
    return findings
