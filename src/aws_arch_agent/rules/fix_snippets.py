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
# CF-LAM-003 names the runtime to move to in its recommendation ("Move to nodejs24.x.").
_MOVE_TO = re.compile(r"Move to (?P<runtime>[a-z0-9.-]+)\.")
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
    "CF-S3-005": """${name}Policy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref $name
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Sid: DenyInsecureTransport
          Effect: Deny
          Principal: "*"
          Action: s3:*
          Resource:
            - !GetAtt $name.Arn
            - !Sub "$${$name.Arn}/*"
          Condition:
            Bool:
              aws:SecureTransport: "false\"""",
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
    "CF-EKS-002": """$name:
  Type: AWS::EKS::Cluster
  Properties:
    ResourcesVpcConfig:
      EndpointPrivateAccess: true
      EndpointPublicAccess: false  # or true with PublicAccessCidrs limited to known ranges""",
    "CF-EKS-003": """$name:
  Type: AWS::EKS::Cluster
  Properties:
    EncryptionConfig:
      - Provider:
          KeyArn: !GetAtt EksSecretsKey.Arn
        Resources:
          - secrets""",
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
    "CF-S3-005": """# merge into the bucket's existing policy: a bucket has only one
resource "aws_s3_bucket_policy" "$tf_name" {
  bucket = aws_s3_bucket.$tf_name.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.$tf_name.arn, "$${aws_s3_bucket.$tf_name.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
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
    "CF-EKS-002": """resource "aws_eks_cluster" "$tf_name" {
  # keep the other arguments as they are
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false # or true with public_access_cidrs limited to known ranges
  }
}""",
    "CF-EKS-003": """resource "aws_eks_cluster" "$tf_name" {
  # keep the other arguments as they are
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }
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

# IAM (CF-IAM-001..003): the fix is the same shape whichever kind of wildcard was found.
_CF_IAM_POLICY = """$name:
  Type: $type
  Properties:
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - s3:GetObject  # only the actions this principal calls
          Resource:
            - arn:aws:s3:::my-bucket/*  # only the resources it calls them on"""
_CF_IAM_PRINCIPAL = """$name:
  Type: $type
  Properties:
    Policies:
      - PolicyName: least-privilege
        PolicyDocument:
          Version: "2012-10-17"
          Statement:
            - Effect: Allow
              Action:
                - s3:GetObject  # only the actions this principal calls
              Resource:
                - arn:aws:s3:::my-bucket/*  # only the resources it calls them on"""
_TF_IAM_DOCUMENT = """data "aws_iam_policy_document" "$tf_name" {
  statement {
    actions   = ["s3:GetObject"]              # only the actions this principal calls
    resources = ["arn:aws:s3:::my-bucket/*"]  # only the resources it calls them on
  }
}
"""
_TF_IAM_POLICY = _TF_IAM_DOCUMENT + """
resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  policy = data.aws_iam_policy_document.$tf_name.json
}"""
_TF_IAM_ROLE = _TF_IAM_DOCUMENT + """
resource "aws_iam_role" "$tf_name" {
  # keep the other arguments as they are
  inline_policy {
    name   = "least-privilege"
    policy = data.aws_iam_policy_document.$tf_name.json
  }
}"""
for _check in ("CF-IAM-001", "CF-IAM-002", "CF-IAM-003"):
    _CLOUDFORMATION[_check] = _CF_IAM_POLICY
    for _principal in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"):
        _CLOUDFORMATION[f"{_check}:{_principal}"] = _CF_IAM_PRINCIPAL
    _TERRAFORM[_check] = _TF_IAM_POLICY
    _TERRAFORM[f"{_check}:aws_iam_role"] = _TF_IAM_ROLE

# Full admin access (CF-IAM-008): drop AdministratorAccess and grant a scoped policy.
_NO_ADMIN_CF = "    # remove arn:aws:iam::aws:policy/AdministratorAccess from ManagedPolicyArns\n"
_CLOUDFORMATION["CF-IAM-008"] = _CF_IAM_POLICY
for _principal in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"):
    _CLOUDFORMATION[f"CF-IAM-008:{_principal}"] = _CF_IAM_PRINCIPAL.replace(
        "  Properties:\n", "  Properties:\n" + _NO_ADMIN_CF, 1
    )
_TERRAFORM["CF-IAM-008"] = _TF_IAM_POLICY
_TERRAFORM["CF-IAM-008:aws_iam_role"] = _TF_IAM_ROLE.replace(
    "  # keep the other arguments as they are\n",
    "  # keep the other arguments as they are; drop AdministratorAccess from managed_policy_arns\n",
    1,
)
_TF_IAM_ATTACHMENT = _TF_IAM_DOCUMENT + """
resource "aws_iam_policy" "$tf_name" {
  policy = data.aws_iam_policy_document.$tf_name.json
}

resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  policy_arn = aws_iam_policy.$tf_name.arn # instead of AdministratorAccess
}"""
for _attachment in (
    "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment", "aws_iam_policy_attachment",
):
    _TERRAFORM[f"CF-IAM-008:{_attachment}"] = _TF_IAM_ATTACHMENT
_TF_IAM_EXCLUSIVE = _TF_IAM_DOCUMENT + """
resource "aws_iam_policy" "$tf_name" {
  policy = data.aws_iam_policy_document.$tf_name.json
}

resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  policy_arns = [aws_iam_policy.$tf_name.arn] # instead of AdministratorAccess
}"""
for _principal in ("role", "user", "group"):
    _TERRAFORM[f"CF-IAM-008:aws_iam_{_principal}_policy_attachments_exclusive"] = _TF_IAM_EXCLUSIVE

# Resource policies open to any principal (CF-RP-001).
_CLOUDFORMATION["CF-RP-001"] = """$name:
  Type: $type
  Properties:
    # keep the other properties as they are
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            Service: events.amazonaws.com  # or AWS: the account or role that needs it
          Action: sqs:SendMessage  # the actions it needs
          Resource: !GetAtt MyQueue.Arn  # the resource this policy is on
          Condition:
            ArnEquals:
              aws:SourceArn: !GetAtt MyRule.Arn  # only for this caller"""
for _type, _action, _resource in (
    ("AWS::SNS::TopicPolicy", "sns:Publish", "!Ref MyTopic"),
    ("AWS::S3::BucketPolicy", "s3:GetObject", '!Sub "$${MyBucket.Arn}/*"'),
):
    _CLOUDFORMATION[f"CF-RP-001:{_type}"] = _CLOUDFORMATION["CF-RP-001"].replace(
        "sqs:SendMessage", _action).replace("!GetAtt MyQueue.Arn", _resource)
_CLOUDFORMATION["CF-RP-001:AWS::ECR::Repository"] = """$name:
  Type: AWS::ECR::Repository
  Properties:
    RepositoryPolicyText:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:root  # the account that pulls
          Action:
            - ecr:BatchGetImage
            - ecr:GetDownloadUrlForLayer"""
_CLOUDFORMATION["CF-RP-001:AWS::Lambda::Permission"] = """$name:
  Type: AWS::Lambda::Permission
  Properties:
    # keep the other properties as they are
    Principal: s3.amazonaws.com  # the service or account that invokes
    SourceArn: !GetAtt MyBucket.Arn  # only this caller
    SourceAccount: !Ref AWS::AccountId"""
_TERRAFORM["CF-RP-001"] = """data "aws_iam_policy_document" "$tf_name" {
  statement {
    actions   = ["sqs:SendMessage"]          # the actions it needs
    resources = [aws_sqs_queue.my_queue.arn] # the resource this policy is on
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"] # or "AWS" with the account or role
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.my_rule.arn] # only for this caller
    }
  }
}

resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  policy = data.aws_iam_policy_document.$tf_name.json
}"""
for _type, _action, _resource in (
    ("aws_sns_topic_policy", "sns:Publish", "aws_sns_topic.my_topic.arn"),
    ("aws_s3_bucket_policy", "s3:GetObject", '"$${aws_s3_bucket.my_bucket.arn}/*"'),
):
    _TERRAFORM[f"CF-RP-001:{_type}"] = _TERRAFORM["CF-RP-001"].replace(
        '"sqs:SendMessage"]         ', f'"{_action}"]').replace("aws_sqs_queue.my_queue.arn", _resource)
# A repository policy has no Resource: the policy is on the repository.
_TERRAFORM["CF-RP-001:aws_ecr_repository_policy"] = "\n".join(
    line for line in _TERRAFORM["CF-RP-001"].replace(
        '"sqs:SendMessage"]         ', '"ecr:BatchGetImage"]').splitlines()
    if "aws_sqs_queue.my_queue.arn" not in line
).replace("events.amazonaws.com", "codebuild.amazonaws.com").replace(
    "aws_cloudwatch_event_rule.my_rule.arn", "aws_codebuild_project.my_project.arn")
_TERRAFORM["CF-RP-001:aws_lambda_permission"] = """resource "aws_lambda_permission" "$tf_name" {
  # keep the other arguments as they are
  principal      = "s3.amazonaws.com"            # the service or account that invokes
  source_arn     = aws_s3_bucket.my_bucket.arn   # only this caller
  source_account = data.aws_caller_identity.current.account_id
}"""

# Encryption at rest / in transit (DM3-525).
_CLOUDFORMATION.update({
    "CF-SNS-001": """$name:
  Type: AWS::SNS::Topic
  Properties:
    KmsMasterKeyId: alias/aws/sns  # or a customer managed key""",
    "CF-EBS-001": """$name:
  Type: AWS::EC2::Volume
  Properties:
    Encrypted: true
    KmsKeyId: alias/aws/ebs  # optional: a customer managed key""",
    "CF-EBS-001:AWS::EC2::LaunchTemplate": """$name:
  Type: AWS::EC2::LaunchTemplate
  Properties:
    LaunchTemplateData:
      BlockDeviceMappings:
        - DeviceName: /dev/xvda
          Ebs:
            Encrypted: true""",
    "CF-EFS-001": """$name:
  Type: AWS::EFS::FileSystem
  Properties:
    Encrypted: true  # set at creation; it cannot be changed later""",
    "CF-KIN-001": """$name:
  Type: AWS::Kinesis::Stream
  Properties:
    StreamEncryption:
      EncryptionType: KMS
      KeyId: alias/aws/kinesis  # or a customer managed key""",
    "CF-EC-001": """$name:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    AtRestEncryptionEnabled: true  # set at creation; it cannot be changed later""",
    "CF-EC-002": """$name:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    TransitEncryptionEnabled: true""",
})
_TERRAFORM.update({
    "CF-SNS-001": """resource "aws_sns_topic" "$tf_name" {
  kms_master_key_id = "alias/aws/sns" # or a customer managed key
}""",
    "CF-EBS-001": """resource "aws_ebs_volume" "$tf_name" {
  # keep the other arguments as they are
  encrypted = true
}""",
    "CF-EBS-001:aws_launch_template": """resource "aws_launch_template" "$tf_name" {
  # keep the other arguments as they are
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted = true
    }
  }
}""",
    "CF-EFS-001": """resource "aws_efs_file_system" "$tf_name" {
  encrypted = true # set at creation; it cannot be changed later
}""",
    "CF-KIN-001": """resource "aws_kinesis_stream" "$tf_name" {
  # keep the other arguments as they are
  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis" # or a customer managed key
}""",
    "CF-EC-001": """resource "aws_elasticache_replication_group" "$tf_name" {
  # keep the other arguments as they are
  at_rest_encryption_enabled = true # set at creation; it cannot be changed later
}""",
    "CF-EC-002": """resource "aws_elasticache_replication_group" "$tf_name" {
  # keep the other arguments as they are
  transit_encryption_enabled = true
}""",
})

# Encryption, part 2 (DM3-552).
_CLOUDFORMATION.update({
    "CF-OS-001": """$name:
  Type: AWS::OpenSearchService::Domain
  Properties:
    EncryptionAtRestOptions:
      Enabled: true  # changing it later replaces the domain""",
    "CF-OS-002": """$name:
  Type: AWS::OpenSearchService::Domain
  Properties:
    NodeToNodeEncryptionOptions:
      Enabled: true""",
    "CF-RS-001": """$name:
  Type: AWS::Redshift::Cluster
  Properties:
    Encrypted: true""",
    "CF-DOCDB-001": """$name:
  Type: AWS::DocDB::DBCluster
  Properties:
    StorageEncrypted: true  # set at creation; it cannot be changed later""",
    "CF-NEP-001": """$name:
  Type: AWS::Neptune::DBCluster
  Properties:
    StorageEncrypted: true  # set at creation; it cannot be changed later""",
    "CF-MSK-001": """$name:
  Type: AWS::MSK::Cluster
  Properties:
    EncryptionInfo:
      EncryptionInTransit:
        ClientBroker: TLS
        InCluster: true""",
})
_TERRAFORM.update({
    "CF-OS-001": """resource "aws_opensearch_domain" "$tf_name" {
  # keep the other arguments as they are
  encrypt_at_rest {
    enabled = true
  }
}""",
    "CF-OS-002": """resource "aws_opensearch_domain" "$tf_name" {
  # keep the other arguments as they are
  node_to_node_encryption {
    enabled = true
  }
}""",
    "CF-RS-001": """resource "aws_redshift_cluster" "$tf_name" {
  # keep the other arguments as they are
  encrypted = true
}""",
    "CF-DOCDB-001": """resource "aws_docdb_cluster" "$tf_name" {
  # keep the other arguments as they are
  storage_encrypted = true # set at creation; it cannot be changed later
}""",
    "CF-NEP-001": """resource "aws_neptune_cluster" "$tf_name" {
  # keep the other arguments as they are
  storage_encrypted = true # set at creation; it cannot be changed later
}""",
    "CF-MSK-001": """resource "aws_msk_cluster" "$tf_name" {
  # keep the other arguments as they are
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}""",
})

# CloudFront and WAF (DM3-526).
_CLOUDFORMATION.update({
    "CF-CF-001": """$name:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      # keep the other settings as they are
      DefaultCacheBehavior:
        ViewerProtocolPolicy: redirect-to-https  # also on each CacheBehaviors entry""",
    "CF-CF-002": """$name:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      # keep the other settings as they are
      ViewerCertificate:
        AcmCertificateArn: !Ref Certificate
        SslSupportMethod: sni-only
        MinimumProtocolVersion: TLSv1.2_2021""",
    "CF-CF-003": """$name:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      # keep the other settings as they are
      WebACLId: !GetAtt EdgeWebAcl.Arn  # an AWS::WAFv2::WebACL with Scope: CLOUDFRONT""",
    "CF-WAF-001": """${name}WebAcl:
  Type: AWS::WAFv2::WebACLAssociation
  Properties:
    ResourceArn: !Ref $name  # an API stage needs its ARN: !Sub arn:$${AWS::Partition}:apigateway:$${AWS::Region}::/restapis/<api-id>/stages/<stage>
    WebACLArn: !GetAtt RegionalWebAcl.Arn  # an AWS::WAFv2::WebACL with Scope: REGIONAL""",
})
_TERRAFORM.update({
    "CF-CF-001": """resource "aws_cloudfront_distribution" "$tf_name" {
  # keep the other arguments as they are
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https" # also on each ordered_cache_behavior
  }
}""",
    "CF-CF-002": """resource "aws_cloudfront_distribution" "$tf_name" {
  # keep the other arguments as they are
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cert.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}""",
    "CF-CF-003": """resource "aws_cloudfront_distribution" "$tf_name" {
  # keep the other arguments as they are
  web_acl_id = aws_wafv2_web_acl.edge.arn # scope = "CLOUDFRONT"
}""",
    "CF-WAF-001": """resource "aws_wafv2_web_acl_association" "$tf_name" {
  resource_arn = $tf_type.$tf_name.arn
  web_acl_arn  = aws_wafv2_web_acl.regional.arn # scope = "REGIONAL"
}""",
})

# Lambda runtime (CF-LAM-003): the recommendation names the runtime to move to.
_CLOUDFORMATION["CF-LAM-003"] = """$name:
  Type: AWS::Lambda::Function
  Properties:
    # keep the other properties as they are
    Runtime: $runtime  # the current runtime of the same language"""
_TERRAFORM["CF-LAM-003"] = """resource "aws_lambda_function" "$tf_name" {
  # keep the other arguments as they are
  runtime = "$runtime" # the current runtime of the same language
}"""

# Role trust policies (CF-IAM-004..007).
def _cf_trust(statement: str) -> str:
    return """$name:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: "2012-10-17"
      Statement:
""" + statement


def _tf_trust(statement: str) -> str:
    return """data "aws_iam_policy_document" "${tf_name}_trust" {
  statement {
""" + statement + """
  }
}

resource "aws_iam_role" "$tf_name" {
  # keep the other arguments as they are
  assume_role_policy = data.aws_iam_policy_document.${tf_name}_trust.json
}"""


_CLOUDFORMATION.update({
    "CF-IAM-004": _cf_trust("""        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:role/caller  # only who needs it
          Action: sts:AssumeRole"""),
    "CF-IAM-005": _cf_trust("""        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:root
          Action: sts:AssumeRole
          Condition:
            StringEquals:
              sts:ExternalId: the-id-the-third-party-gave-you"""),
    "CF-IAM-006": _cf_trust("""        - Effect: Allow
          Principal:
            Service: config.amazonaws.com
          Action: sts:AssumeRole
          Condition:
            StringEquals:
              aws:SourceAccount: !Ref AWS::AccountId"""),
    "CF-IAM-007": _cf_trust("""        - Effect: Allow
          Principal:
            Federated: !Sub arn:aws:iam::$${AWS::AccountId}:oidc-provider/token.actions.githubusercontent.com
          Action: sts:AssumeRoleWithWebIdentity
          Condition:
            StringEquals:
              token.actions.githubusercontent.com:aud: sts.amazonaws.com
            StringLike:
              token.actions.githubusercontent.com:sub: repo:my-org/my-repo:ref:refs/heads/main"""),
})
_TERRAFORM.update({
    "CF-IAM-004": _tf_trust("""    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:role/caller"] # only who needs it
    }"""),
    "CF-IAM-005": _tf_trust("""    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["the-id-the-third-party-gave-you"]
    }"""),
    "CF-IAM-006": _tf_trust("""    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id] # data "aws_caller_identity" "current" {}
    }"""),
    "CF-IAM-007": _tf_trust("""    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn] # your GitHub OIDC provider
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:my-org/my-repo:ref:refs/heads/main"]
    }"""),
})

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
            move = _MOVE_TO.search(finding.recommendation or "")
            names["runtime"] = move.group("runtime") if move else "<a supported runtime>"
            finding.suggested_code = Template(snippet).substitute(names)
        finding.recommendation = strip_cdk_hint(finding.recommendation)
    return findings
