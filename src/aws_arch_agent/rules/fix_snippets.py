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
    "CF-VPC-002": """S3GatewayEndpoint:
  Type: AWS::EC2::VPCEndpoint
  Properties:
    VpcId: !Ref $name
    ServiceName: !Sub com.amazonaws.$${AWS::Region}.s3
    VpcEndpointType: Gateway
    RouteTableIds:
      - !Ref PrivateRouteTable""",
    "CF-VPC-002:AWS::EC2::NatGateway": """S3GatewayEndpoint:
  Type: AWS::EC2::VPCEndpoint
  Properties:
    VpcId: !Ref Vpc  # the VPC of the NAT gateway
    ServiceName: !Sub com.amazonaws.$${AWS::Region}.s3
    VpcEndpointType: Gateway
    RouteTableIds:
      - !Ref PrivateRouteTable""",
    "CF-VPC-003": """DynamoDBGatewayEndpoint:
  Type: AWS::EC2::VPCEndpoint
  Properties:
    VpcId: !Ref $name
    ServiceName: !Sub com.amazonaws.$${AWS::Region}.dynamodb
    VpcEndpointType: Gateway
    RouteTableIds:
      - !Ref PrivateRouteTable""",
    "CF-VPC-003:AWS::EC2::NatGateway": """DynamoDBGatewayEndpoint:
  Type: AWS::EC2::VPCEndpoint
  Properties:
    VpcId: !Ref Vpc  # the VPC of the NAT gateway
    ServiceName: !Sub com.amazonaws.$${AWS::Region}.dynamodb
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
    "CF-VPC-002": """data "aws_region" "current" {}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.$tf_name.id
  service_name      = "com.amazonaws.$${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}""",
    "CF-VPC-002:aws_nat_gateway": """data "aws_region" "current" {}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id # the VPC of the NAT gateway
  service_name      = "com.amazonaws.$${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}""",
    "CF-VPC-003": """data "aws_region" "current" {}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.$tf_name.id
  service_name      = "com.amazonaws.$${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}""",
    "CF-VPC-003:aws_nat_gateway": """data "aws_region" "current" {}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id # the VPC of the NAT gateway
  service_name      = "com.amazonaws.$${data.aws_region.current.name}.dynamodb"
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

# Encryption at rest / in transit.
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

# Encryption, part 2.
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

# Secret template parameters: resolve the secret where it is used.
_CF_SECRET_REFERENCE = """MyResource:
  Type: AWS::Service::Resource  # the resource that uses $name
  Properties:
    # instead of !Ref $name, resolve the secret where it is used
    TheSecretProperty: "{{resolve:secretsmanager:my-secret:SecretString:my-key}}"
    # or "{{resolve:ssm-secure:/my/parameter}}" where the property supports it"""
_CLOUDFORMATION["CF-PAR-001"] = _CF_SECRET_REFERENCE
_CLOUDFORMATION["CF-PAR-002"] = _CF_SECRET_REFERENCE
_TF_SECRET_REFERENCE = """data "aws_secretsmanager_secret_version" "db" {
  secret_id = "my-db-secret"
}

resource "aws_db_instance" "db" {
  # keep the other arguments as they are
  password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]
  # or let RDS keep it: manage_master_user_password = true
}"""
_TERRAFORM["CF-PAR-001"] = _TF_SECRET_REFERENCE
_TERRAFORM["CF-PAR-002"] = _TF_SECRET_REFERENCE
# Terraform variables: evidence "var.<name> (variable)".
_TERRAFORM["CF-PAR-001:variable"] = """variable "$tf_name" {
  # keep the other arguments (type, description, validation) as they are
  sensitive = true
}

# Better: no variable at all. Read the secret where it is used:
# data "aws_secretsmanager_secret_version" "$tf_name" { secret_id = "my-secret" }"""
_TERRAFORM["CF-PAR-002:variable"] = """variable "$tf_name" {
  # keep type, description and validation; remove the default
  sensitive = true
  # the value comes from the environment (TF_VAR_$tf_name) or a secret store
}

# Better: no variable at all. Read the secret where it is used:
# data "aws_secretsmanager_secret_version" "$tf_name" { secret_id = "my-secret" }"""

# Required tag policy. The keys are an example: use the ones in tags.required.
_CF_TAGS = """$name:
  Type: $type
  Properties:
    # keep the other properties as they are
    Tags:
      - Key: CostCenter # every key in tags.required
        Value: '1234'"""
_CLOUDFORMATION["CF-TAG-001"] = _CF_TAGS
_CLOUDFORMATION["CF-TAG-001:AWS::EFS::FileSystem"] = _CF_TAGS.replace("    Tags:", "    FileSystemTags:")
_CLOUDFORMATION["CF-TAG-001:AWS::Cognito::UserPool"] = """$name:
  Type: AWS::Cognito::UserPool
  Properties:
    # keep the other properties as they are
    UserPoolTags:
      CostCenter: "1234" # every key in tags.required"""
_TERRAFORM["CF-TAG-001"] = """resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  tags = {
    CostCenter = "1234" # every key in tags.required
  }
}

# Or once for every resource: provider "aws" { default_tags { tags = { CostCenter = "1234" } } }"""

# S3 storage classes, DynamoDB autoscaling, launch template gp2.
_CLOUDFORMATION.update({
    "CF-S3-006": """$name:
  Type: AWS::S3::Bucket
  Properties:
    # keep the other properties as they are
    LifecycleConfiguration:
      Rules:
        - Id: tier-and-expire
          Status: Enabled
          Transitions:
            - StorageClass: INTELLIGENT_TIERING
              TransitionInDays: 30
          NoncurrentVersionExpiration:
            NoncurrentDays: 90""",
    "CF-S3-007": """$name:
  Type: AWS::S3::Bucket
  Properties:
    # keep the other properties as they are; add to the existing rule
    LifecycleConfiguration:
      Rules:
        - Id: tier
          Status: Enabled
          Transitions:
            - StorageClass: INTELLIGENT_TIERING
              TransitionInDays: 30""",
    "CF-DDB-003": """${name}ReadScaling:
  Type: AWS::ApplicationAutoScaling::ScalableTarget
  Properties:
    ServiceNamespace: dynamodb
    ScalableDimension: dynamodb:table:ReadCapacityUnits
    ResourceId: !Sub table/$${$name}
    MinCapacity: 5
    MaxCapacity: 100
    # add a matching WriteCapacityUnits target and target-tracking ScalingPolicies""",
    "CF-EBS-002:AWS::EC2::LaunchTemplate": """$name:
  Type: AWS::EC2::LaunchTemplate
  Properties:
    LaunchTemplateData:
      # keep the other settings as they are
      BlockDeviceMappings:
        - DeviceName: /dev/xvda # each gp2 device
          Ebs:
            VolumeType: gp3""",
})
_TERRAFORM.update({
    "CF-S3-006": """resource "aws_s3_bucket_lifecycle_configuration" "$tf_name" {
  bucket = aws_s3_bucket.$tf_name.id
  rule {
    id     = "tier-and-expire"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}""",
    "CF-S3-007": """resource "aws_s3_bucket_lifecycle_configuration" "$tf_name" {
  bucket = aws_s3_bucket.$tf_name.id
  # Add this rule to the bucket's existing aws_s3_bucket_lifecycle_configuration
  # (one per bucket), next to its expiration rules.
  rule {
    id     = "tier"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }
  }
}""",
    "CF-DDB-003": """resource "aws_appautoscaling_target" "${tf_name}_read" {
  service_namespace  = "dynamodb"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  resource_id        = "table/$${aws_dynamodb_table.$tf_name.name}"
  min_capacity       = 5
  max_capacity       = 100
}
# add a matching WriteCapacityUnits target and aws_appautoscaling_policy resources""",
    "CF-EBS-002:aws_launch_template": """resource "aws_launch_template" "$tf_name" {
  # keep the other arguments as they are
  block_device_mappings {
    device_name = "/dev/xvda" # each gp2 device
    ebs {
      volume_type = "gp3"
    }
  }
}""",
})

# Previous-generation instance families. The finding names the type to use.
_CLOUDFORMATION.update({
    "CF-GEN-001": """$name:
  Type: $type
  Properties:
    # keep the other properties as they are
    InstanceType: m7i.large # the type the finding suggests""",
    "CF-GEN-001:AWS::RDS::DBInstance": """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    # keep the other properties as they are
    DBInstanceClass: db.m6i.large # the class the finding suggests""",
    "CF-GEN-001:AWS::ElastiCache::ReplicationGroup": """$name:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    # keep the other properties as they are
    CacheNodeType: cache.m7g.large # the type the finding suggests""",
})
_TERRAFORM.update({
    "CF-GEN-001": """resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  instance_type = "m7i.large" # the type the finding suggests
}""",
    "CF-GEN-001:aws_db_instance": """resource "aws_db_instance" "$tf_name" {
  # keep the other arguments as they are
  instance_class = "db.m6i.large" # the class the finding suggests
}""",
    "CF-GEN-001:aws_elasticache_replication_group": """resource "aws_elasticache_replication_group" "$tf_name" {
  # keep the other arguments as they are
  node_type = "cache.m7g.large" # the type the finding suggests
}""",
})

# Production-grade spend in non-production stacks.
_CLOUDFORMATION.update({
    "CF-ENV-001": """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    # keep the other properties as they are
    MultiAZ: false""",
    "CF-ENV-001:AWS::ElastiCache::ReplicationGroup": """$name:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    # keep the other properties as they are
    MultiAZEnabled: false""",
    "CF-ENV-005": """$name:
  Type: AWS::Logs::LogGroup
  Properties:
    # keep the other properties as they are
    RetentionInDays: 30""",
    "CF-ENV-006": """$name:
  Type: AWS::DynamoDB::Table
  Properties:
    # keep the other properties as they are; remove ProvisionedThroughput
    BillingMode: PAY_PER_REQUEST""",
})
_TERRAFORM.update({
    "CF-ENV-001": """resource "aws_db_instance" "$tf_name" {
  # keep the other arguments as they are
  multi_az = false
}""",
    "CF-ENV-001:aws_elasticache_replication_group": """resource "aws_elasticache_replication_group" "$tf_name" {
  # keep the other arguments as they are
  multi_az_enabled = false
}""",
    "CF-ENV-005": """resource "aws_cloudwatch_log_group" "$tf_name" {
  # keep the other arguments as they are
  retention_in_days = 30
}""",
    "CF-ENV-006": """resource "aws_dynamodb_table" "$tf_name" {
  # keep the other arguments as they are; remove read_capacity and write_capacity
  billing_mode = "PAY_PER_REQUEST"
}""",
})

# gp2 volumes.
_CLOUDFORMATION["CF-EBS-002"] = """$name:
  Type: AWS::EC2::Volume
  Properties:
    # keep the other properties as they are
    VolumeType: gp3
    # over 1,000 GiB: Iops: <3 x size in GiB> to keep the gp2 baseline"""
# Unused Elastic IPs: delete the resource to release it, or attach it.
_CLOUDFORMATION["CF-APIGW-003"] = """$name:
  Type: AWS::ApiGateway::Method
  Properties:
    AuthorizationType: COGNITO_USER_POOLS  # or AWS_IAM, CUSTOM
    AuthorizerId: !Ref Authorizer"""
_CLOUDFORMATION["CF-APIGW-004"] = """$name:
  Type: AWS::ApiGateway::RestApi
  Properties:
    SecurityPolicy: TLS_1_2  # same on AWS::ApiGateway::DomainName; V2 domains: in DomainNameConfigurations"""
_CLOUDFORMATION["CF-APIGW-005"] = """$name:
  Type: AWS::ApiGateway::Stage
  Properties:
    MethodSettings:
      - ResourcePath: "/*"
        HttpMethod: "*"
        ThrottlingRateLimit: 100
        ThrottlingBurstLimit: 200"""
_CLOUDFORMATION["CF-APIGW-006"] = """$name:
  Type: AWS::ApiGateway::Method
  Properties:
    RequestValidatorId: !Ref BodyValidator  # AWS::ApiGateway::RequestValidator, ValidateRequestBody: true
    RequestModels:
      application/json: !Ref RequestModel"""
_CLOUDFORMATION["CF-APIGW-007"] = """$name:
  Type: AWS::ApiGateway::Stage
  Properties:
    MethodSettings:
      - ResourcePath: "/*"
        HttpMethod: "*"
        CachingEnabled: true
        CacheDataEncrypted: true"""
_CLOUDFORMATION["CF-APIGW-008"] = """$name:
  Type: AWS::ApiGateway::Stage
  Properties:
    CacheClusterEnabled: true
    CacheClusterSize: "0.5"
    MethodSettings:
      - ResourcePath: "/~1items"  # one entry per cacheable GET method; "/" is written as ~1
        HttpMethod: GET
        CachingEnabled: true
        CacheDataEncrypted: true"""
_CLOUDFORMATION["CF-APIGW-009"] = """$name:
  Type: AWS::ApiGateway::Stage
  Properties:
    ClientCertificateId: !Ref BackendClientCertificate  # AWS::ApiGateway::ClientCertificate"""
_CLOUDFORMATION["CF-APIGW-V2-003"] = """$name:
  Type: AWS::ApiGatewayV2::Route
  Properties:
    AuthorizationType: JWT  # or AWS_IAM, CUSTOM
    AuthorizerId: !Ref JwtAuthorizer"""
_CLOUDFORMATION["CF-APIGW-V2-004"] = """$name:
  Type: AWS::ApiGatewayV2::Stage
  Properties:
    DefaultRouteSettings:
      ThrottlingRateLimit: 100
      ThrottlingBurstLimit: 200"""
_TERRAFORM["CF-APIGW-003"] = """resource "aws_api_gateway_method" "$tf_name" {
  authorization = "COGNITO_USER_POOLS" # or AWS_IAM, CUSTOM
  authorizer_id = aws_api_gateway_authorizer.example.id
}"""
_TERRAFORM["CF-APIGW-004"] = """resource "$tf_type" "$tf_name" {
  security_policy = "TLS_1_2" # aws_apigatewayv2_domain_name: inside domain_name_configuration
}"""
_TERRAFORM["CF-APIGW-005"] = """resource "aws_api_gateway_method_settings" "$tf_name" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.$tf_name.stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 200
  }
}"""
_TERRAFORM["CF-APIGW-006"] = """resource "aws_api_gateway_method" "$tf_name" {
  request_validator_id = aws_api_gateway_request_validator.body.id
  request_models = {
    "application/json" = aws_api_gateway_model.request.name
  }
}"""
_TERRAFORM["CF-APIGW-007"] = """resource "aws_api_gateway_method_settings" "$tf_name" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.$tf_name.stage_name
  method_path = "*/*"
  settings {
    caching_enabled      = true
    cache_data_encrypted = true
  }
}"""
_TERRAFORM["CF-APIGW-008"] = """resource "aws_api_gateway_stage" "$tf_name" {
  cache_cluster_enabled = true
  cache_cluster_size    = "0.5"
}
# Then turn caching_enabled on for the cacheable GET methods in aws_api_gateway_method_settings."""
_TERRAFORM["CF-APIGW-009"] = """resource "aws_api_gateway_stage" "$tf_name" {
  client_certificate_id = aws_api_gateway_client_certificate.backend.id
}"""
_TERRAFORM["CF-APIGW-V2-003"] = """resource "aws_apigatewayv2_route" "$tf_name" {
  authorization_type = "JWT" # or AWS_IAM, CUSTOM
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}"""
_TERRAFORM["CF-APIGW-V2-004"] = """resource "aws_apigatewayv2_stage" "$tf_name" {
  default_route_settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 200
  }
}"""
_CLOUDFORMATION["CF-LAM-004"] = """$name:
  Type: AWS::Lambda::Url
  Properties:
    TargetFunctionArn: !GetAtt Function.Arn
    AuthType: AWS_IAM"""
_CLOUDFORMATION["CF-LAM-005"] = """$name:
  Type: AWS::Lambda::Function
  Properties:
    Environment:
      Variables:
        DB_SECRET_ARN: !Ref DbSecret  # read the value at runtime with GetSecretValue"""
_CLOUDFORMATION["CF-LAM-006"] = """$name:
  Type: AWS::Lambda::Function
  Properties:
    ReservedConcurrentExecutions: 50  # what the function and its downstreams can take"""
_CLOUDFORMATION["CF-LAM-007"] = """$name:
  Type: AWS::Lambda::Function
  Properties:
    Timeout: 30  # what one batch needs; behind API Gateway, just above its 29 s limit"""
_CLOUDFORMATION["CF-LAM-008"] = """$name:
  Type: AWS::Lambda::Function
  Properties:
    VpcConfig:
      SubnetIds:  # private subnets in at least two AZs
        - !Ref PrivateSubnetA
        - !Ref PrivateSubnetB
      SecurityGroupIds:
        - !Ref FunctionSecurityGroup"""
_TERRAFORM["CF-LAM-004"] = """resource "aws_lambda_function_url" "$tf_name" {
  function_name      = aws_lambda_function.example.function_name
  authorization_type = "AWS_IAM"
}"""
_TERRAFORM["CF-LAM-005"] = """resource "aws_lambda_function" "$tf_name" {
  environment {
    variables = {
      DB_SECRET_ARN = aws_secretsmanager_secret.db.arn # read the value at runtime
    }
  }
}"""
_TERRAFORM["CF-LAM-006"] = """resource "aws_lambda_function" "$tf_name" {
  reserved_concurrent_executions = 50 # what the function and its downstreams can take
}"""
_TERRAFORM["CF-LAM-007"] = """resource "aws_lambda_function" "$tf_name" {
  timeout = 30 # what one batch needs; behind API Gateway, just above its 29 s limit
}"""
_TERRAFORM["CF-LAM-008"] = """resource "aws_lambda_function" "$tf_name" {
  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id] # two AZs or more
    security_group_ids = [aws_security_group.function.id]
  }
}"""
_CLOUDFORMATION["CF-RDS-006"] = """DbParameterGroup:
  Type: AWS::RDS::DBParameterGroup
  Properties:
    Family: postgres16  # match the engine
    Description: Require TLS
    Parameters:
      rds.force_ssl: "1"  # MySQL and MariaDB: require_secure_transport: "ON"
# Then on $name: DBParameterGroupName: !Ref DbParameterGroup
#   (a cluster: AWS::RDS::DBClusterParameterGroup and DBClusterParameterGroupName)"""
_CLOUDFORMATION["CF-RDS-007"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    MonitoringInterval: 60
    MonitoringRoleArn: !GetAtt RdsMonitoringRole.Arn"""
_CLOUDFORMATION["CF-RDS-008"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    EnableIAMDatabaseAuthentication: true"""
_CLOUDFORMATION["CF-RDS-009"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    AutoMinorVersionUpgrade: true"""
_CLOUDFORMATION["CF-RDS-010"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    CopyTagsToSnapshot: true"""
_CLOUDFORMATION["CF-RDS-011"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    EnableCloudwatchLogsExports:
      - postgresql  # MySQL: error, general, slowquery"""
_CLOUDFORMATION["CF-RDS-012"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    Port: "5433"  # not the engine default"""
_CLOUDFORMATION["CF-RDS-013"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    # Set only when the database is created: a new name means a new database.
    MasterUsername: app_owner"""
_CLOUDFORMATION["CF-RDS-014"] = """$name:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceClass: db.r7g.large  # the Graviton class of the same size"""
_TERRAFORM["CF-RDS-006"] = """resource "aws_db_parameter_group" "require_tls" {
  family = "postgres16" # match the engine
  parameter {
    name  = "rds.force_ssl" # MySQL and MariaDB: require_secure_transport = "ON"
    value = "1"
  }
}
# Then on $tf_type.$tf_name: parameter_group_name = aws_db_parameter_group.require_tls.name
# (a cluster: aws_rds_cluster_parameter_group and db_cluster_parameter_group_name)"""
_TERRAFORM["CF-RDS-007"] = """resource "$tf_type" "$tf_name" {
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
}"""
_TERRAFORM["CF-RDS-008"] = """resource "$tf_type" "$tf_name" {
  iam_database_authentication_enabled = true
}"""
_TERRAFORM["CF-RDS-009"] = """resource "$tf_type" "$tf_name" {
  auto_minor_version_upgrade = true
}"""
_TERRAFORM["CF-RDS-010"] = """resource "$tf_type" "$tf_name" {
  copy_tags_to_snapshot = true
}"""
_TERRAFORM["CF-RDS-011"] = """resource "$tf_type" "$tf_name" {
  enabled_cloudwatch_logs_exports = ["postgresql"] # MySQL: error, general, slowquery
}"""
_TERRAFORM["CF-RDS-012"] = """resource "$tf_type" "$tf_name" {
  port = 5433 # not the engine default
}"""
_TERRAFORM["CF-RDS-013"] = """resource "$tf_type" "$tf_name" {
  # Set only when the database is created: a new name means a new database.
  username = "app_owner" # aws_rds_cluster: master_username
}"""
_TERRAFORM["CF-RDS-014"] = """resource "$tf_type" "$tf_name" {
  instance_class = "db.r7g.large" # the Graviton class of the same size
}"""
_CLOUDFORMATION["CF-ALB-002"] = """$name:
  Type: AWS::ElasticLoadBalancingV2::Listener
  Properties:
    LoadBalancerArn: !Ref LoadBalancer
    Protocol: HTTP
    Port: 80
    DefaultActions:
      - Type: redirect
        RedirectConfig:
          Protocol: HTTPS
          Port: "443"
          StatusCode: HTTP_301"""
_CLOUDFORMATION["CF-ALB-003"] = """$name:
  Type: AWS::ElasticLoadBalancingV2::Listener
  Properties:
    SslPolicy: ELBSecurityPolicy-TLS13-1-2-2021-06"""
_CLOUDFORMATION["CF-ALB-004"] = """$name:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties:
    LoadBalancerAttributes:
      - Key: routing.http.drop_invalid_header_fields.enabled
        Value: 'true'"""
_CLOUDFORMATION["CF-ALB-005"] = """$name:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties:
    LoadBalancerAttributes:
      - Key: deletion_protection.enabled
        Value: 'true'"""
_CLOUDFORMATION["CF-ALB-006"] = """$name:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties:
    LoadBalancerAttributes:
      - Key: routing.http.desync_mitigation_mode
        Value: defensive"""
_CLOUDFORMATION["CF-ALB-007"] = """$name:
  Type: AWS::ElasticLoadBalancingV2::TargetGroup
  Properties:
    HealthCheckEnabled: true
    HealthCheckPath: /health  # an endpoint that checks the app and its dependencies"""
_CLOUDFORMATION["CF-CLB-001"] = """$name:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    Listeners:
      - LoadBalancerPort: "443"
        InstancePort: "80"
        Protocol: HTTPS
        SSLCertificateId: !Ref Certificate  # an AWS::CertificateManager::Certificate"""
_CLOUDFORMATION["CF-CLB-002"] = _CLOUDFORMATION["CF-CLB-001"]
_CLOUDFORMATION["CF-CLB-003"] = """$name:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    AccessLoggingPolicy:
      Enabled: true
      EmitInterval: 60
      S3BucketName: !Ref LogBucket"""
_CLOUDFORMATION["CF-CLB-004"] = """$name:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    CrossZone: true"""
_CLOUDFORMATION["CF-CLB-005"] = """$name:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    ConnectionDrainingPolicy:
      Enabled: true
      Timeout: 300"""
_TERRAFORM["CF-ALB-002"] = """resource "aws_lb_listener" "$tf_name" {
  load_balancer_arn = aws_lb.example.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}"""
_TERRAFORM["CF-ALB-003"] = """resource "aws_lb_listener" "$tf_name" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}"""
_TERRAFORM["CF-ALB-004"] = """resource "aws_lb" "$tf_name" {
  drop_invalid_header_fields = true
}"""
_TERRAFORM["CF-ALB-005"] = """resource "aws_lb" "$tf_name" {
  enable_deletion_protection = true
}"""
_TERRAFORM["CF-ALB-006"] = """resource "aws_lb" "$tf_name" {
  desync_mitigation_mode = "defensive"
}"""
_TERRAFORM["CF-ALB-007"] = """resource "aws_lb_target_group" "$tf_name" {
  health_check {
    enabled = true
    path    = "/health" # an endpoint that checks the app and its dependencies
  }
}"""
_TERRAFORM["CF-CLB-001"] = """resource "aws_elb" "$tf_name" {
  listener {
    lb_port            = 443
    lb_protocol        = "https"
    instance_port      = 80
    instance_protocol  = "http"
    ssl_certificate_id = aws_acm_certificate.example.arn
  }
}"""
_TERRAFORM["CF-CLB-002"] = _TERRAFORM["CF-CLB-001"]
_TERRAFORM["CF-CLB-003"] = """resource "aws_elb" "$tf_name" {
  access_logs {
    bucket   = aws_s3_bucket.logs.id
    interval = 60
    enabled  = true
  }
}"""
_TERRAFORM["CF-CLB-004"] = """resource "aws_elb" "$tf_name" {
  cross_zone_load_balancing = true
}"""
_TERRAFORM["CF-CLB-005"] = """resource "aws_elb" "$tf_name" {
  connection_draining         = true
  connection_draining_timeout = 300
}"""

_CLOUDFORMATION["CF-SG-002"] = """$name:
  Type: AWS::EC2::SecurityGroup
  Properties:
    # Replace the all-ports 0.0.0.0/0 (or ::/0) entry with the ports the service needs.
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0"""
_CLOUDFORMATION["CF-SG-002:AWS::EC2::SecurityGroupIngress"] = """$name:
  Type: AWS::EC2::SecurityGroupIngress
  Properties:
    GroupId: !Ref SecurityGroup
    IpProtocol: tcp  # one protocol and port, not -1
    FromPort: 443
    ToPort: 443
    CidrIp: 0.0.0.0/0"""
_CLOUDFORMATION["CF-SG-003"] = """$name:
  Type: AWS::EC2::SecurityGroup
  Properties:
    # Replace the allow-all rule (or the AWS default) with what the workload calls.
    SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        DestinationPrefixListId: pl-12345678  # e.g. the S3 prefix list, or a VPC CIDR"""
_CLOUDFORMATION["CF-SG-003:AWS::EC2::SecurityGroupEgress"] = """$name:
  Type: AWS::EC2::SecurityGroupEgress
  Properties:
    GroupId: !Ref SecurityGroup
    IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    CidrIp: 10.0.0.0/16  # a known destination, not 0.0.0.0/0 on every port"""
_CLOUDFORMATION["CF-NACL-001"] = """$name:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: !Ref NetworkAcl
    RuleNumber: 100
    Protocol: 6
    RuleAction: allow
    Egress: false
    CidrBlock: 10.0.0.0/16  # a known range, not 0.0.0.0/0 or ::/0
    PortRange:
      From: 22
      To: 22"""
_CLOUDFORMATION["CF-NAT-001"] = """# One NAT gateway per AZ: add one in the second AZ's public subnet, and point that AZ's
# private route table at it.
NatGatewayB:
  Type: AWS::EC2::NatGateway
  Properties:
    SubnetId: !Ref PublicSubnetB
    AllocationId: !GetAtt NatEipB.AllocationId"""
_CLOUDFORMATION["CF-TGW-001"] = """$name:
  Type: AWS::EC2::TransitGateway
  Properties:
    AutoAcceptSharedAttachments: disable"""
_CLOUDFORMATION["CF-TGW-002"] = """TransitGatewayFlowLog:
  Type: AWS::EC2::FlowLog
  Properties:
    ResourceType: TransitGateway
    ResourceId: !Ref $name
    LogDestinationType: s3
    LogDestination: !GetAtt FlowLogBucket.Arn"""
_TERRAFORM["CF-SG-002"] = """# Replace the all-ports 0.0.0.0/0 (or ::/0) ingress with the ports the service needs.
resource "aws_security_group" "$tf_name" {
  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}"""
_TERRAFORM["CF-SG-002:aws_security_group_rule"] = """resource "aws_security_group_rule" "$tf_name" {
  type              = "ingress"
  security_group_id = aws_security_group.example.id
  protocol          = "tcp" # one protocol and port, not -1
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
}"""
_TERRAFORM["CF-SG-002:aws_vpc_security_group_ingress_rule"] = """resource "aws_vpc_security_group_ingress_rule" "$tf_name" {
  security_group_id = aws_security_group.example.id
  ip_protocol       = "tcp" # one protocol and port, not -1
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}"""
_TERRAFORM["CF-SG-003"] = """# Replace the allow-all egress with what the workload calls.
resource "aws_security_group" "$tf_name" {
  egress {
    protocol        = "tcp"
    from_port       = 443
    to_port         = 443
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id] # or a VPC CIDR
  }
}"""
_TERRAFORM["CF-SG-003:aws_security_group_rule"] = """resource "aws_security_group_rule" "$tf_name" {
  type              = "egress"
  security_group_id = aws_security_group.example.id
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["10.0.0.0/16"] # a known destination, not 0.0.0.0/0 on every port
}"""
_TERRAFORM["CF-SG-003:aws_vpc_security_group_egress_rule"] = """resource "aws_vpc_security_group_egress_rule" "$tf_name" {
  security_group_id = aws_security_group.example.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "10.0.0.0/16" # a known destination, not 0.0.0.0/0 on every port
}"""
_TERRAFORM["CF-NACL-001"] = """resource "aws_network_acl_rule" "$tf_name" {
  network_acl_id = aws_network_acl.example.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16" # a known range, not 0.0.0.0/0 or ::/0
  from_port      = 22
  to_port        = 22
}"""
_TERRAFORM["CF-NACL-001:aws_network_acl"] = """resource "aws_network_acl" "$tf_name" {
  vpc_id = aws_vpc.example.id
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.0.0/16" # a known range, not 0.0.0.0/0 or ::/0
    from_port  = 22
    to_port    = 22
  }
}"""
_TERRAFORM["CF-NAT-001"] = """# One NAT gateway per AZ, each in that AZ's public subnet. Route each private subnet
# to the NAT gateway in its own AZ.
resource "aws_nat_gateway" "$tf_name" {
  for_each      = aws_subnet.public
  subnet_id     = each.value.id
  allocation_id = aws_eip.nat[each.key].id
}"""
_TERRAFORM["CF-TGW-001"] = """resource "aws_ec2_transit_gateway" "$tf_name" {
  auto_accept_shared_attachments = "disable"
}"""
_TERRAFORM["CF-TGW-002"] = """resource "aws_flow_log" "$tf_name" {
  transit_gateway_id   = aws_ec2_transit_gateway.$tf_name.id
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.flow_logs.arn
}"""

_CLOUDFORMATION["CF-EIP-001"] = """# Not needed: delete $name to release the address. Needed: attach it.
${name}Association:
  Type: AWS::EC2::EIPAssociation
  Properties:
    AllocationId: !GetAtt $name.AllocationId
    InstanceId: !Ref Instance # the instance that needs a fixed public address"""
_TERRAFORM["CF-EIP-001"] = """# Not needed: delete aws_eip.$tf_name to release the address. Needed: attach it.
resource "aws_eip_association" "$tf_name" {
  allocation_id = aws_eip.$tf_name.id
  instance_id   = aws_instance.app.id # the instance that needs a fixed public address
}"""
_TERRAFORM["CF-EBS-002"] = """resource "aws_ebs_volume" "$tf_name" {
  # keep the other arguments as they are
  type = "gp3"
  # over 1,000 GiB: iops = <3 x size in GiB> to keep the gp2 baseline
}"""

# Secrets Manager rotation and Cognito user pools.
_CLOUDFORMATION.update({
    "CF-SM-001": """${name}Rotation:
  Type: AWS::SecretsManager::RotationSchedule
  Properties:
    SecretId: !Ref $name
    # a rotation Lambda you own, or HostedRotationLambda for RDS, Redshift and DocumentDB
    RotationLambdaARN: !GetAtt RotationFunction.Arn
    RotationRules:
      ScheduleExpression: rate(30 days)""",
    "CF-COG-001": """$name:
  Type: AWS::Cognito::UserPool
  Properties:
    # keep the other properties as they are
    MfaConfiguration: "ON"
    EnabledMfas:
      - SOFTWARE_TOKEN_MFA""",
    "CF-COG-002": """$name:
  Type: AWS::Cognito::UserPool
  Properties:
    # keep the other properties as they are
    Policies:
      PasswordPolicy:
        MinimumLength: 12
        RequireLowercase: true
        RequireUppercase: true
        RequireNumbers: true
        RequireSymbols: true""",
    "CF-COG-003": """$name:
  Type: AWS::Cognito::UserPool
  Properties:
    # keep the other properties as they are
    UserPoolTier: PLUS # threat protection needs the Plus feature plan
    UserPoolAddOns:
      AdvancedSecurityMode: ENFORCED""",
})
_TERRAFORM.update({
    "CF-SM-001": """resource "aws_secretsmanager_secret_rotation" "$tf_name" {
  secret_id           = aws_secretsmanager_secret.$tf_name.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn # a rotation Lambda you own
  rotation_rules {
    automatically_after_days = 30
  }
}""",
    "CF-COG-001": """resource "aws_cognito_user_pool" "$tf_name" {
  # keep the other arguments as they are
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }
}""",
    "CF-COG-002": """resource "aws_cognito_user_pool" "$tf_name" {
  # keep the other arguments as they are
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
}""",
    "CF-COG-003": """resource "aws_cognito_user_pool" "$tf_name" {
  # keep the other arguments as they are
  user_pool_tier = "PLUS" # threat protection needs the Plus feature plan
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }
}""",
})

# ECR repositories and ECS task definitions.
_CLOUDFORMATION.update({
    "CF-ECR-001": """$name:
  Type: AWS::ECR::Repository
  Properties:
    # keep the other properties as they are
    ImageScanningConfiguration:
      ScanOnPush: true""",
    "CF-ECR-002": """$name:
  Type: AWS::ECR::Repository
  Properties:
    # keep the other properties as they are
    ImageTagMutability: IMMUTABLE""",
    "CF-ECR-003": """$name:
  Type: AWS::ECR::Repository
  Properties:
    # keep the other properties as they are
    LifecyclePolicy:
      LifecyclePolicyText: |
        {"rules": [{"rulePriority": 1, "description": "Expire untagged images after 14 days",
          "selection": {"tagStatus": "untagged", "countType": "sinceImagePushed",
            "countUnit": "days", "countNumber": 14},
          "action": {"type": "expire"}}]}""",
    "CF-ECS-001": """$name:
  Type: AWS::ECS::TaskDefinition
  Properties:
    # keep the other properties as they are
    ContainerDefinitions:
      - Name: app # each container: keep its other keys as they are
        Privileged: false""",
    "CF-ECS-002": """$name:
  Type: AWS::ECS::TaskDefinition
  Properties:
    # keep the other properties as they are
    ContainerDefinitions:
      - Name: app # each container: keep its other keys as they are
        ReadonlyRootFilesystem: true""",
    "CF-ECS-003": """$name:
  Type: AWS::ECS::TaskDefinition
  Properties:
    # keep the other properties as they are
    ContainerDefinitions:
      - Name: app # each container: keep its other keys as they are
        User: '1000'""",
})
_TERRAFORM.update({
    "CF-ECR-001": """resource "aws_ecr_repository" "$tf_name" {
  # keep the other arguments as they are
  image_scanning_configuration {
    scan_on_push = true
  }
}""",
    "CF-ECR-002": """resource "aws_ecr_repository" "$tf_name" {
  # keep the other arguments as they are
  image_tag_mutability = "IMMUTABLE"
}""",
    "CF-ECR-003": """resource "aws_ecr_lifecycle_policy" "$tf_name" {
  repository = aws_ecr_repository.$tf_name.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 14
      }
      action = { type = "expire" }
    }]
  })
}""",
    "CF-ECS-001": """resource "aws_ecs_task_definition" "$tf_name" {
  # keep the other arguments as they are
  container_definitions = jsonencode([{
    name       = "app" # each container: keep its other keys as they are
    privileged = false
  }])
}""",
    "CF-ECS-002": """resource "aws_ecs_task_definition" "$tf_name" {
  # keep the other arguments as they are
  container_definitions = jsonencode([{
    name                   = "app" # each container: keep its other keys as they are
    readonlyRootFilesystem = true
  }])
}""",
    "CF-ECS-003": """resource "aws_ecs_task_definition" "$tf_name" {
  # keep the other arguments as they are
  container_definitions = jsonencode([{
    name = "app" # each container: keep its other keys as they are
    user = "1000"
  }])
}""",
})

# Stateful resources deleted with the stack.
_CLOUDFORMATION.update({
    "CF-DEL-001": """$name:
  Type: $type
  DeletionPolicy: Retain
  UpdateReplacePolicy: Retain
  Properties:
    # keep the properties as they are
    {}""",
})
for _rds in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
    _CLOUDFORMATION[f"CF-DEL-001:{_rds}"] = _CLOUDFORMATION["CF-DEL-001"].replace(
        "Retain", "Snapshot")
_TERRAFORM.update({
    "CF-DEL-001": """resource "$tf_type" "$tf_name" {
  # keep the other arguments as they are
  lifecycle { # one lifecycle block: add this line to an existing one
    prevent_destroy = true
  }
}""",
})

# Public IPs.
_CLOUDFORMATION.update({
    "CF-EC2-002": """$name:
  Type: AWS::EC2::Subnet
  Properties:
    # keep the other properties as they are
    MapPublicIpOnLaunch: false""",
    "CF-EC2-003": """$name:
  Type: AWS::EC2::Instance
  Properties:
    # keep the other properties as they are
    NetworkInterfaces:
      - DeviceIndex: "0"
        # keep this interface's other keys (SubnetId, GroupSet, ...) as they are
        AssociatePublicIpAddress: false""",
    "CF-EC2-003:AWS::EC2::LaunchTemplate": """$name:
  Type: AWS::EC2::LaunchTemplate
  Properties:
    LaunchTemplateData:
      # keep the other settings as they are
      NetworkInterfaces:
        - DeviceIndex: 0
          # keep this interface's other keys as they are
          AssociatePublicIpAddress: false""",
})
_TERRAFORM.update({
    "CF-EC2-002": """resource "aws_subnet" "$tf_name" {
  # keep the other arguments as they are
  map_public_ip_on_launch = false
}""",
    "CF-EC2-003": """resource "aws_instance" "$tf_name" {
  # keep the other arguments as they are
  associate_public_ip_address = false
}""",
    "CF-EC2-003:aws_launch_template": """resource "aws_launch_template" "$tf_name" {
  # keep the other arguments as they are
  network_interfaces {
    associate_public_ip_address = false
  }
}""",
})

# CloudFront and WAF.
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
    "CF-CF-004": """$name:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      # keep the other settings and the other origins as they are; change the S3 origin:
      Origins:
        - Id: s3  # your S3 origin's Id
          DomainName: !GetAtt MyBucket.RegionalDomainName  # your bucket
          S3OriginConfig:
            OriginAccessIdentity: ""  # no OAI
          # add an AWS::CloudFront::OriginAccessControl named ${name}Oac with
          # OriginAccessControlOriginType: s3, SigningBehavior: always, SigningProtocol: sigv4
          OriginAccessControlId: !GetAtt ${name}Oac.Id
# Bucket policy: allow s3:GetObject to Service cloudfront.amazonaws.com
# with Condition StringEquals AWS:SourceArn = the distribution ARN.""",
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
    "CF-CF-004": """resource "aws_cloudfront_origin_access_control" "$tf_name" {
  name                              = "$tf_name"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "$tf_name" {
  # keep the other arguments and origin blocks as they are; change the S3 origin:
  origin {
    origin_id                = "s3"                                         # your S3 origin's id
    domain_name              = aws_s3_bucket.my_bucket.bucket_regional_domain_name # your bucket
    origin_access_control_id = aws_cloudfront_origin_access_control.$tf_name.id
  }
}
# Bucket policy: allow s3:GetObject to Service cloudfront.amazonaws.com
# with condition StringEquals AWS:SourceArn = aws_cloudfront_distribution.$tf_name.arn""",
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
