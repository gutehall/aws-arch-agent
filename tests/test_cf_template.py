"""Tests for CloudFormation template rules."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules,
    run_cf_rules_from_paths,
)


def test_s3_missing_public_access_block(tmp_path: Path) -> None:
    """S3 bucket without PublicAccessBlockConfiguration should yield CF-S3-001."""
    template = {
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {},
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    ids = [f.id for f in findings]
    assert "CF-S3-001" in ids
    assert any(f.id == "CF-S3-001" and "PublicAccessBlock" in f.recommendation for f in findings)


def test_s3_with_encryption_no_finding(tmp_path: Path) -> None:
    """S3 with encryption and versioning should not yield S3 encryption/versioning findings."""
    template = {
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "BucketEncryption": {"ServerSideEncryptionConfiguration": []},
                    "VersioningConfiguration": {"Status": "Enabled"},
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    ids = [f.id for f in findings]
    assert "CF-S3-001" not in ids
    assert "CF-S3-002" not in ids
    assert "CF-S3-003" not in ids


def test_rds_storage_encryption(tmp_path: Path) -> None:
    """RDS without StorageEncrypted should yield CF-RDS-001."""
    template = {
        "Resources": {
            "MyDB": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "DBInstanceClass": "db.t3.micro",
                    "AllocatedStorage": 20,
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-RDS-001" for f in findings)


def test_s3_server_access_logging_missing(tmp_path: Path) -> None:
    """S3 bucket without LoggingConfiguration should yield CF-S3-004."""
    template = {
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-S3-004" for f in findings)


def test_s3_with_logging_no_s3_004(tmp_path: Path) -> None:
    """S3 with LoggingConfiguration should not yield CF-S3-004."""
    template = {
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "LoggingConfiguration": {"DestinationBucketName": "MyLogBucket", "LogFilePrefix": "logs/"},
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert not any(f.id == "CF-S3-004" for f in findings)


def test_vpc_no_endpoints(tmp_path: Path) -> None:
    """Template with VPC but no VPCEndpoint should yield CF-VPC-001."""
    template = {
        "Resources": {
            "MyVpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-VPC-001" for f in findings)


def test_vpc_with_endpoint_no_vpc_001(tmp_path: Path) -> None:
    """Template with VPC and VPCEndpoint should not yield CF-VPC-001."""
    template = {
        "Resources": {
            "MyVpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
            "S3Endpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {"ServiceName": "com.amazonaws.us-east-1.s3", "VpcId": {"Ref": "MyVpc"}},
            },
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert not any(f.id == "CF-VPC-001" for f in findings)


def test_lambda_no_dlq(tmp_path: Path) -> None:
    """Lambda without DeadLetterConfig should yield CF-LAM-001."""
    template = {
        "Resources": {
            "MyFunc": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.11",
                    "Handler": "index.handler",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                    "Code": {"ZipFile": "def handler(*args): pass"},
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-LAM-001" for f in findings)


def test_dynamodb_no_pitr(tmp_path: Path) -> None:
    """DynamoDB table without PointInTimeRecovery should yield CF-DDB-001."""
    template = {
        "Resources": {
            "MyTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-DDB-001" for f in findings)


def test_security_group_open_ssh(tmp_path: Path) -> None:
    """Security group with 0.0.0.0/0 on port 22 should yield CF-SG-001."""
    template = {
        "Resources": {
            "MySG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "test",
                    "SecurityGroupIngress": [
                        {"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp"},
                    ],
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-SG-001" for f in findings)


def test_log_group_no_retention(tmp_path: Path) -> None:
    """Log group without RetentionInDays should yield CF-CW-001."""
    template = {
        "Resources": {
            "MyLogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": "/my/app"}},
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-CW-001" for f in findings)


def test_vpc_no_flow_log(tmp_path: Path) -> None:
    """Template with VPC but no FlowLog should yield CF-FL-001."""
    template = {
        "Resources": {
            "MyVpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-FL-001" for f in findings)


def test_rds_publicly_accessible(tmp_path: Path) -> None:
    """RDS with PubliclyAccessible true should yield CF-RDS-004."""
    template = {
        "Resources": {
            "MyDB": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "DBInstanceClass": "db.t3.micro",
                    "AllocatedStorage": 20,
                    "StorageEncrypted": True,
                    "PubliclyAccessible": True,
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-RDS-004" for f in findings)


def test_run_cf_rules_from_paths_yaml(tmp_path: Path) -> None:
    """run_cf_rules_from_paths works with YAML template files."""
    yaml_content = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties: {}
"""
    (tmp_path / "stack.yaml").write_text(yaml_content.strip(), encoding="utf-8")
    paths = [tmp_path / "stack.yaml"]
    findings = run_cf_rules_from_paths(paths)
    assert any(f.id == "CF-S3-001" for f in findings)


def test_kms_wildcard_principal(tmp_path: Path) -> None:
    """KMS key with wildcard in KeyPolicy should yield CF-KMS-001."""
    template = {
        "Resources": {
            "MyKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowRoot",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "kms:*",
                                "Resource": "*",
                            }
                        ],
                    }
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-KMS-001" for f in findings)


def test_cloudtrail_log_file_validation(tmp_path: Path) -> None:
    """CloudTrail without EnableLogFileValidation should yield CF-CT-001."""
    template = {
        "Resources": {
            "MyTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "Properties": {
                    "IsLogging": True,
                    "S3BucketName": "my-bucket",
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-CT-001" for f in findings)


def test_cloudtrail_multi_region(tmp_path: Path) -> None:
    """CloudTrail without IsMultiRegionTrail should yield CF-CT-002."""
    template = {
        "Resources": {
            "MyTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "Properties": {
                    "IsLogging": True,
                    "S3BucketName": "my-bucket",
                    "EnableLogFileValidation": True,
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-CT-002" for f in findings)


def test_cloudtrail_kms(tmp_path: Path) -> None:
    """CloudTrail without KmsKeyId should yield CF-CT-003."""
    template = {
        "Resources": {
            "MyTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "Properties": {
                    "IsLogging": True,
                    "S3BucketName": "my-bucket",
                    "EnableLogFileValidation": True,
                    "IsMultiRegionTrail": True,
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-CT-003" for f in findings)


def test_alb_access_logs(tmp_path: Path) -> None:
    """ALB without access_logs.s3.enabled should yield CF-ALB-001."""
    template = {
        "Resources": {
            "MyALB": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internet-facing",
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-ALB-001" for f in findings)


def test_eks_control_plane_logging(tmp_path: Path) -> None:
    """EKS cluster without control plane logging should yield CF-EKS-001."""
    template = {
        "Resources": {
            "MyCluster": {
                "Type": "AWS::EKS::Cluster",
                "Properties": {
                    "Name": "my-cluster",
                    "RoleArn": "arn:aws:iam::123456789012:role/eks-role",
                    "Version": "1.28",
                    "ResourcesVpcConfig": {
                        "SubnetIds": ["subnet-123"],
                    },
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-EKS-001" for f in findings)


def test_two_buckets_keep_distinct_relative_fingerprints(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {}},
            "BucketB": {"Type": "AWS::S3::Bucket", "Properties": {}},
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = [f for f in run_cf_rules(cdk_out) if f.id == "CF-S3-001"]
    assert len(findings) == 2
    assert {f.evidence for f in findings} == {
        "BucketA (AWS::S3::Bucket)",
        "BucketB (AWS::S3::Bucket)",
    }
    assert {f.file for f in findings} == {"cdk.out/mystack.template.json"}


def test_string_redrive_policy_with_target_is_clean(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {}},
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "RedrivePolicy": json.dumps(
                        {"deadLetterTargetArn": "arn:aws:sqs:us-east-1:123:dlq"}
                    )
                },
            },
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    other = tmp_path / "cdk.out" / "other.template.json"
    other.write_text(
        json.dumps({"Resources": {"Trail": {"Type": "AWS::CloudTrail::Trail", "Properties": {}}}}),
        encoding="utf-8",
    )
    warnings: list[str] = []
    findings = run_cf_rules(cdk_out, warnings=warnings)
    ids = {f.id for f in findings}
    assert "CF-S3-001" in ids
    assert "CF-CT-001" in ids
    assert "CF-SQS-002" not in ids
    assert warnings == []


def test_unresolved_redrive_intrinsic_is_not_a_missing_dlq(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"RedrivePolicy": {"Ref": "RedriveParam"}},
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert not any(f.id == "CF-SQS-002" for f in findings)


def test_aurora_member_skips_cluster_level_rds_findings(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "Cluster": {
                "Type": "AWS::RDS::DBCluster",
                "Properties": {
                    "Engine": "aurora-mysql",
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 7,
                    "DeletionProtection": True,
                },
            },
            "Instance": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "DBClusterIdentifier": {"Ref": "Cluster"},
                    "DBInstanceClass": "db.t3.medium",
                    "Engine": "aurora-mysql",
                },
            },
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    standalone = {"CF-RDS-001", "CF-RDS-002", "CF-RDS-003", "CF-RDS-005"}
    assert not any(f.id in standalone for f in findings)


def test_backup_retention_zero_is_a_finding(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "MyDB": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "DBInstanceClass": "db.t3.micro",
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 0,
                    "MultiAZ": True,
                    "DeletionProtection": True,
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert any(f.id == "CF-RDS-002" and "MyDB" in (f.evidence or "") for f in findings)


def test_rest_api_tracing_enabled_is_not_data_trace(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "Stage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": "api",
                    "StageName": "prod",
                    "TracingEnabled": True,
                    "AccessLogSetting": {"DestinationArn": "arn:aws:logs:us-east-1:1:log-group:api"},
                },
            }
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    findings = run_cf_rules(cdk_out)
    assert not any(f.id == "CF-APIGW-002" for f in findings)


def test_string_launch_template_properties_keep_sibling_findings(tmp_path: Path) -> None:
    template = {
        "Resources": {
            "BadLt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": "nope"},
            "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {}},
        }
    }
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "mystack.template.json").write_text(json.dumps(template), encoding="utf-8")
    warnings: list[str] = []
    findings = run_cf_rules(cdk_out, warnings=warnings)
    assert any(f.id == "CF-S3-001" for f in findings)
    assert any("BadLt" in warning for warning in warnings)


def test_drop_static_covered_by_cf() -> None:
    def finding(rule_id: str) -> Finding:
        return Finding(id=rule_id, title=rule_id, recommendation="fix")

    kept = drop_static_covered_by_cf(
        [
            finding("SEC-005"),
            finding("SEC-006"),
            finding("SEC-022"),
            finding("OPS-002"),
            finding("SEC-001"),
            finding("CF-S3-001"),
            finding("CF-S3-002"),
            finding("CF-VPC-001"),
            finding("CF-FL-001"),
        ]
    )
    ids = [item.id for item in kept]
    assert ids == ["SEC-001", "CF-S3-001", "CF-S3-002", "CF-VPC-001", "CF-FL-001"]
    untouched = drop_static_covered_by_cf([finding("SEC-005")])
    assert [item.id for item in untouched] == ["SEC-005"]
