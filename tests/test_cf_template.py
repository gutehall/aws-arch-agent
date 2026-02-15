"""Tests for CloudFormation template rules."""
from pathlib import Path
import json

from aws_arch_agent.rules.cf_template import run_cf_rules


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
