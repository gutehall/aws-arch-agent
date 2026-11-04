"""CF-EKS-002 (public API endpoint) and CF-EKS-003 (secrets encryption)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import _k8s_minor, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes, strip_cdk_hint
from aws_arch_agent.rules.terraform_model import resources_from_terraform

EKS_IDS = {"CF-EKS-002", "CF-EKS-003"}
KEY = [{"Provider": {"KeyArn": "arn:aws:kms:eu-north-1:1:key/k"}, "Resources": ["secrets"]}]


def _cluster(**props) -> dict:
    return {"Type": "AWS::EKS::Cluster", "Properties": {"RoleArn": "arn:aws:iam::1:role/eks", **props}}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in EKS_IDS]


def _by_name(findings: list[Finding], check_id: str) -> dict[str, str]:
    return {f.evidence.split(" ")[0]: f.severity for f in findings if f.id == check_id}


def test_cloudformation_public_endpoint(tmp_path: Path) -> None:
    private = {"EndpointPublicAccess": False, "EndpointPrivateAccess": True}
    found = _by_name(_cf(tmp_path, {
        "Default": _cluster(ResourcesVpcConfig={"SubnetIds": ["s-1"]}),
        "NoVpcConfig": _cluster(),
        "OpenCidr": _cluster(ResourcesVpcConfig={"PublicAccessCidrs": ["10.0.0.0/8", "0.0.0.0/0"]}),
        "OpenV6": _cluster(ResourcesVpcConfig={"PublicAccessCidrs": ["::/0"]}),
        "Limited": _cluster(ResourcesVpcConfig={"PublicAccessCidrs": ["203.0.113.0/24"]}),
        "Private": _cluster(ResourcesVpcConfig=private),
        "PublicFromParam": _cluster(ResourcesVpcConfig={"EndpointPublicAccess": {"Ref": "Public"},
                                                         "PublicAccessCidrs": ["203.0.113.0/24"]}),
        "CidrsFromParam": _cluster(ResourcesVpcConfig={"PublicAccessCidrs": {"Ref": "Cidrs"}}),
        "WholeIf": _cluster(ResourcesVpcConfig={"Fn::If": ["Prod", private, {}]}),
    }), "CF-EKS-002")
    assert found == {"Default": "High", "NoVpcConfig": "High", "OpenCidr": "High", "OpenV6": "High"}


def test_cloudformation_secrets_encryption(tmp_path: Path) -> None:
    found = _by_name(_cf(tmp_path, {
        "Encrypted": _cluster(EncryptionConfig=KEY),
        "OtherResources": _cluster(EncryptionConfig=[{"Provider": {"KeyArn": "k"}, "Resources": ["configmaps"]}]),
        "Old": _cluster(Version="1.27"),
        "OldUnquotedYaml": _cluster(Version=1.2),  # YAML 1.20 -> 1.2
        "Current": _cluster(Version="1.31"),
        "CurrentUnquotedYaml": _cluster(Version=1.3),  # YAML 1.30 -> 1.3
        "Unset": _cluster(),
        "VersionParam": _cluster(Version={"Ref": "K8s"}),
        "FromIf": _cluster(EncryptionConfig=[{"Fn::If": ["C", KEY[0], {}]}]),
        "EmptyList": _cluster(EncryptionConfig=[]),
        "ResourcesParam": _cluster(EncryptionConfig=[{"Provider": {"KeyArn": "k"}, "Resources": {"Ref": "R"}}]),
    }), "CF-EKS-003")
    assert found == {
        "OtherResources": "Low",
        "Old": "Medium",
        "OldUnquotedYaml": "Medium",
        "Current": "Low",
        "CurrentUnquotedYaml": "Low",
        "Unset": "Low",
        "VersionParam": "Low",
        "EmptyList": "Low",
    }


@pytest.mark.parametrize(
    ("version", "minor"),
    [("1.27", 27), ("1.30", 30), (1.3, 30), (1.29, 29), ("2.0", None), ("latest", None), (True, None), (None, None)],
)
def test_k8s_minor(version, minor) -> None:
    assert _k8s_minor(version) == minor


TF = """\
resource "aws_eks_cluster" "default" {
  name     = "a"
  role_arn = "arn"
  vpc_config {
    subnet_ids = ["s-1"]
  }
}

resource "aws_eks_cluster" "locked" {
  name     = "b"
  role_arn = "arn"
  version  = "1.26"
  vpc_config {
    subnet_ids              = ["s-1"]
    endpoint_private_access = true
    endpoint_public_access  = false
  }
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }
}

resource "aws_eks_cluster" "limited_old" {
  name     = "c"
  role_arn = "arn"
  version  = "1.27"
  vpc_config {
    subnet_ids          = ["s-1"]
    public_access_cidrs = ["203.0.113.0/24"]
  }
}

resource "aws_eks_cluster" "from_vars" {
  name     = "d"
  role_arn = "arn"
  version  = var.k8s_version
  vpc_config {
    subnet_ids          = ["s-1"]
    public_access_cidrs = var.cidrs
  }
  dynamic "encryption_config" {
    for_each = var.kms_arn == null ? [] : [1]
    content {
      provider {
        key_arn = var.kms_arn
      }
      resources = ["secrets"]
    }
  }
}

resource "aws_eks_cluster" "dynamic_vpc" {
  name     = "e"
  role_arn = "arn"
  version  = "1.30"
  dynamic "vpc_config" {
    for_each = [1]
    content {
      subnet_ids = ["s-1"]
    }
  }
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }
}
"""


def _tf(tmp_path: Path) -> list[Finding]:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    return run_resource_checks(resources_from_terraform(tmp_path), tmp_path / "main.tf")


def test_terraform_clusters(tmp_path: Path) -> None:
    findings = _tf(tmp_path)
    assert _by_name(findings, "CF-EKS-002") == {"aws_eks_cluster.default": "High"}
    assert _by_name(findings, "CF-EKS-003") == {
        "aws_eks_cluster.default": "Low",
        "aws_eks_cluster.limited_old": "Medium",
    }


def test_fixes_in_both_languages(tmp_path: Path) -> None:
    tf = {(f.id, f.evidence.split(" ")[0]): f for f in attach_fixes(_tf(tmp_path), "terraform")}
    assert "endpoint_public_access  = false" in tf[("CF-EKS-002", "aws_eks_cluster.default")].suggested_code
    assert 'resources = ["secrets"]' in tf[("CF-EKS-003", "aws_eks_cluster.default")].suggested_code
    cf = attach_fixes(_cf(tmp_path, {"C": _cluster()}), "cloudformation")
    assert {f.id for f in cf if f.suggested_code} == EKS_IDS
    assert all("In CDK" not in f.recommendation for f in cf)


def test_cdk_hints_are_stripped_for_raw_templates(tmp_path: Path) -> None:
    for finding in _cf(tmp_path, {"C": _cluster()}):
        stripped = strip_cdk_hint(finding.recommendation)
        assert "In CDK" not in stripped and stripped.endswith(".")
