"""How much work each rule's fix is (DM3-550). Rules not listed are medium.

low: one property or attribute, changed in place without replacing the resource or
breaking callers (versioning, retention, tracing, gp2 -> gp3, NoEcho, a tag).
high: the fix replaces the resource, changes its design, or needs work outside the
template (encrypting an existing database or volume, which CloudFormation does by
replacement; a private EKS endpoint, which needs a VPN or bastion; non-root containers,
which need image changes).
"""
from __future__ import annotations

from typing import Iterable

from aws_arch_agent.models import Effort, Finding

LOW: frozenset[str] = frozenset({
    "CF-S3-001", "CF-S3-002", "CF-S3-003", "CF-S3-004", "CF-CT-001", "CF-CT-002",
    "CF-CW-001", "CF-LAM-002", "CF-APIGW-001", "CF-APIGW-002", "CF-APIGW-V2-001",
    "CF-APIGW-V2-002", "CF-SQS-001", "CF-SNS-001", "CF-DDB-001", "CF-DDB-002", "CF-RDS-002",
    "CF-RDS-005", "CF-ECR-001", "CF-ECR-002", "CF-ECR-003", "CF-EBS-002", "CF-EIP-001",
    "CF-CF-001", "CF-CF-002", "CF-PAR-001", "CF-DEL-001", "CF-TAG-001", "CF-EKS-001",
    "CF-ALB-001",
})
HIGH: frozenset[str] = frozenset({
    # Encryption at rest on an existing store: CloudFormation replaces the resource.
    "CF-RDS-001", "CF-EBS-001", "CF-EFS-001", "CF-EC-001", "CF-OS-001", "CF-RS-001",
    "CF-DOCDB-001", "CF-NEP-001", "CF-MSK-001",
    # Architecture: NAT traffic, a public EKS endpoint, running containers as non-root.
    "CF-COST-002", "CF-EKS-002", "CF-ECS-003",
})


def effort_of(rule_id: str) -> Effort:
    if rule_id in LOW:
        return "low"
    if rule_id in HIGH:
        return "high"
    return "medium"


def annotate(findings: Iterable[Finding]) -> None:
    """Set each finding's effort from its rule id. Mutates the findings."""
    for finding in findings:
        finding.effort = effort_of(finding.id)
