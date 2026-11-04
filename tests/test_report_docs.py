"""AWS documentation links resolved from a finding's title and pillar."""
import re

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.report.docs import PILLAR_DOCS, doc_links
from aws_arch_agent.rules.registry import ALL_RULES


def _finding(title: str, category: str = "Security") -> Finding:
    return Finding(id="X-1", title=title, category=category, recommendation="r")


@pytest.mark.parametrize(
    ("title", "label"),
    [
        ("S3 bucket may miss Block Public Access", "Amazon S3"),
        ("VPC endpoints missing (security & cost improvement)", "AWS PrivateLink and VPC endpoints"),
        ("VPC has no flow logs in this template", "VPC Flow Logs"),
        ("WAF not enabled on ALB/API Gateway/CloudFront", "AWS WAF"),
        ("ALB/NLB not enforcing HTTPS redirect", "Application Load Balancers"),
        ("Aurora not using I/O-Optimized for high I/O workloads", "Amazon Aurora"),
        ("RDS Proxy not used for connection pooling", "Amazon RDS Proxy"),
        ("S3 Storage Lens not enabled", "Amazon S3 Storage Lens"),
        ("Log group has no retention period (infinite retention)", "Amazon CloudWatch Logs"),
        ("Lambda not in VPC when accessing RDS/ElastiCache", "AWS Lambda"),
    ],
)
def test_specific_service_wins_over_broad_one(title: str, label: str) -> None:
    assert doc_links(_finding(title))[0]["label"] == label


def test_pillar_link_is_always_last() -> None:
    links = doc_links(_finding("RDS Multi-AZ not enabled", "Reliability"))
    assert links[-1]["url"] == PILLAR_DOCS["Reliability"][1]


def test_unmatched_title_gets_pillar_only() -> None:
    links = doc_links(_finding("Consider managed services over self-managed", "Sustainability"))
    assert links == [{"label": PILLAR_DOCS["Sustainability"][0], "url": PILLAR_DOCS["Sustainability"][1]}]


def test_unknown_category_falls_back_to_framework() -> None:
    links = doc_links(_finding("Something new", "Made Up"))
    assert links[-1]["url"].endswith("/wellarchitected/latest/framework/welcome.html")


def test_every_rule_gets_aws_docs_links() -> None:
    for rule in ALL_RULES:
        links = doc_links(_finding(rule.title, rule.category))
        assert links, rule.id
        for link in links:
            assert re.fullmatch(r"https://docs\.aws\.amazon\.com/[\w./-]*", link["url"]), rule.id


def test_every_pillar_used_by_rules_has_a_page() -> None:
    assert {rule.category for rule in ALL_RULES} <= set(PILLAR_DOCS) | {"Best Practices"}
