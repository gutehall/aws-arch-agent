"""AWS documentation links resolved from a finding's title and pillar."""
import re
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.report.doc_topics import RULE_TOPICS, TOPICS
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


def _template_check_ids() -> set[str]:
    rules = Path(__file__).resolve().parents[1] / "src" / "aws_arch_agent" / "rules"
    found: set[str] = set()
    for module in rules.glob("*.py"):
        found |= set(re.findall(r'"(CF-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3})"', module.read_text(encoding="utf-8")))
    return found


def test_every_rule_and_template_check_has_a_topic() -> None:
    ids = {rule.id for rule in ALL_RULES} | _template_check_ids()
    assert sorted(ids - set(RULE_TOPICS)) == []


def test_every_topic_is_used_and_every_rule_points_at_a_topic() -> None:
    assert set(RULE_TOPICS.values()) == set(TOPICS)


@pytest.mark.parametrize("topic", sorted(TOPICS))
def test_topic_links_name_a_page_not_a_start_page(topic: str) -> None:
    _, path, wa_label, wa_path = TOPICS[topic]
    assert re.fullmatch(r"/[\w./-]+\.html(#[\w-]+)?", path), path
    assert re.fullmatch(r"/wellarchitected/latest/[\w-]+-pillar/[a-z0-9_]+\.html", wa_path), wa_path
    assert not wa_path.endswith(("/welcome.html", "/sustainability-pillar.html")), wa_path
    assert re.match(r"Well-Architected [A-Z]+\d\d-BP\d\d: ", wa_label), wa_label


def test_mapped_rule_links_to_its_control_and_best_practice() -> None:
    links = doc_links(Finding(id="CF-S3-002", title="S3 bucket encryption explicitly disabled",
                              category="Security", recommendation="r"))
    assert links == [
        {"label": "Amazon S3: default bucket encryption",
         "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"},
        {"label": "Well-Architected SEC08-BP02: Enforce encryption at rest",
         "url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_encrypt.html"},
    ]


def test_html_report_shows_the_mapped_links() -> None:
    from aws_arch_agent.models import RepoContext
    from aws_arch_agent.report.html import render_html

    html = render_html(RepoContext(repo_path="/r"), [Finding(
        id="CF-RDS-003", title="RDS Multi-AZ not enabled", category="Reliability", recommendation="r")])
    assert "/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html" in html
    assert "rel_fault_isolation_multiaz_region_system.html" in html
    assert "reliability-pillar/welcome.html" not in html
