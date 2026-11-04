"""HTML report: one self-contained page with counts, tabs, and escaped finding text."""
from datetime import datetime

import pytest

from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.html import render_html

CTX = RepoContext(repo_path="/repo", source="terraform", files_scanned=12)


def _findings() -> list[Finding]:
    return [
        Finding(id="LOW-1", title="Low one", severity="Low", category="Cost Optimization",
                recommendation="Tune it."),
        Finding(id="CF-S3-001", title="Bucket is public", severity="High", category="Security",
                file="infra/main.tf", line=5, evidence="aws_s3_bucket.data (aws_s3_bucket)",
                recommendation="Block public access.",
                suggested_code='resource "aws_s3_bucket_public_access_block" "b" {}'),
        Finding(id="MED-1", title="Medium one", severity="Medium", category="Reliability",
                file="lib/stack.ts", recommendation="Add a DLQ."),
    ]


def test_page_has_context_counts_and_tabs() -> None:
    page = render_html(CTX, _findings(), warnings=["CF rule failed"],
                       generated=datetime(2026, 11, 4, 9, 30))
    assert page.startswith("<!DOCTYPE html>")
    for text in ("/repo", "terraform", "12", "2026-11-04 09:30", "CF rule failed"):
        assert text in page
    assert 'data-tab="All"' in page and "All (3)" in page
    for sev in ("High", "Medium", "Low"):
        assert f'data-tab="{sev}"' in page and f"{sev} (1)" in page
    assert '<div class="n">1</div><div class="label">Warnings</div>' in page


def test_findings_are_ordered_by_severity_with_all_fields() -> None:
    page = render_html(CTX, _findings())
    assert page.index("CF-S3-001") < page.index("MED-1") < page.index("LOW-1")
    for text in ("Bucket is public", "Security", "infra/main.tf:5", "Block public access.",
                 "aws_s3_bucket.data (aws_s3_bucket)", "lib/stack.ts"):
        assert text in page
    assert "aws_s3_bucket_public_access_block" in page


def test_page_is_self_contained() -> None:
    page = render_html(CTX, _findings())
    assert "<style>" in page and "<script>" in page
    assert "<link" not in page and "src=" not in page
    assert "http://" not in page and "https://" not in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page


def test_evidence_and_code_are_escaped() -> None:
    nasty = Finding(id="X-1", title="<b>t</b>", severity="High", category="Security",
                    evidence="<script>alert(1)</script>", recommendation="r & <i>",
                    suggested_code="</pre><script>alert(2)</script>")
    page = render_html(CTX, [nasty], warnings=["<img src=x onerror=alert(3)>"])
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;/pre&gt;&lt;script&gt;alert(2)&lt;/script&gt;" in page
    assert "<img" not in page and "&lt;b&gt;t&lt;/b&gt;" in page
    assert page.count("<script>") == 1


def test_no_findings_shows_empty_state() -> None:
    page = render_html(CTX, [])
    assert "All (0)" in page
    assert '<p class="empty">No findings.</p>' in page


def test_baselined_flags_label_each_finding() -> None:
    findings = _findings()  # LOW-1, CF-S3-001, MED-1
    page = render_html(CTX, findings, baselined=[True, False, True])
    assert "2 accepted, 1 new" in page
    assert '<article class="finding" data-severity="High" data-baseline="new">' in page
    assert page.count('data-baseline="accepted">') == 2


def test_baselined_must_match_findings() -> None:
    with pytest.raises(ValueError):
        render_html(CTX, _findings(), baselined=[True])


def _many() -> list[Finding]:
    def f(fid: str, sev: str) -> Finding:
        return Finding(id=fid, title=f"title {fid}", severity=sev, category="Security",
                       recommendation="fix")

    return [
        f("H-1", "High"), f("L-1", "Low"), f("M-1", "Medium"),
        f("H-2", "High"), f("H-3", "High"), f("L-2", "Low"),
    ]


def test_counts_match_the_findings_passed_in() -> None:
    page = render_html(CTX, _many(), warnings=["w1", "w2"])
    assert '<div class="count High"><div class="n">3</div>' in page
    assert '<div class="count Medium"><div class="n">1</div>' in page
    assert '<div class="count Low"><div class="n">2</div>' in page
    assert '<div class="n">2</div><div class="label">Warnings</div>' in page
    for label in ("All (6)", "High (3)", "Medium (1)", "Low (2)"):
        assert label in page
    assert page.count('data-severity="High"') == 3
    assert page.count('data-severity="Medium"') == 1
    assert page.count('data-severity="Low"') == 2


def test_every_finding_appears_once() -> None:
    findings = _many()
    page = render_html(CTX, findings)
    assert page.count('<article class="finding"') == len(findings)
    for finding in findings:
        assert page.count(f'<span class="id">{finding.id}</span>') == 1
