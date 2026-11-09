"""Text from the scanned repo must stay inside its code span or fence in the Markdown report."""
import pytest

from aws_arch_agent.cli import _finding_location
from aws_arch_agent.models import Finding, Hypothesis, RepoContext, Verdict
from aws_arch_agent.report.markdown import _fence, _span_text, render_markdown
from aws_arch_agent.report.summary import build_summary


def _finding(**overrides) -> Finding:
    fields = {"id": "SEC-001", "title": "t", "severity": "High", "category": "Security",
              "file": "lib/stack.ts", "line": 2, "recommendation": "r"}
    return Finding(**(fields | overrides))


def _render(*findings: Finding) -> str:
    return render_markdown(RepoContext(repo_path="/repo"), list(findings))


@pytest.mark.parametrize(
    "text, expected",
    [
        ("lib/my stack.ts", "lib/my stack.ts"),
        ("a`b.ts", "a'b.ts"),
        ("a\nb.ts", "a b.ts"),
        ("a\r\n\t  b.ts", "a b.ts"),
        ("a\x07b\x00.ts\x7f", "ab.ts"),
        ("a \x07 b", "a b"),
        ("\na\n", "a"),
    ],
)
def test_span_text(text: str, expected: str) -> None:
    assert _span_text(text) == expected


@pytest.mark.parametrize(
    "evidence, expected",
    [
        ("plain", "```"),
        ("a `span` here", "```"),
        ("``two``", "```"),
        ("```\ncode\n```", "````"),
        ("`````", "``````"),
    ],
)
def test_the_fence_is_longer_than_any_backtick_run(evidence: str, expected: str) -> None:
    assert _fence(evidence) == expected


def test_a_finding_file_stays_on_its_line_and_in_its_span() -> None:
    report = _render(_finding(file="lib/a`b\n## Injected.ts"))
    assert "- File: `lib/a'b ## Injected.ts` (line 2)\n" in report
    assert "\n## Injected" not in report


def test_the_summary_keeps_a_file_in_its_span_and_the_json_location_exact() -> None:
    file = "lib/a`b\n![x](http://e/i).ts"
    finding = _finding(file=file, suggested_code="fix")
    report = _render(finding)
    assert ", e.g. `lib/a'b ![x](http://e/i).ts:2`" in report
    assert build_summary([finding])["top_fixes"][0]["first_location"] == f"{file}:2"


def test_the_baseline_section_keeps_a_file_in_its_span() -> None:
    assert _finding_location(_finding(file="a`b\nc.ts")) == " `a'b c.ts` line 2"
    assert _finding_location(_finding(file="a`b\nc.ts", line=None)) == " `a'b c.ts`"


def test_cost_section_names_and_files_stay_in_their_spans() -> None:
    cost = {
        "region": "us-east-1", "basis": "b", "total_monthly_usd": 1.0, "not_priced": {},
        "stacks": [{"name": "s`t\n## Injected", "resources_priced": 1, "monthly_usd": 1.0}],
        "top_resources": [{"name": "n`\n## Injected", "type": "AWS::S3::Bucket", "file": "f`\n## Injected",
                           "line": 1, "monthly_usd": 1.0, "basis": "b"}],
    }
    report = render_markdown(RepoContext(repo_path="/repo", notes={"cost": cost}), [])
    assert "`s't ## Injected`" in report
    assert "`n' ## Injected`" in report
    assert "`f' ## Injected`" in report
    assert "\n## Injected" not in report


def test_the_repo_path_stays_in_its_span() -> None:
    assert "- Repo: `/a'b c`\n" in render_markdown(RepoContext(repo_path="/a`b\nc"), [])


def test_suggested_code_with_a_fence_cannot_close_its_block() -> None:
    code = "```\n## Injected\n```"
    assert f"**Suggested Code**\n````\n{code}\n````\n" in _render(_finding(suggested_code=code))


def test_a_verdict_why_stays_in_its_span() -> None:
    finding = _finding(verdict=Verdict(verdict="confirm", why="x`y\nz"))
    assert "- LLM verdict: **confirmed** — `x'y z`\n" in _render(finding)


def test_a_hypothesis_file_and_why_stay_in_their_spans() -> None:
    ctx = RepoContext(repo_path="/repo", hypotheses=[
        Hypothesis(rule_id="SEC-001", title="t", file="a\nb.ts", line=1, why="x`\n\x07y")
    ])
    assert "- [SEC-001] t: `a b.ts` (line 1) — `x' y`\n" in render_markdown(ctx, [])


def test_evidence_with_a_fence_cannot_close_its_block() -> None:
    evidence = "before\n```\n## Injected\n```"
    assert f"**Evidence**\n````\n{evidence}\n````\n" in _render(_finding(evidence=evidence))


def test_ordinary_paths_and_evidence_render_as_before() -> None:
    report = _render(_finding(file="lib/my-stack_1.ts", evidence="Action: `*`"))
    assert "- File: `lib/my-stack_1.ts` (line 2)\n" in report
    assert "**Evidence**\n```\nAction: `*`\n```\n" in report


def test_a_warning_stays_on_its_line_and_in_its_span() -> None:
    report = render_markdown(RepoContext(repo_path="/repo"), [], warnings=["bad `file\n## Injected"])
    assert "- `bad 'file ## Injected`\n" in report
    assert "\n## Injected" not in report
