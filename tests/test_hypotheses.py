"""The model may name catalog rules the scanner missed, and that never becomes a finding."""
import json
import re
from pathlib import Path
from typing import Callable
from unittest.mock import patch

import pytest
import requests
from typer.testing import CliRunner

from aws_arch_agent import cli
from aws_arch_agent.agent import v1, v2_graph
from aws_arch_agent.agent.hypotheses import (
    HYPOTHESIS_SYSTEM,
    MAX_FILE_CHARS,
    MAX_SLICE_CHARS,
    build_slice,
    find_hypotheses,
    parse_reply,
)
from aws_arch_agent.agent.v1 import analyze_v1, iac_files
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.agent.verdicts import VERDICT_SYSTEM
from aws_arch_agent.baseline import merge_into_baseline
from aws_arch_agent.cli import _should_fail, app
from aws_arch_agent.models import Finding, Hypothesis, RepoContext
from aws_arch_agent.report.html import render_html
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.report.sarif import render_sarif
from aws_arch_agent.tools.llm import LLMResult

RULE = "SEC-001"
LOUD = 'import * as cdk from "aws-cdk-lib";\nconst policy = { Action: "*", Resource: "*" };\n'
QUIET = 'import * as cdk from "aws-cdk-lib";\nconst region = "eu-north-1";\nexport { region };\n'
QUIET_FILE = "lib/quiet.ts"
SHOWN = {QUIET_FILE: 3}
runner = CliRunner()


def _ok(text: str) -> LLMResult:
    return LLMResult(text, "ok", "ollama", "llama3:8b")


def _item(**overrides) -> dict:
    return {"rule_id": RULE, "file": QUIET_FILE, "line": 2, "why": "no encryption"} | overrides


def _finding(file: str = "lib/loud.ts", line: int = 2, rule: str = RULE) -> Finding:
    return Finding(id=rule, title="t", severity="High", category="Security", file=file, line=line,
                   recommendation="r")


def _hypothesis() -> Hypothesis:
    return Hypothesis(rule_id=RULE, title="A title", file=QUIET_FILE, line=2, why="no encryption")


class FakeLLM:
    def __init__(self, reply: Callable[[str, str], LLMResult]) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def polish(self, prompt: str, system: str = "") -> LLMResult:
        self.calls.append((prompt, system))
        return self.reply(prompt, system)

    def asked(self, system: str) -> list[str]:
        return [prompt for prompt, used in self.calls if used == system]


def _answering(hypotheses: list[dict]) -> Callable[[str, str], LLMResult]:
    def reply(_prompt: str, system: str) -> LLMResult:
        return _ok(json.dumps(hypotheses if system == HYPOTHESIS_SYSTEM else []))

    return reply


def _use(monkeypatch: pytest.MonkeyPatch, reply: Callable[[str, str], LLMResult]) -> FakeLLM:
    fake = FakeLLM(reply)
    monkeypatch.setattr(v1, "LLMClient", lambda: fake)
    monkeypatch.setattr(v2_graph, "LLMClient", lambda: fake)
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    return fake


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "loud.ts").write_text(LOUD, encoding="utf-8")
    (tmp_path / "lib" / "quiet.ts").write_text(QUIET, encoding="utf-8")
    return tmp_path


# Keeping a hypothesis


def _parse(items, findings=(), shown=None, repo_path=Path("/repo")):
    return parse_reply(json.dumps(items), SHOWN if shown is None else shown, list(findings), repo_path)


def test_a_valid_hypothesis_is_kept_with_the_catalog_title() -> None:
    kept = _parse([_item()])
    assert [(h.rule_id, h.file, h.line, h.why) for h in kept] == [(RULE, QUIET_FILE, 2, "no encryption")]
    assert kept[0].title
    assert kept[0].unverified is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule_id": "SEC-99999"},
        {"rule_id": 1},
        {"file": "lib/other.ts"},
        {"file": None},
        {"line": 0},
        {"line": 4},
        {"line": "2"},
        {"line": True},
        {"why": ""},
        {"why": None},
    ],
)
def test_a_hypothesis_outside_the_prompt_is_dropped(overrides: dict) -> None:
    assert _parse([_item(**overrides)]) == []


@pytest.mark.parametrize("missing", ["rule_id", "file", "line", "why"])
def test_a_hypothesis_missing_a_field_is_dropped(missing: str) -> None:
    item = _item()
    del item[missing]
    assert _parse([item]) == []


def test_a_hypothesis_on_a_finding_file_and_line_is_dropped_whatever_the_rule() -> None:
    other_rule = _finding(file=QUIET_FILE, line=2, rule="COST-001")
    assert _parse([_item()], findings=[other_rule]) == []
    assert len(_parse([_item(line=3)], findings=[other_rule])) == 1


def test_a_finding_with_an_absolute_path_still_matches(tmp_path: Path) -> None:
    absolute = _finding(file=str(tmp_path / QUIET_FILE), line=2)
    assert _parse([_item()], findings=[absolute], repo_path=tmp_path) == []


def test_a_repeated_hypothesis_is_kept_once() -> None:
    assert len(_parse([_item(), _item()])) == 1


def test_why_is_cleaned_to_one_line() -> None:
    assert _parse([_item(why="two\n\nlines\x07")])[0].why == "two lines"


@pytest.mark.parametrize("text", ["not json", '{"other": []}', "7", "null"])
def test_a_body_that_is_not_the_json_asked_for_is_none(text: str) -> None:
    assert parse_reply(text, SHOWN, [], Path("/repo")) is None


def test_a_fenced_or_wrapped_reply_is_read() -> None:
    body = json.dumps({"hypotheses": [_item()]})
    assert len(parse_reply(f"```json\n{body}\n```", SHOWN, [], Path("/repo"))) == 1


# The slice


def test_the_slice_has_only_files_with_no_finding(repo: Path) -> None:
    blocks, shown = build_slice(iac_files(repo, "cdk"), repo, [_finding()])
    assert shown == {QUIET_FILE: len(QUIET.split("\n"))}
    assert blocks[0].startswith(f"File: {QUIET_FILE}\n")
    assert '     2| const region = "eu-north-1";' in blocks[0]


def test_the_slice_is_capped_per_file_and_in_all(tmp_path: Path) -> None:
    for number in range(12):
        (tmp_path / f"f{number:02}.tf").write_text("x = 1\n" * 5000, encoding="utf-8")
    blocks, shown = build_slice(sorted(tmp_path.glob("*.tf")), tmp_path, [])
    assert sum(len(block) for block in blocks) <= MAX_SLICE_CHARS + 12 * len("File: f00.tf\n")
    assert all(len(block) <= MAX_FILE_CHARS + len("File: f00.tf\n") for block in blocks)
    assert len(shown) < 12


def test_a_line_past_the_slice_is_dropped(tmp_path: Path) -> None:
    (tmp_path / "big.tf").write_text("x = 1\n" * 5000, encoding="utf-8")
    _, shown = build_slice([tmp_path / "big.tf"], tmp_path, [])
    assert shown["big.tf"] < 5000
    item = _item(file="big.tf", line=shown["big.tf"] + 1)
    assert parse_reply(json.dumps([item]), shown, [], tmp_path) == []


def test_a_link_out_of_the_repo_is_not_read(tmp_path: Path) -> None:
    secret = tmp_path / "secret.tf"
    secret.write_text("password = 1\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "link.tf").symlink_to(secret)
    assert build_slice([root / "link.tf"], root, []) == ([], {})


def test_iac_files_follow_the_source(tmp_path: Path) -> None:
    for name, text in {
        "main.tf": "x = 1",
        "README.md": "aws-cdk",
        "lib/stack.ts": "aws-cdk-lib",
        "lib/util.ts": "plain",
        "lib/types.d.ts": "aws-cdk-lib",
        "lib/stack.test.ts": "aws-cdk-lib",
        "test/helper.ts": "aws-cdk-lib",
        "app.py": "import aws_cdk",
    }.items():
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
    names = lambda source: {p.relative_to(tmp_path).as_posix() for p in iac_files(tmp_path, source)}  # noqa: E731
    assert names("cdk") == {"lib/stack.ts", "app.py"}
    assert names("terraform") == {"main.tf"}


# The call


def test_no_quiet_file_means_no_call(repo: Path) -> None:
    fake = FakeLLM(_answering([]))
    assert find_hypotheses(fake, [], repo, []) == ([], None)
    assert fake.calls == []


def test_the_prompt_has_catalog_reported_ids_slice_and_markers(repo: Path) -> None:
    fake = FakeLLM(_answering([]))
    find_hypotheses(fake, [_finding(rule="COST-001")], repo, iac_files(repo, "cdk"), synth_summary="SYNTH")
    prompt, system = fake.calls[0]
    assert system == HYPOTHESIS_SYSTEM
    assert f"\n{RULE}: " in prompt
    assert "already reported elsewhere in this repo: COST-001" in prompt
    assert f"File: {QUIET_FILE}" in prompt
    assert "## Synth summary\nSYNTH" in prompt
    marker = prompt.split("<<<DATA_")[1].split(">>>")[0]
    data = prompt.rsplit(f"<<<DATA_{marker}>>>", 1)[1].split(f"<<<END_DATA_{marker}>>>")[0]
    assert f"File: {QUIET_FILE}" in data
    assert "## Synth summary" in data
    assert "## Catalog" not in data


def test_an_unusable_reply_is_retried_once_then_invalid(repo: Path) -> None:
    fake = FakeLLM(lambda _p, _s: _ok("no"))
    hypotheses, result = find_hypotheses(fake, [], repo, iac_files(repo, "cdk"))
    assert hypotheses == []
    assert result.status == "invalid"
    assert len(fake.calls) == 2


def test_a_fallback_is_not_retried(repo: Path) -> None:
    fake = FakeLLM(lambda p, _s: LLMResult(p, "fallback", "ollama", "m", "down"))
    hypotheses, result = find_hypotheses(fake, [], repo, iac_files(repo, "cdk"))
    assert (hypotheses, result.status, len(fake.calls)) == ([], "fallback", 1)


# V1 and V2


def _analyze(mode: str, repo: Path, **kwargs):
    if mode == "v1":
        return analyze_v1(repo, **kwargs)
    return analyze_v2(repo, skip_synth=True, **kwargs)


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_a_scan_with_the_llm_makes_one_call_and_shows_the_hypothesis(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _use(monkeypatch, _answering([_item()]))
    report, ctx, findings, _ = _analyze(mode, repo)
    assert len(fake.asked(HYPOTHESIS_SYSTEM)) == 1
    assert [h.file for h in ctx.hypotheses] == [QUIET_FILE]
    assert "## Unverified hypotheses" in report
    assert ctx.llm.status == "ok"
    assert ctx.hypothesis_llm.status == "ok"
    assert not any(f.file == QUIET_FILE and f.line == 2 for f in findings)


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_no_llm_makes_no_call(mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _use(monkeypatch, _answering([_item()]))
    report, ctx, _, _ = _analyze(mode, repo, use_llm=False)
    assert fake.asked(HYPOTHESIS_SYSTEM) == []
    assert ctx.hypotheses == []
    assert "Unverified hypotheses" not in report


def _fail_hypothesis_call(prompt: str, system: str) -> LLMResult:
    if system == HYPOTHESIS_SYSTEM:
        return LLMResult(prompt, "fallback", "ollama", "m", "down")
    ids = [line.removeprefix("finding_id: ") for line in prompt.splitlines() if line.startswith("finding_id: ")]
    return _ok(json.dumps([{"finding_id": i, "verdict": "confirm", "why": "real"} for i in ids]))


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_a_failed_hypothesis_call_is_reported_and_keeps_the_verdicts(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _fail_hypothesis_call)
    _, ctx, findings, _ = _analyze(mode, repo)
    assert findings
    assert ctx.llm.status == "ok"
    assert ctx.hypothesis_llm.status == "fallback"
    assert any(f.verdict is not None for f in findings)


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_a_model_that_failed_verdicts_gets_no_hypothesis_call(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _use(monkeypatch, lambda p, _s: LLMResult(p, "fallback", "ollama", "m", "down"))
    _, ctx, _, _ = _analyze(mode, repo)
    assert fake.asked(VERDICT_SYSTEM)
    assert fake.asked(HYPOTHESIS_SYSTEM) == []
    assert ctx.llm.status == "fallback"
    assert ctx.hypothesis_llm.status == "skipped"


def test_v1_with_no_findings_still_reports_the_hypothesis_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "stack.ts").write_text('import "aws-cdk-lib";\n', encoding="utf-8")
    _use(monkeypatch, _answering([]))
    _, ctx, findings, _ = analyze_v1(tmp_path, rules_include=[])
    assert findings == []
    assert ctx.llm.status == "skipped"
    assert ctx.hypothesis_llm.status == "ok"


def test_v2_prompt_gets_the_synth_summary_and_v1_does_not(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _use(monkeypatch, _answering([]))
    analyze_v1(repo)
    assert "## Synth summary" not in fake.asked(HYPOTHESIS_SYSTEM)[-1]
    analyze_v2(repo, skip_synth=True)
    assert "## Synth summary" in fake.asked(HYPOTHESIS_SYSTEM)[-1]


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_a_theme_filter_does_not_make_a_file_with_findings_look_quiet(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _use(monkeypatch, _answering([]))
    _analyze(mode, repo, theme_filter=["sustainability"])
    prompt = fake.asked(HYPOTHESIS_SYSTEM)[0]
    assert f"File: {QUIET_FILE}" in prompt
    assert "File: lib/loud.ts" not in prompt


TEMPLATE_LOUD = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
"""
TEMPLATE_QUIET = """AWSTemplateFormatVersion: "2010-09-09"
Description: nothing to check
Outputs:
  Name:
    Value: x
"""
TERRAFORM_LOUD = """resource "aws_s3_bucket" "b" {
  bucket = "b"
}
"""
TERRAFORM_QUIET = """variable "name" {
  type = string
}
"""


@pytest.mark.parametrize(
    "iac, loud, quiet, loud_text, quiet_text",
    [
        ("cloudformation", "loud.yaml", "quiet.yaml", TEMPLATE_LOUD, TEMPLATE_QUIET),
        ("terraform", "loud.tf", "quiet.tf", TERRAFORM_LOUD, TERRAFORM_QUIET),
    ],
)
def test_a_template_or_module_with_findings_is_not_in_the_slice(
    iac: str, loud: str, quiet: str, loud_text: str, quiet_text: str,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / loud).write_text(loud_text, encoding="utf-8")
    (tmp_path / "infra" / quiet).write_text(quiet_text, encoding="utf-8")
    fake = _use(monkeypatch, _answering([]))
    _, _, findings, _ = analyze_v1(tmp_path, iac=iac)
    assert any(f.file == f"infra/{loud}" for f in findings)
    prompt = fake.asked(HYPOTHESIS_SYSTEM)[0]
    assert f"File: infra/{loud}" not in prompt
    assert f"File: infra/{quiet}" in prompt


# Renderers and the boundaries


def _ctx() -> RepoContext:
    return RepoContext(repo_path="/repo", hypotheses=[_hypothesis()])


def test_markdown_lists_the_hypothesis_in_its_own_section() -> None:
    report = render_markdown(_ctx(), [])
    section = report.split("## Unverified hypotheses")[1].split("## ")[0]
    assert f"[{RULE}] A title: `{QUIET_FILE}` (line 2) — `no encryption`" in section


def test_markdown_text_from_the_repo_cannot_leave_its_code_span() -> None:
    ctx = RepoContext(repo_path="/repo", hypotheses=[
        Hypothesis(rule_id=RULE, title="t", file="a`b.ts", line=1, why="x` ![img](http://e/i)")
    ])
    assert "`a'b.ts` (line 1) — `x' ![img](http://e/i)`" in render_markdown(ctx, [])


def test_json_marks_each_hypothesis_unverified_and_keeps_it_out_of_findings_and_context() -> None:
    data = json.loads(render_json(_ctx(), [_finding()]))
    assert data["hypotheses"] == [_hypothesis().model_dump()]
    assert data["hypotheses"][0]["unverified"] is True
    assert [f["id"] for f in data["findings"]] == [RULE]
    assert "hypotheses" not in data["context"]
    assert data["summary"]["findings"] == 1


def test_json_has_no_key_when_there_are_none() -> None:
    assert "hypotheses" not in json.loads(render_json(RepoContext(repo_path="/repo"), []))


def test_html_shows_them_outside_the_severity_tabs_and_escaped() -> None:
    ctx = RepoContext(repo_path="/repo", hypotheses=[
        Hypothesis(rule_id=RULE, title="t", file=QUIET_FILE, line=2, why="<script>x</script>")
    ])
    page = render_html(ctx, [_finding()])
    assert page.index('id="findings"') < page.index('class="hypotheses"')
    assert page.index("</section>", page.index('id="findings"')) < page.index('class="hypotheses"')
    assert "<script>x</script>" not in page
    assert 'class="hypotheses"' not in render_html(RepoContext(repo_path="/repo"), [_finding()])


def test_sarif_is_the_same_with_and_without_a_hypothesis() -> None:
    plain = RepoContext(repo_path="/repo")
    assert render_sarif(_ctx(), [_finding()]) == render_sarif(plain, [_finding()])
    assert "no encryption" not in render_sarif(_ctx(), [_finding()])


def test_fail_on_and_baseline_read_only_findings(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, _answering([_item()]))
    _, ctx, findings, _ = analyze_v1(repo)
    assert ctx.hypotheses
    assert not any(isinstance(f, Hypothesis) for f in findings)
    assert not any(f.file == QUIET_FILE for f in findings)
    assert _should_fail("low", [f for f in findings if f.file == QUIET_FILE]) is False
    assert QUIET_FILE not in str(merge_into_baseline(set(), findings))


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_the_cli_exit_code_and_baseline_ignore_a_hypothesis(
    fmt: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "quiet.ts").write_text('import "aws-cdk-lib";\n', encoding="utf-8")
    # A High rule, so counting the hypothesis would fail the scan.
    _use(monkeypatch, _answering([_item(file="quiet.ts", line=1)]))
    out = tmp_path / "out.txt"
    baseline = tmp_path / "baseline.json"
    result = runner.invoke(app, ["--repo", str(tmp_path), "--out", str(out), "--format", fmt,
                                 "--fail-on", "high", "--baseline", str(baseline), "--update-baseline"])
    assert result.exit_code == 0, result.output
    assert "quiet.ts" not in baseline.read_text(encoding="utf-8")
    assert ("no encryption" in out.read_text(encoding="utf-8")) is (fmt == "json")


# The split: a verdict is a label, a hypothesis is a guess

ROOT = Path(__file__).resolve().parent.parent
GENERATED = re.compile(r"^- Generated: .*$", re.MULTILINE)
VERDICT_LINE = re.compile(r"^- LLM verdict: .*\n", re.MULTILINE)
HYPOTHESIS_SECTION = re.compile(r"## Unverified hypotheses\n.*?(?=## Suggested Next Actions)", re.DOTALL)
V2_ARGS = {"v1": [], "v2": ["--mode", "v2", "--no-synth"]}


def _verdicts_and(hypothesis_reply: Callable[[str], LLMResult], verdict: str = "confirm"):
    def reply(prompt: str, system: str) -> LLMResult:
        if system == HYPOTHESIS_SYSTEM:
            return hypothesis_reply(prompt)
        ids = re.findall(r"^finding_id: (\S+)$", prompt, re.MULTILINE)
        return _ok(json.dumps([{"finding_id": i, "verdict": verdict, "why": "real"} for i in ids]))

    return reply


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_a_connection_failure_is_fallback_and_not_rendered_as_a_verdict(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setattr(v2_graph, "_pillar_cache", {})
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=requests.ConnectionError("down")):
        report, ctx, findings, _ = _analyze(mode, repo)
    assert ctx.llm.status == "fallback"
    assert findings and not any(f.verdict for f in findings)
    assert "LLM verdict" not in report
    assert "Unverified hypotheses" not in report


@pytest.mark.parametrize("mode", ["v1", "v2"])
@pytest.mark.parametrize(
    "reply, status",
    [
        (lambda p, _s: LLMResult(p, "fallback", "ollama", "m", "down"), "fallback"),
        (lambda _p, _s: _ok("not json"), "invalid"),
    ],
)
def test_the_markdown_label_needs_status_ok(
    mode: str, reply, status: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, reply)
    report, ctx, _, _ = _analyze(mode, repo)
    assert ctx.llm.status == status
    assert "LLM verdict" not in report


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_every_label_shown_has_status_ok_even_when_the_hypothesis_call_fails(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    down = lambda p: LLMResult(p, "fallback", "ollama", "m", "down")  # noqa: E731
    _use(monkeypatch, _verdicts_and(down))
    report, ctx, _, _ = _analyze(mode, repo)
    assert "LLM verdict" in report
    assert ctx.llm.status == "ok"
    data = json.loads(render_json(ctx, []))
    assert data["llm"]["status"] == "ok"
    assert data["hypotheses_llm"]["status"] == "fallback"


def test_the_v1_findings_text_matches_the_no_llm_render(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, _verdicts_and(lambda _p: _ok(json.dumps([_item()])), "false_positive"))
    plain, _, _, _ = analyze_v1(repo, use_llm=False)
    report, ctx, _, _ = analyze_v1(repo)
    assert ctx.hypotheses and "LLM verdict" in report
    stripped = HYPOTHESIS_SECTION.sub("", VERDICT_LINE.sub("", report))
    assert GENERATED.sub("", stripped) == GENERATED.sub("", plain)


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_the_lists_passed_to_sarif_fail_on_and_the_baseline_hold_only_findings(
    mode: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _verdicts_and(lambda _p: _ok(json.dumps([_item()]))))
    seen: dict[str, list] = {}

    def spy_on(name: str) -> None:
        real = getattr(cli, name)

        def spy(*args, **kwargs):
            seen[name] = next(a for a in args if isinstance(a, list))
            return real(*args, **kwargs)

        monkeypatch.setattr(cli, name, spy)

    for name in ("render_sarif", "_should_fail", "merge_into_baseline"):
        spy_on(name)
    out = repo / "out.sarif"
    result = runner.invoke(app, ["--repo", str(repo), *V2_ARGS[mode], "--out", str(out), "--format", "sarif",
                                 "--baseline", str(repo / "base.json"), "--update-baseline"])
    assert result.exit_code == 0, result.output
    assert "Hypotheses: 1 unverified" in result.output
    assert set(seen) == {"render_sarif", "_should_fail", "merge_into_baseline"}
    for items in seen.values():
        assert items and all(isinstance(item, Finding) for item in items)
    assert "no encryption" not in out.read_text(encoding="utf-8")


def test_the_console_says_when_the_hypothesis_call_failed(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, _verdicts_and(lambda p: LLMResult(p, "fallback", "ollama", "m", "down")))
    result = runner.invoke(app, ["--repo", str(repo), "--out", str(repo / "out.md")])
    assert "Hypotheses: fallback (down)" in result.output
    assert "Hypotheses: fallback (down)" in (repo / "out.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("doc", ["docs/REFERENCE.md", "docs/V2_LANGGRAPH.md", "docs/report-schema.json"])
def test_the_docs_name_the_split(doc: str) -> None:
    text = " ".join((ROOT / doc).read_text(encoding="utf-8").split()).lower()
    assert "exit code" in text
    assert "unverified" in text
    assert "catalog rule" in text
    assert "polish" not in text
