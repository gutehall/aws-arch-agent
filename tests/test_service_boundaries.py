"""REL 3: a workload that mixes many services and stores in one stack (REPO-188)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES


def _tf(kind: str, name: str, n: int) -> str:
    return "".join(f'resource "{kind}" "{name}{i}" {{\n}}\n' for i in range(n))


_BIG = _tf("aws_lambda_function", "fn", 4) + _tf("aws_dynamodb_table", "t", 4)


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-188"]


def test_rule_answers_rel3() -> None:
    assert RULE_BEST_PRACTICES["REPO-188"] == ("REL03-BP01", "REL03-BP02")
    assert not {"REL03-BP01", "REL03-BP02"} & NOT_CHECKED


def test_one_big_stack_fires(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, {"main.tf": _BIG}))
    assert hit.question == "REL 3" and hit.category == "Reliability"
    assert hit.file == "prod/main.tf" and "4 compute resources and 4 data stores" in hit.evidence


@pytest.mark.parametrize(
    "files",
    [
        {"main.tf": _tf("aws_lambda_function", "fn", 2) + _tf("aws_dynamodb_table", "t", 2)},
        {"main.tf": _BIG, "orders/main.tf": _tf("aws_lambda_function", "o", 1)},
        {"main.tf": _BIG + 'module "billing" {\n  source = "./billing"\n}\n'
                    + 'module "orders" {\n  source = "./orders"\n}\n'},
        {"lib/a.ts": "class A extends Stack {}\nclass B extends Stack {}\n"
                     + "new lambda.Function(this, 'A', p);\n" * 4 + "new s3.Bucket(this, 'B');\n" * 4},
        {"main.tf": _tf("aws_lambda_function", "fn", 6)},
    ],
    ids=["small", "two-files", "modules", "two-stacks", "compute-only"],
)
def test_segmented_or_small_workload_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files))
