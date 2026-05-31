"""Generate rule_cases.json: positive/negative snippets per rule ID (run once to refresh)."""
from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

from aws_arch_agent.rules.registry import ALL_RULES

OUT = Path(__file__).parent / "rule_cases.json"

# Hand-tuned snippets where auto-generation is unreliable.
MANUAL: dict[str, dict[str, str | None]] = {
    "SEC-001": {"positive_ts": 'Action: "*"', "negative_ts": 'actions: ["s3:GetObject"]'},
    "SEC-016": {"positive_ts": 'access_key = "AKIAIOSFODNN7EXAMPLE"', "negative_ts": "// no secrets"},
    "SEC-003": {"positive_ts": "0.0.0.0/0 port 22", "negative_ts": "10.0.0.0/24 port 22"},
    "OPS-001": {"positive_py": "# empty stack", "negative_py": "cloudtrail.Trail"},
    "REL-001": {"positive_ts": "new rds.DatabaseInstance(this, 'Db', { multiAz: false })", "negative_ts": "multiAz: true"},
}


def _extract_rg_patterns(source: str) -> list[str]:
    patterns: list[str] = []
    for m in re.finditer(r"rg\(\s*repo_path,\s*(r?)(['\"])(.*?)\2", source, re.DOTALL):
        patterns.append(m.group(3))
    return patterns


def _regex_to_snippet(pattern: str, lang: str) -> str:
    """Best-effort snippet from a regex pattern."""
    p = pattern
    if lang == "python":
        p = p.replace(r"new\s+", "").replace(r"\.(", "(")
    # Prefer explicit quoted literals
    quoted = re.findall(r'["\']([^"\']{3,})["\']', p)
    if quoted:
        token = quoted[0]
        if "Action" in token or "action" in token.lower():
            return 'Action: "*"' if lang == "typescript" else '"Action": "*"'
        if token.startswith("AKIA"):
            return f'access_key = "{token}"' if lang == "python" else f'const access_key = "{token}"'
        return token
    # CDK construct patterns
    m = re.search(r"(?:new\s+)?([\w.]+)\\?\(", p)
    if m:
        expr = m.group(1)
        if lang == "typescript":
            return f"new {expr}(this, 'X')"
        return f"{expr}(self, 'X')"
    m = re.search(r"([\w.]+)", p)
    if m:
        return m.group(1)
    return "// trigger"


def _pick_lang(rule) -> str:
    src = inspect.getsource(rule.run)
    if 'language == "typescript"' in src and 'language == "python"' not in src:
        return "typescript"
    if 'language == "python"' in src and 'language == "typescript"' not in src:
        return "python"
    return "typescript"


def _classify(source: str) -> str:
    if re.search(r"for f, ln, txt in", source):
        return "presence"
    if re.search(r"if not \w+:", source) and "return [Finding" in source:
        return "absence"
    if re.search(r"if \w+ and not \w+:", source):
        return "compound_absence"
    return "other"


def build_case(rule) -> dict[str, str | None]:
    rid = rule.id
    if rid in MANUAL:
        return MANUAL[rid]
    src = inspect.getsource(rule.run)
    kind = _classify(src)
    lang = _pick_lang(rule)
    patterns = _extract_rg_patterns(src)
    case: dict[str, str | None] = {}

    if kind == "absence":
        case[f"positive_{lang[:2] if lang == 'python' else 'ts'}"] = "// empty"
        if patterns:
            snip = _regex_to_snippet(patterns[0], lang)
            key = f"negative_{'py' if lang == 'python' else 'ts'}"
            case[key] = snip
    elif kind == "presence":
        if patterns:
            snip = _regex_to_snippet(patterns[0], lang)
            key = f"positive_{'py' if lang == 'python' else 'ts'}"
            case[key] = snip
            case[f"negative_{'py' if lang == 'python' else 'ts'}"] = "// clean code"
    elif kind == "compound_absence":
        if patterns:
            pos = _regex_to_snippet(patterns[0], lang)
            key_p = f"positive_{'py' if lang == 'python' else 'ts'}"
            key_n = f"negative_{'py' if lang == 'python' else 'ts'}"
            case[key_p] = pos
            if len(patterns) > 1:
                neg_extra = _regex_to_snippet(patterns[1], lang)
                if lang == "typescript":
                    case[key_n] = f"{pos}, {{ {neg_extra} }}"
                else:
                    case[key_n] = f"{pos}\n{neg_extra}"
            else:
                case[key_n] = "// mitigated"
    else:
        if patterns:
            snip = _regex_to_snippet(patterns[0], lang)
            case[f"positive_{'py' if lang == 'python' else 'ts'}"] = snip
            case[f"negative_{'py' if lang == 'python' else 'ts'}"] = "// clean"
    return case


def main() -> None:
    cases = {r.id: build_case(r) for r in ALL_RULES}
    OUT.write_text(json.dumps(cases, indent=2), encoding="utf-8")
    print(f"Wrote {len(cases)} rule cases to {OUT}")


if __name__ == "__main__":
    main()
