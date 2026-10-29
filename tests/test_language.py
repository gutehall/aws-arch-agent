"""Language detection for TypeScript and Python CDK apps."""
import json
from pathlib import Path
from types import SimpleNamespace

from aws_arch_agent.agent.v1 import analyze_v1, detect_language
from aws_arch_agent.agent.v2_graph import node_synth
from aws_arch_agent.models import RepoContext


def test_python_cdk_with_cdk_json_scans_py(tmp_path: Path) -> None:
    (tmp_path / "cdk.json").write_text(json.dumps({"app": "python3 app.py"}), encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "app.py").write_text('s3.Bucket(self, "B")\n', encoding="utf-8")
    _report, ctx, findings, _warnings = analyze_v1(
        tmp_path, use_llm=False, rules_include=["SEC-005"]
    )
    assert ctx.language == "python"
    assert any(f.id == "SEC-005" and str(f.file).endswith("app.py") for f in findings)


def test_typescript_cdk_app_stays_typescript(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"aws-cdk-lib": "2.170.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "cdk.json").write_text(
        json.dumps({"app": "npx ts-node --prefer-ts-exts bin/app.ts"}),
        encoding="utf-8",
    )
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "app.ts").write_text('new s3.Bucket(this, "B");\n', encoding="utf-8")
    _report, ctx, findings, _warnings = analyze_v1(
        tmp_path, use_llm=False, rules_include=["SEC-005"]
    )
    assert ctx.language == "typescript"
    assert any(str(f.file).endswith("app.ts") for f in findings)


def test_mixed_repo_scans_both_languages(tmp_path: Path) -> None:
    (tmp_path / "cdk.json").write_text(json.dumps({"app": "python3 app.py"}), encoding="utf-8")
    (tmp_path / "app.py").write_text('s3.Bucket(self, "Py")\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"aws-cdk-lib": "2.170.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "app.ts").write_text('new s3.Bucket(this, "Ts");\n', encoding="utf-8")
    _report, ctx, findings, _warnings = analyze_v1(
        tmp_path, use_llm=False, rules_include=["SEC-005"]
    )
    assert ctx.language == "unknown"
    names = {Path(f.file).name for f in findings if f.file}
    assert "app.py" in names
    assert "app.ts" in names


def test_requirements_without_typescript_app_is_python(tmp_path: Path) -> None:
    (tmp_path / "cdk.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("aws-cdk-lib\n", encoding="utf-8")
    assert detect_language(tmp_path) == "python"


def test_v2_synth_receives_python_app_command(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "cdk.json").write_text(json.dumps({"app": "python3 app.py"}), encoding="utf-8")
    (tmp_path / "app.py").write_text("import aws_cdk\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(cmd, **_kwargs):
        commands.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("aws_arch_agent.tools.cdk_synth.subprocess.run", fake_run)
    ctx = RepoContext(repo_path=str(tmp_path), language=detect_language(tmp_path))
    node_synth(
        {
            "repo_path": str(tmp_path),
            "ctx": ctx,
            "templates_path": "",
            "skip_synth": False,
            "raw_findings": [],
        }
    )
    assert commands
    command = commands[0]
    assert command[command.index("--app") + 1] == "python3 app.py"
