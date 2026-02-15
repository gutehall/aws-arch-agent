from pathlib import Path
from aws_arch_agent.agent.v1 import analyze_v1

def test_smoke(tmp_path: Path):
    # create tiny fake repo
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    report, ctx, findings = analyze_v1(tmp_path)
    assert "AWS Architecture Review Report" in report
