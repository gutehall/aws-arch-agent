"""A mitigating keyword only clears resources in the same file."""
from pathlib import Path

from aws_arch_agent.rules.security import S3PublicAccessNotBlocked


def test_block_public_access_in_another_file_does_not_clear_bucket(tmp_path: Path) -> None:
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "safe.ts").write_text(
        'new s3.Bucket(this, "Safe", { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL });\n',
        encoding="utf-8",
    )
    (lib / "open.ts").write_text(
        'const note = "keep";\nnew s3.Bucket(this, "Open");\n',
        encoding="utf-8",
    )
    findings = S3PublicAccessNotBlocked().run(tmp_path, "typescript")
    assert len(findings) == 1
    assert str(findings[0].file).endswith("open.ts")
    assert findings[0].line == 2
    assert "Open" in (findings[0].evidence or "")
