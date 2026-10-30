"""Python CDK keyword arguments must count, and only in the same file."""
from pathlib import Path

from aws_arch_agent.rules.reliability import LambdaTimeout, RdsMultiAzMissing, SqsDlqMissing
from aws_arch_agent.rules.security_iam import KmsKeyRotation


def test_python_settings_do_not_clear_another_file(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "\n".join(
            [
                "rds.DatabaseInstance(self, 'DB', multi_az=True)",
                "sqs.Queue(self, 'Q', dead_letter_queue=dlq)",
                "kms.Key(self, 'Key', enable_key_rotation=True)",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "bare.py").write_text(
        "\n".join(
            [
                "rds.DatabaseInstance(self, 'DB')",
                "sqs.Queue(self, 'Q')",
                "kms.Key(self, 'Key')",
            ]
        ),
        encoding="utf-8",
    )
    multi_az = RdsMultiAzMissing().run(tmp_path, "python")
    dlq = SqsDlqMissing().run(tmp_path, "python")
    rotation = KmsKeyRotation().run(tmp_path, "python")
    assert [f.file for f in multi_az] == ["bare.py"]
    assert [f.file for f in dlq] == ["bare.py"]
    assert [f.file for f in rotation] == ["bare.py"]


def test_python_lambda_timeout_keyword(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "aws_lambda.Function(self, 'Fn', timeout=Duration.seconds(30))\n",
        encoding="utf-8",
    )
    (tmp_path / "bare.py").write_text(
        "aws_lambda.Function(self, 'Fn')\n",
        encoding="utf-8",
    )
    findings = LambdaTimeout().run(tmp_path, "python")
    assert [f.file for f in findings] == ["bare.py"]
