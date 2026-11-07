"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def _no_aws_region_from_the_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scan falls back to AWS_REGION / AWS_DEFAULT_REGION; tests must not see the developer's."""
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
