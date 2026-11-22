"""Shared test setup."""
import json
from pathlib import Path

import pytest

from aws_arch_agent import pricing

# A few real AWS prices, so estimates have numbers to work with. No test reaches AWS.
_PRICES = json.loads((Path(__file__).parent / "fixtures" / "prices.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _offline_prices(monkeypatch: pytest.MonkeyPatch):
    """In-memory prices for every test. The CLI's --pricing-source / --price-cache-ttl /
    --refresh-prices choose a live provider through pricing.configure; here that keeps the
    test's provider (off stays off) and records the call in `pricing_calls`."""
    real = pricing.configure
    calls: list[dict] = []

    def configure(source="auto", ttl_hours=pricing.DEFAULT_TTL_HOURS, refresh=False, cache_path=None):
        calls.append({"source": source, "ttl_hours": ttl_hours, "refresh": refresh})
        return real(source) if source == "off" else pricing.provider()

    monkeypatch.setattr(pricing, "configure", configure)
    with pricing.use_provider(pricing.InMemoryPriceProvider.from_snapshot(_PRICES)) as provider:
        provider.calls = calls
        provider.real_configure = real
        yield provider


@pytest.fixture(autouse=True)
def _no_aws_region_from_the_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scan falls back to AWS_REGION / AWS_DEFAULT_REGION; tests must not see the developer's."""
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
