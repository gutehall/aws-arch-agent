"""Live AWS on-demand prices for cost estimates.

Prices are fetched when a scan needs them (see pricing.providers): from the AWS Price
List Query API when boto3 and AWS credentials are available, else from the public bulk
API, and kept in a SQLite cache (pricing.cache) for 24 hours by default. Any region is
priced. An unknown key, a region AWS does not price, or pricing that cannot be reached
gives None: no estimate, never a guess. `--pricing-source off` turns pricing off.

The price keys are listed in pricing.catalog.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from aws_arch_agent.pricing.cache import DEFAULT_TTL_HOURS, PriceCache
from aws_arch_agent.pricing.providers import (
    SOURCE_LABELS,
    SOURCES,
    Boto3PricingProvider,
    BulkPricingProvider,
    HybridPriceProvider,
    InMemoryPriceProvider,
    OffPriceProvider,
    Price,
    PriceProvider,
)

__all__ = [
    "DEFAULT_REGION", "DEFAULT_TTL_HOURS", "SOURCES", "Boto3PricingProvider", "BulkPricingProvider",
    "HybridPriceProvider", "InMemoryPriceProvider", "OffPriceProvider", "Price", "PriceProvider",
    "configure", "current_region", "price", "price_info", "price_note", "provider", "set_provider",
    "snapshot_date", "use_provider", "use_region", "warnings",
]

DEFAULT_REGION = "us-east-1"

_provider: PriceProvider | None = None
# Prices handed out since the provider was set, by region: the report's source and dates.
_seen: dict[str, dict[str, Any]] = {}


def provider() -> PriceProvider:
    """The active provider; a HybridPriceProvider with defaults until one is set."""
    global _provider
    if _provider is None:
        _provider = HybridPriceProvider()
    return _provider


def set_provider(new: PriceProvider) -> None:
    global _provider
    _provider = new
    _seen.clear()


@contextmanager
def use_provider(new: PriceProvider) -> Iterator[PriceProvider]:
    """Price with this provider for a block; the previous one (and what it saw) after."""
    global _provider, _seen
    previous, previous_seen = _provider, _seen
    _provider, _seen = new, {}
    try:
        yield new
    finally:
        _provider, _seen = previous, previous_seen


def configure(
    source: str = "auto", ttl_hours: float = DEFAULT_TTL_HOURS, refresh: bool = False,
    cache_path: Path | None = None,
) -> PriceProvider:
    """The provider for --pricing-source / --price-cache-ttl / --refresh-prices (not yet set)."""
    if source == "off":
        return OffPriceProvider()
    return HybridPriceProvider(source=source, cache=PriceCache(cache_path, ttl_hours), refresh=refresh)


def price(key: str, region: str = DEFAULT_REGION) -> Price | None:
    """The price for a key in a region, or None when no source has one."""
    found = provider().price(key, region)
    if found is not None:
        seen = _seen.setdefault(region, {"dates": set(), "sources": set(), "fetched": set(), "stale": False})
        if found.snapshot_date:
            seen["dates"].add(found.snapshot_date)
        if found.source:
            seen["sources"].add(found.source)
        if found.fetched_at:
            seen["fetched"].add(found.fetched_at)
        seen["stale"] = seen["stale"] or found.stale
    return found


def snapshot_date(region: str = DEFAULT_REGION) -> str | None:
    """The newest AWS publication date of the prices used in the region, or None if none were."""
    dates = (_seen.get(region) or {}).get("dates")
    return max(dates) if dates else None


def price_info(region: str = DEFAULT_REGION) -> dict[str, Any]:
    """Where the region's prices came from: source label, newest fetch time, stale or not."""
    seen = _seen.get(region) or {}
    sources = sorted(seen.get("sources") or ())
    fetched = seen.get("fetched") or ()
    return {
        "pricing_source": ", ".join(SOURCE_LABELS.get(s, s) for s in sources) or None,
        "fetched_at": max(fetched) if fetched else None,
        "stale": bool(seen.get("stale")),
    }


def warnings() -> list[str]:
    """What the active provider could not do (offline, stale prices), for the report."""
    return list(getattr(provider(), "warnings", []) or [])


_active_region = DEFAULT_REGION


def current_region() -> str:
    """The region a scan prices in (see use_region)."""
    return _active_region


@contextmanager
def use_region(region: str) -> Iterator[None]:
    """Price in this region for the duration of a scan. Restores the previous one after."""
    global _active_region
    previous, _active_region = _active_region, region
    try:
        yield
    finally:
        _active_region = previous


def price_note(region: str = DEFAULT_REGION) -> dict[str, Any]:
    """What the report says about prices: the region, its newest price date, and their source."""
    return {"region": region, "snapshot_date": snapshot_date(region), **price_info(region)}
