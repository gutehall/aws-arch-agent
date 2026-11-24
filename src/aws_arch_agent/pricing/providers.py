"""Where prices come from.

HybridPriceProvider looks a key up in this order and stops at the first answer:

1. memory: keys already looked up in this process (misses included);
2. the SQLite cache (pricing.cache) within its TTL;
3. the AWS Price List Query API through boto3, when boto3 is installed and AWS credentials
   resolve. Its answer is final: a key it has no product for is a miss, not a reason to
   download a bulk file;
4. the public AWS Price List bulk API (no credentials): the region's offer CSV is streamed
   once and every key it prices goes into the cache;
5. an expired cache entry, with a warning, when the sources above are unreachable.

Otherwise there is no price, and no estimate: a scan never fails because pricing did. A
source that fails (no credentials, no network) is not tried again in the same process.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from aws_arch_agent.pricing import catalog
from aws_arch_agent.pricing.build import OFFER_URL, PriceBuildError, prices_from_rows, read_offer
from aws_arch_agent.pricing.cache import Entry, PriceCache, iso

SOURCES = ("auto", "api", "bulk", "off")
SOURCE_LABELS = {
    "api": "AWS Price List Query API",
    "bulk": "AWS Price List bulk API",
    "memory": "prices supplied in memory",
}


@dataclass(frozen=True)
class Price:
    """One on-demand price. snapshot_date is the AWS publication date of its offer;
    source is where it came from (api, bulk, memory); stale marks an expired cache entry."""

    usd: float
    unit: str
    region: str
    snapshot_date: str | None
    source: str = ""
    fetched_at: str | None = None
    stale: bool = False


class PriceProvider(Protocol):
    def price(self, key: str, region: str) -> Price | None: ...


class PricingUnavailable(Exception):
    """A price source cannot be reached or used (no boto3, no credentials, no network)."""


class Truncated(Exception):
    """The Query API had more products than were read: the prices read are kept, but a key
    not among them is not a known miss."""

    def __init__(self, offer: str, prices: dict[str, list], published: str | None) -> None:
        super().__init__(offer)
        self.offer, self.prices, self.published = offer, prices, published


class OffPriceProvider:
    """--pricing-source off: no prices, so no estimates, and no network."""

    warnings: list[str] = []

    def price(self, key: str, region: str) -> Price | None:
        return None


class InMemoryPriceProvider:
    """Fixed prices: region -> key -> (usd, unit). For tests and offline use."""

    def __init__(
        self, prices: Mapping[str, Mapping[str, Sequence]],
        published: Mapping[str, Mapping[str, str] | str] | None = None, source: str = "memory",
    ) -> None:
        self._prices = {r: dict(keys) for r, keys in prices.items()}
        self._published = dict(published or {})
        self.source = source
        self.warnings: list[str] = []

    @classmethod
    def from_snapshot(cls, data: Mapping[str, Any]) -> "InMemoryPriceProvider":
        """From {"regions": {region: {"published": {offer: date}, "prices": {key: [usd, unit]}}}}."""
        regions = data.get("regions") or {}
        return cls(
            {r: body.get("prices", {}) for r, body in regions.items()},
            {r: body.get("published", {}) for r, body in regions.items()},
        )

    def price(self, key: str, region: str) -> Price | None:
        entry = self._prices.get(region, {}).get(key)
        if not entry:
            return None
        published = self._published.get(region)
        if isinstance(published, Mapping):
            published = published.get(catalog.offer_for(key) or "")
        return Price(float(entry[0]), str(entry[1]), region, published or None, self.source)


class Boto3PricingProvider:
    """The Price List Query API (pricing:GetProducts in us-east-1). Needs boto3 and credentials."""

    def __init__(self, client: Any = None, max_items: int = 2000) -> None:
        self._client = client
        self._max_items = max_items

    def _pricing_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore[import-not-found]
            except ImportError as exc:
                raise PricingUnavailable("boto3 is not installed") from exc
            try:
                session = boto3.Session()
                credentials = session.get_credentials()
                if credentials is None:
                    raise PricingUnavailable("no AWS credentials")
                self._client = session.client("pricing", region_name="us-east-1")
            except PricingUnavailable:
                raise
            except Exception as exc:  # botocore: unknown profile, bad config, ...
                raise PricingUnavailable(f"Price List Query API: {exc}") from exc
        return self._client

    def fetch(self, key: str, region: str) -> tuple[str, dict[str, list], str | None]:
        """(offer, key -> [usd, unit] for every key the matching products price, publication date).

        Raises PricingUnavailable when the API cannot be used, and Truncated (with what was
        read) when there were more products than max_items, so a miss is not final."""
        spec = catalog.spec(key)
        if spec is None:
            return "", {}, None
        client = self._pricing_client()
        rows: list[catalog.Row] = []
        dates: list[str] = []
        items = 0
        try:
            pages = client.get_paginator("get_products").paginate(
                **spec.query(region), PaginationConfig={"MaxItems": self._max_items},
            )
            for page in pages:
                for item in page.get("PriceList") or []:
                    items += 1
                    rows.extend(catalog.api_rows(item))
                    date = catalog.publication_date(item)
                    if date:
                        dates.append(date)
        except Exception as exc:  # botocore raises many types: network, throttling, access
            raise PricingUnavailable(f"Price List Query API: {exc}") from exc
        try:
            prices = prices_from_rows(spec.offer, rows, strict=False)  # disagreeing rows: no price
        except PriceBuildError:
            prices = {}  # a row without a readable price
        published = max(dates) if dates else None
        if items >= self._max_items:
            raise Truncated(spec.offer, prices, published)
        return spec.offer, prices, published

    def price(self, key: str, region: str) -> Price | None:
        try:
            _, prices, published = self.fetch(key, region)
        except Truncated as cut:
            prices, published = cut.prices, cut.published
        except PricingUnavailable:
            return None
        entry = prices.get(key)
        return Price(entry[0], entry[1], region, published, "api") if entry else None


def _stream(url: str) -> Iterable[str]:
    import requests

    try:
        resp = requests.get(url, stream=True, timeout=(10, 120), headers={"User-Agent": "aws-arch-agent"})
    except requests.RequestException as exc:
        raise PricingUnavailable(f"Price List bulk API: {exc}") from exc
    if resp.status_code == 404:  # the offer has no file for this region
        resp.close()
        return []
    if resp.status_code != 200:
        resp.close()
        raise PricingUnavailable(f"Price List bulk API: HTTP {resp.status_code} for {url}")

    # The offer CSV is UTF-8 but served as application/octet-stream, so requests finds no
    # charset and iter_lines(decode_unicode=True) would yield bytes.
    resp.encoding = "utf-8"

    def lines() -> Iterable[str]:
        with resp:
            for line in resp.iter_lines(decode_unicode=True):
                if line is not None:
                    yield line + "\n"

    return lines()


class BulkPricingProvider:
    """The public Price List bulk API: one offer CSV per region, no credentials."""

    def __init__(self, opener: Callable[[str], Iterable[str]] = _stream) -> None:
        self._open = opener

    def fetch_offer(self, offer: str, region: str) -> tuple[str | None, dict[str, list]]:
        """(publication date, key -> [usd, unit]) for the offer's file in the region."""
        lines = iter(self._open(OFFER_URL.format(offer=offer, region=region)))
        try:
            first = next(lines, None)
            if first is None:
                return None, {}  # no file for the region: a known miss
            published, rows = read_offer(itertools.chain([first], lines))
            return published, prices_from_rows(offer, rows, strict=False)
        except PriceBuildError as exc:  # not an offer file (a proxy page?): try again later
            raise PricingUnavailable(f"Price List bulk API: {offer} for {region}: {exc}") from exc
        except PricingUnavailable:
            raise
        except Exception as exc:  # the stream broke part way
            raise PricingUnavailable(f"Price List bulk API: {exc}") from exc

    def price(self, key: str, region: str) -> Price | None:
        offer = catalog.offer_for(key)
        if offer is None:
            return None
        try:
            published, prices = self.fetch_offer(offer, region)
        except PricingUnavailable:
            return None
        entry = prices.get(key)
        return Price(entry[0], entry[1], region, published, "bulk") if entry else None


def _from_entry(entry: Entry, region: str) -> Price | None:
    if entry.usd is None:
        return None
    return Price(entry.usd, entry.unit, region, entry.published_date, entry.source, iso(entry.fetched_at), entry.stale)


class HybridPriceProvider:
    """Memory, then the SQLite cache, then the Query API, then the bulk API, then stale cache."""

    def __init__(
        self, source: str = "auto", cache: PriceCache | None = None,
        api: Boto3PricingProvider | None = None, bulk: BulkPricingProvider | None = None,
        refresh: bool = False,
    ) -> None:
        if source not in SOURCES:
            raise ValueError(f"pricing source must be one of {', '.join(SOURCES)}, not {source!r}")
        self.source = source
        self.cache = cache if cache is not None else PriceCache()
        self.api = api if api is not None else Boto3PricingProvider()
        self.bulk = bulk if bulk is not None else BulkPricingProvider()
        self._refresh = refresh
        self._memory: dict[tuple[str, str], Price | None] = {}
        self._offers: dict[tuple[str, str], dict[str, list]] = {}
        self._published: dict[tuple[str, str], str | None] = {}
        self._down: set[str] = set()
        self._lock = threading.Lock()
        self.warnings: list[str] = []

    def _warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)

    def _layers(self) -> tuple[str, ...]:
        return {"auto": ("api", "bulk"), "api": ("api",), "bulk": ("bulk",)}.get(self.source, ())

    def price(self, key: str, region: str) -> Price | None:
        if self.source == "off":
            return None
        with self._lock:
            if self._refresh:
                self.cache.invalidate()
                self._refresh = False
            if (region, key) not in self._memory:
                self._memory[(region, key)] = self._lookup(key, region)
            return self._memory[(region, key)]

    def _lookup(self, key: str, region: str) -> Price | None:
        spec = catalog.spec(key)
        if spec is None:
            return None
        entry = self.cache.get(region, key)
        if entry is not None:
            return _from_entry(entry, region)
        for layer in self._layers():
            if layer in self._down:
                continue
            try:
                if layer == "api":
                    return self._from_api(key, region, spec.offer)
                if (region, spec.offer) not in self._offers and self.cache.offer_fresh(region, spec.offer):
                    return None  # the offer file was read within the TTL and has no such key
                return self._from_bulk(key, region, spec.offer)
            except PricingUnavailable as exc:
                self._down.add(layer)
                if layer == "api" and self.source == "auto":
                    continue  # quietly fall through to the bulk API
                self._warn(f"{exc}")
        stale = self.cache.get(region, key, allow_stale=True)
        if stale is not None and stale.usd is not None:
            self._warn("Prices could not be fetched; some estimates use expired cached prices.")
            return _from_entry(stale, region)
        if self._down >= set(self._layers()):
            self._warn("Prices could not be fetched (offline?); resources without a cached price are not estimated.")
        return None

    def _from_api(self, key: str, region: str, offer: str) -> Price | None:
        try:
            _, prices, published = self.api.fetch(key, region)
            missing = [key]
        except Truncated as cut:  # a key not read is not a known miss
            prices, published, missing = cut.prices, cut.published, []
        self.cache.put_many(region, offer, prices, published, "api", missing=missing)
        entry = prices.get(key)
        return Price(entry[0], entry[1], region, published, "api", iso(time.time())) if entry else None

    def _from_bulk(self, key: str, region: str, offer: str) -> Price | None:
        if (region, offer) not in self._offers:
            published, prices = self.bulk.fetch_offer(offer, region)
            self.cache.put_many(region, offer, prices, published, "bulk")
            self.cache.mark_offer(region, offer, published)
            self._offers[(region, offer)] = prices
            self._published[(region, offer)] = published
        entry = self._offers[(region, offer)].get(key)
        published = self._published.get((region, offer))
        return Price(entry[0], entry[1], region, published, "bulk", iso(time.time())) if entry else None
