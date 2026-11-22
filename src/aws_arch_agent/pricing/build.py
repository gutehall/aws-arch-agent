"""Turn AWS price rows into canonical prices.

Rows come from a bulk offer CSV (`read_offer`) or from Query API products
(`catalog.api_rows`); the offer's matcher in `catalog` names the key each row is for.
Only the SKUs the cost rules use are kept.
"""
from __future__ import annotations

import csv
import re
from decimal import Decimal
from typing import Iterable, Iterator

from aws_arch_agent.pricing.catalog import MATCHERS, OFFERS, Row

__all__ = ["OFFERS", "OFFER_URL", "PriceBuildError", "build_region", "prices_from_rows", "read_offer"]

OFFER_URL = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/{offer}/current/{region}/index.csv"

# AWS spells some units two ways; prices use one spelling.
_UNITS = {"GB-month": "GB-Mo", "GB-Month": "GB-Mo", "Request": "Requests", "Hours": "Hrs"}


class PriceBuildError(ValueError):
    """An offer file is malformed, or two rows give one key different prices."""


def read_offer(lines: Iterable[str]) -> tuple[str, Iterator[dict[str, str]]]:
    """(publication date YYYY-MM-DD, rows) from an offer CSV. Rows stream; nothing is buffered."""
    it = iter(lines)
    meta: dict[str, str] = {}
    for _ in range(5):  # FormatVersion, Disclaimer, Publication Date, Version, OfferCode
        cells = next(csv.reader([next(it, "")]), [])
        if len(cells) >= 2:
            meta[cells[0]] = cells[1]
    published = meta.get("Publication Date", "")[:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published):
        raise PriceBuildError("offer file has no Publication Date header")
    return published, csv.DictReader(it)


def prices_from_rows(offer: str, rows: Iterable[Row], strict: bool = True) -> dict[str, list]:
    """key -> [usd, unit] for the rows of one offer.

    Each key gets the first paid tier: the lowest StartingRange with a price above zero,
    so a free tier is skipped. Rows that give one key different prices at that tier fail
    rather than pick one; with strict=False only that key is left out, so one ambiguous
    SKU does not cost the whole offer its prices.
    """
    matcher = MATCHERS.get(offer)
    if matcher is None:
        raise PriceBuildError(f"unknown offer {offer}")
    # key -> starting range -> set of (price, unit)
    found: dict[str, dict[Decimal, set[tuple[Decimal, str]]]] = {}
    for row in rows:
        if row.get("TermType") != "OnDemand" or row.get("Currency") != "USD":
            continue
        key = matcher(row)
        if key is None:
            continue
        try:
            usd = Decimal(row["PricePerUnit"])
            start = Decimal(row.get("StartingRange") or "0")
        except (KeyError, TypeError, ArithmeticError) as exc:  # missing or short row
            if not strict:
                continue
            raise PriceBuildError(f"{offer}: bad price for {key}: {exc}") from exc
        if usd > 0:
            unit = row.get("Unit", "")
            found.setdefault(key, {}).setdefault(start, set()).add((usd, _UNITS.get(unit, unit)))
    prices: dict[str, list] = {}
    for key, tiers in sorted(found.items()):
        first = tiers[min(tiers)]
        if len(first) > 1:
            if not strict:
                continue
            raise PriceBuildError(f"{key}: rows disagree on the price: {sorted(first)}")
        usd, unit = next(iter(first))
        prices[key] = [float(usd), unit]
    return prices


def build_region(offers: dict[str, Iterable[str]]) -> dict:
    """Prices for one region from its offer CSVs (offer code -> CSV lines)."""
    published: dict[str, str] = {}
    prices: dict[str, list] = {}
    for offer, lines in sorted(offers.items()):
        if offer not in MATCHERS:
            raise PriceBuildError(f"unknown offer {offer}")
        published[offer], rows = read_offer(lines)
        prices.update(prices_from_rows(offer, rows))
    return {"published": published, "prices": dict(sorted(prices.items()))}
