"""Offline AWS on-demand prices for cost estimates (DM3-540).

The snapshot ships with the package (prices.json.gz) and is read from disk: a scan never
calls the network. scripts/refresh_prices.py rebuilds it from the AWS Price List bulk API.

Price keys:
    ec2:<instance type>                         USD per hour, Linux, shared tenancy
    rds:<engine>:<single-az|multi-az>:<class>   USD per hour; engine mysql, postgres,
                                                mariadb, aurora-mysql, aurora-postgresql
    nat:hour, nat:gb                            NAT gateway hour and GB processed
    ebs:gp2, ebs:gp3, ebs:io2                   USD per GB-month
    eip:in-use-hour, eip:idle-hour              public IPv4 address hour
    lambda:gb-second, lambda:gb-second-arm, lambda:request
    dynamodb:read-request, dynamodb:write-request (on-demand, per request unit)
    dynamodb:rcu-hour, dynamodb:wcu-hour        provisioned capacity unit hour
    dynamodb:storage-gb                         USD per GB-month
    s3:<standard|intelligent-tiering|standard-ia|onezone-ia|glacier-ir|glacier|deep-archive>
                                                first-tier USD per GB-month
    logs:ingest-gb, logs:storage-gb             CloudWatch Logs

Tiered prices are the first paid tier. An unknown key or region gives None: no estimate,
never a guess.
"""
from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_REGION = "us-east-1"
DATA_PATH = Path(__file__).with_name("prices.json.gz")

# The offer a key's price comes from: the whole key first, then its prefix.
_KEY_OFFER = {
    "ec2": "AmazonEC2", "nat": "AmazonEC2", "ebs": "AmazonEC2", "eip": "AmazonVPC",
    "rds": "AmazonRDS", "lambda": "AWSLambda", "dynamodb": "AmazonDynamoDB",
    "s3": "AmazonS3", "s3:deep-archive": "AmazonS3GlacierDeepArchive", "logs": "AmazonCloudWatch",
}


@dataclass(frozen=True)
class Price:
    """One on-demand price. snapshot_date is the AWS publication date of its offer."""

    usd: float
    unit: str
    region: str
    snapshot_date: str | None


@lru_cache(maxsize=1)
def _snapshot() -> dict[str, Any]:
    """The snapshot, or {} when the file is missing or unreadable: then no region has prices."""
    try:
        with gzip.open(DATA_PATH, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, EOFError, ValueError):  # missing, truncated, not gzip, not JSON
        return {}
    return data if isinstance(data, dict) else {}


def _region(region: str) -> dict[str, Any] | None:
    body = _snapshot().get("regions", {}).get(region)
    return body if isinstance(body, dict) else None


def regions() -> list[str]:
    """Regions the snapshot has prices for."""
    return sorted(_snapshot().get("regions", {}))


def snapshot_date(region: str = DEFAULT_REGION) -> str | None:
    """The newest offer publication date in the region's prices, or None for an unknown region."""
    body = _region(region)
    dates = list((body or {}).get("published", {}).values())
    return max(dates) if dates else None


def price(key: str, region: str = DEFAULT_REGION) -> Price | None:
    """The price for a key in a region, or None when the snapshot has none."""
    body = _region(region)
    entry = (body or {}).get("prices", {}).get(key)
    if not entry:
        return None
    offer = _KEY_OFFER.get(key) or _KEY_OFFER.get(key.split(":", 1)[0], "")
    published = (body or {}).get("published", {}).get(offer) or None
    usd, unit = entry
    return Price(usd=float(usd), unit=str(unit), region=region, snapshot_date=published)


def price_note(region: str = DEFAULT_REGION) -> dict[str, Any]:
    """What the report says about prices: the region and its snapshot date (None if unknown)."""
    return {"region": region, "snapshot_date": snapshot_date(region)}
