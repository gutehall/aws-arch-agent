"""Build the offline price snapshot from AWS Price List bulk offer files (DM3-540).

Not used at scan time: scripts/refresh_prices.py downloads the offers and calls this.
Only the SKUs the cost rules use are kept. The output depends only on the offer files,
so the same offers always give the same bytes.
"""
from __future__ import annotations

import csv
import gzip
import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Callable, Iterable, Iterator

# Offer codes in the Price List bulk API.
OFFERS = (
    "AmazonEC2", "AmazonRDS", "AWSLambda", "AmazonDynamoDB", "AmazonS3",
    "AmazonS3GlacierDeepArchive", "AmazonCloudWatch", "AmazonVPC",
)
OFFER_URL = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/{offer}/current/{region}/index.csv"
DEFAULT_REGIONS = ("us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "eu-north-1")
SCHEMA = 1

# Usage types carry a region prefix (EUN1-, USW2-, EU- for eu-west-1; none in us-east-1).
# IA- (DynamoDB Infrequent Access) and lowercase prefixes are not regions.
_PFX = r"^(?:[A-Z]{2,4}[0-9]-|EU-)?"
_BOX = re.compile(_PFX + r"BoxUsage:(?P<type>[a-z0-9.\-]+)$")
_RDS = re.compile(_PFX + r"(?:InstanceUsage|Multi-AZUsage):(?P<class>db\.[a-z0-9.\-]+)$")
_RDS_ENGINES = {
    "MySQL": "mysql", "PostgreSQL": "postgres", "MariaDB": "mariadb",
    "Aurora MySQL": "aurora-mysql", "Aurora PostgreSQL": "aurora-postgresql",
}
_RDS_DEPLOYMENTS = {"Single-AZ": "single-az", "Multi-AZ": "multi-az"}
_S3_CLASSES = {
    "TimedStorage-ByteHrs": "standard",
    "TimedStorage-INT-FA-ByteHrs": "intelligent-tiering",
    "TimedStorage-SIA-ByteHrs": "standard-ia",
    "TimedStorage-ZIA-ByteHrs": "onezone-ia",
    "TimedStorage-GIR-ByteHrs": "glacier-ir",
    "TimedStorage-GlacierByteHrs": "glacier",
}


# AWS spells some units two ways; the snapshot uses one spelling.
_UNITS = {"GB-month": "GB-Mo", "GB-Month": "GB-Mo", "Request": "Requests", "Hours": "Hrs"}


class PriceBuildError(ValueError):
    """An offer file is malformed, or two rows give one key different prices."""


def _usage(row: dict[str, str], name: str) -> bool:
    return re.fullmatch(_PFX + re.escape(name), row.get("usageType", "")) is not None


def _ec2(row: dict[str, str]) -> str | None:
    family = row.get("Product Family", "")
    if family in ("Compute Instance", "Compute Instance (bare metal)"):
        box = _BOX.match(row.get("usageType", ""))
        if box and (
            row.get("Operating System") == "Linux" and row.get("Tenancy") == "Shared"
            and row.get("Pre Installed S/W") == "NA" and row.get("CapacityStatus") == "Used"
            and row.get("License Model") == "No License required"
        ):
            return f"ec2:{box.group('type')}"
        return None
    if family == "NAT Gateway" and row.get("operation") == "NatGateway":
        if _usage(row, "NatGateway-Hours"):
            return "nat:hour"
        if _usage(row, "NatGateway-Bytes"):
            return "nat:gb"
        return None
    if family == "Storage" and re.match(_PFX + r"EBS:VolumeUsage", row.get("usageType", "")):
        api = row.get("Volume API Name", "")
        return f"ebs:{api}" if api in ("gp2", "gp3", "io2") else None
    return None


def _vpc(row: dict[str, str]) -> str | None:
    """Public IPv4 addresses, Elastic IPs included, are billed under Amazon VPC."""
    if row.get("Group") != "VPCPublicIPv4Address":
        return None
    if _usage(row, "PublicIPv4:InUseAddress"):
        return "eip:in-use-hour"
    if _usage(row, "PublicIPv4:IdleAddress"):
        return "eip:idle-hour"
    return None


def _deep_archive(row: dict[str, str]) -> str | None:
    return "s3:deep-archive" if _usage(row, "TimedStorage-GDA-ByteHrs") else None


def _rds(row: dict[str, str]) -> str | None:
    if row.get("Product Family") != "Database Instance":
        return None
    engine = _RDS_ENGINES.get(row.get("Database Engine", ""))
    deployment = _RDS_DEPLOYMENTS.get(row.get("Deployment Option", ""))
    match = _RDS.match(row.get("usageType", ""))
    if not (engine and deployment and match) or row.get("License Model") != "No license required":
        return None
    return f"rds:{engine}:{deployment}:{row.get('Instance Type') or match.group('class')}"


def _lambda(row: dict[str, str]) -> str | None:
    if _usage(row, "Lambda-GB-Second"):
        return "lambda:gb-second"
    if _usage(row, "Lambda-GB-Second-ARM"):
        return "lambda:gb-second-arm"
    if row.get("Group") == "AWS-Lambda-Requests" and _usage(row, "Request"):
        return "lambda:request"
    return None


def _dynamodb(row: dict[str, str]) -> str | None:
    for usage, key in (
        ("ReadRequestUnits", "dynamodb:read-request"), ("WriteRequestUnits", "dynamodb:write-request"),
        ("ReadCapacityUnit-Hrs", "dynamodb:rcu-hour"), ("WriteCapacityUnit-Hrs", "dynamodb:wcu-hour"),
    ):
        if _usage(row, usage):
            return key
    if row.get("Product Family") == "Database Storage" and _usage(row, "TimedStorage-ByteHrs"):
        return "dynamodb:storage-gb"
    return None


def _s3(row: dict[str, str]) -> str | None:
    if row.get("Product Family") != "Storage":
        return None
    for usage, storage_class in _S3_CLASSES.items():
        if _usage(row, usage):
            return f"s3:{storage_class}"
    return None


def _cloudwatch(row: dict[str, str]) -> str | None:
    if row.get("Group") == "Ingested Logs" and _usage(row, "DataProcessing-Bytes"):
        return "logs:ingest-gb"
    if "Storage" in row.get("Group", "") and _usage(row, "TimedStorage-ByteHrs"):
        return "logs:storage-gb"
    return None


_MATCHERS: dict[str, Callable[[dict[str, str]], str | None]] = {
    "AmazonEC2": _ec2, "AmazonRDS": _rds, "AWSLambda": _lambda,
    "AmazonDynamoDB": _dynamodb, "AmazonS3": _s3, "AmazonCloudWatch": _cloudwatch,
    "AmazonVPC": _vpc, "AmazonS3GlacierDeepArchive": _deep_archive,
}



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


def build_region(offers: dict[str, Iterable[str]]) -> dict:
    """Prices for one region from its offer files (offer code -> CSV lines).

    Each key gets the first paid tier: the lowest StartingRange with a price above zero,
    so a free tier is skipped. Rows that give one key different prices at that tier fail
    the build rather than pick one.
    """
    published: dict[str, str] = {}
    # key -> starting range -> set of (price, unit)
    found: dict[str, dict[Decimal, set[tuple[Decimal, str]]]] = {}
    for offer, lines in sorted(offers.items()):
        matcher = _MATCHERS.get(offer)
        if matcher is None:
            raise PriceBuildError(f"unknown offer {offer}")
        published[offer], rows = read_offer(lines)
        for row in rows:
            if row.get("TermType") != "OnDemand" or row.get("Currency") != "USD":
                continue
            key = matcher(row)
            if key is None:
                continue
            try:
                usd = Decimal(row["PricePerUnit"])
                start = Decimal(row.get("StartingRange") or "0")
            except (KeyError, ArithmeticError) as exc:
                raise PriceBuildError(f"{offer}: bad price for {key}: {exc}") from exc
            if usd > 0:
                unit = row.get("Unit", "")
                found.setdefault(key, {}).setdefault(start, set()).add((usd, _UNITS.get(unit, unit)))
    prices: dict[str, list] = {}
    for key, tiers in sorted(found.items()):
        first = tiers[min(tiers)]
        if len(first) > 1:
            raise PriceBuildError(f"{key}: rows disagree on the price: {sorted(first)}")
        usd, unit = next(iter(first))
        prices[key] = [float(usd), unit]
    return {"published": published, "prices": prices}


def build(regions: dict[str, dict[str, Iterable[str]]]) -> dict:
    """The whole snapshot: region -> offer code -> CSV lines."""
    return {
        "schema": SCHEMA,
        "source": "AWS Price List bulk API, on-demand, USD",
        "regions": {region: build_region(offers) for region, offers in sorted(regions.items())},
    }


def dump(data: dict) -> bytes:
    """Deterministic bytes: sorted keys, no whitespace, gzip without a timestamp or name."""
    text = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return gzip.compress(text, compresslevel=9, mtime=0)


def write(data: dict, path: Path) -> None:
    path.write_bytes(dump(data))
