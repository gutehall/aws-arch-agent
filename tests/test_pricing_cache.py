"""The SKU catalog and the SQLite price cache. Offline: everything lives under tmp_path."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from aws_arch_agent.pricing import catalog
from aws_arch_agent.pricing.build import prices_from_rows
from aws_arch_agent.pricing.cache import FILE_NAME, PriceCache, default_path

# Every key prefix the estimators price, with one example key.
KEYS = [
    "ec2:m5.large", "rds:postgres:multi-az:db.r6g.large", "rds:aurora-mysql:single-az:db.r6g.large",
    "nat:hour", "nat:gb", "ebs:gp2", "ebs:gp3", "ebs:io2", "eip:in-use-hour", "eip:idle-hour",
    "lambda:gb-second", "lambda:gb-second-arm", "lambda:request", "dynamodb:read-request",
    "dynamodb:write-request", "dynamodb:rcu-hour", "dynamodb:wcu-hour", "dynamodb:storage-gb",
    "s3:standard", "s3:glacier-ir", "s3:deep-archive", "logs:ingest-gb", "logs:storage-gb",
]


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize("key", KEYS)
def test_every_estimator_key_has_an_offer_and_query(key: str) -> None:
    spec = catalog.spec(key)
    assert spec is not None and spec.offer in catalog.MATCHERS
    query = spec.query("eu-north-1")
    assert query["ServiceCode"] == spec.offer
    assert {"Type": "TERM_MATCH", "Field": "regionCode", "Value": "eu-north-1"} in query["Filters"]


@pytest.mark.parametrize("key", ["ec2:", "rds:oracle:single-az:db.m5.large", "rds:postgres:x", "ebs:magic",
                                 "s3:tape", "unknown", "lambda:edge"])
def test_unknown_keys_have_no_spec(key: str) -> None:
    assert catalog.spec(key) is None and catalog.offer_for(key) is None


def _item(family: str, attributes: dict, usd: str, unit: str = "Hrs", begin: str = "0",
          published: str = "2026-11-05T16:26:28Z") -> str:
    return json.dumps({
        "product": {"productFamily": family, "attributes": attributes},
        "publicationDate": published,
        "terms": {"OnDemand": {"T1": {"priceDimensions": {"D1": {
            "pricePerUnit": {"USD": usd}, "unit": unit, "beginRange": begin}}}}},
    })


def test_query_api_products_match_with_the_bulk_matcher() -> None:
    linux = {"instanceType": "m5.large", "operatingSystem": "Linux", "tenancy": "Shared",
             "preInstalledSw": "NA", "capacitystatus": "Used", "licenseModel": "No License required",
             "usagetype": "EUN1-BoxUsage:m5.large", "regionCode": "eu-north-1"}
    rows = [
        *catalog.api_rows(_item("Compute Instance", linux, "0.102")),
        *catalog.api_rows(_item("Compute Instance", {**linux, "operatingSystem": "Windows"}, "0.194")),
    ]
    assert prices_from_rows("AmazonEC2", rows) == {"ec2:m5.large": [0.102, "Hrs"]}
    assert catalog.publication_date(_item("Compute Instance", linux, "1")) == "2026-11-05"
    rds = {"instanceType": "db.r6g.large", "databaseEngine": "PostgreSQL", "deploymentOption": "Multi-AZ",
           "licenseModel": "No license required", "usagetype": "Multi-AZUsage:db.r6g.large"}
    assert prices_from_rows("AmazonRDS", catalog.api_rows(_item("Database Instance", rds, "0.45"))) == {
        "rds:postgres:multi-az:db.r6g.large": [0.45, "Hrs"]}


def test_query_api_first_paid_tier_and_no_usd() -> None:
    attrs = {"usagetype": "Lambda-GB-Second"}
    rows = [
        *catalog.api_rows(_item("Serverless", attrs, "0.0000150000", "Lambda-GB-Second", begin="6000000000")),
        *catalog.api_rows(_item("Serverless", attrs, "0.0000166667", "Lambda-GB-Second")),
        *catalog.api_rows(json.dumps({"product": {}, "terms": {"OnDemand": {"T": {"priceDimensions": {
            "D": {"pricePerUnit": {"CNY": "1"}}}}}}})),
    ]
    assert prices_from_rows("AWSLambda", rows) == {"lambda:gb-second": [0.0000166667, "Lambda-GB-Second"]}


def test_default_path(tmp_path: Path) -> None:
    assert default_path({"AWS_ARCH_AGENT_CACHE_DIR": str(tmp_path)}) == tmp_path / FILE_NAME
    assert default_path({"XDG_CACHE_HOME": str(tmp_path)}) == tmp_path / "aws-arch-agent" / FILE_NAME
    assert default_path({}) == Path.home() / ".cache" / "aws-arch-agent" / FILE_NAME


def test_fresh_hit_expiry_and_stale_read(tmp_path: Path) -> None:
    clock = Clock()
    cache = PriceCache(tmp_path / "p.sqlite3", ttl_hours=1, clock=clock)
    cache.put_many("eu-north-1", "AmazonEC2", {"ec2:m5.large": [0.102, "Hrs"]}, "2026-11-05", "bulk")
    hit = cache.get("eu-north-1", "ec2:m5.large")
    assert hit is not None and hit.usd == 0.102 and hit.unit == "Hrs" and not hit.stale
    assert hit.published_date == "2026-11-05" and hit.source == "bulk" and hit.offer_code == "AmazonEC2"
    assert cache.get("us-east-1", "ec2:m5.large") is None
    clock.now += 3601
    assert cache.get("eu-north-1", "ec2:m5.large") is None
    stale = cache.get("eu-north-1", "ec2:m5.large", allow_stale=True)
    assert stale is not None and stale.stale and stale.usd == 0.102


def test_known_misses_and_offer_tracking(tmp_path: Path) -> None:
    clock = Clock()
    cache = PriceCache(tmp_path / "p.sqlite3", ttl_hours=24, clock=clock)
    cache.put_many("eu-north-1", "AmazonEC2", {}, None, "api", missing=["ec2:m99.huge"])
    miss = cache.get("eu-north-1", "ec2:m99.huge")
    assert miss is not None and miss.usd is None
    assert not cache.offer_fresh("eu-north-1", "AmazonEC2")
    cache.mark_offer("eu-north-1", "AmazonEC2", "2026-11-05")
    assert cache.offer_fresh("eu-north-1", "AmazonEC2")
    clock.now += 24 * 3600
    assert not cache.offer_fresh("eu-north-1", "AmazonEC2")


def test_invalidate(tmp_path: Path) -> None:
    cache = PriceCache(tmp_path / "p.sqlite3")
    for region in ("eu-north-1", "us-east-1"):
        cache.put_many(region, "AmazonEC2", {"ec2:m5.large": [0.1, "Hrs"]}, None, "bulk")
        cache.mark_offer(region, "AmazonEC2", None)
    cache.invalidate("eu-north-1")
    assert cache.get("eu-north-1", "ec2:m5.large") is None and not cache.offer_fresh("eu-north-1", "AmazonEC2")
    assert cache.get("us-east-1", "ec2:m5.large") is not None
    cache.invalidate()
    assert list(cache.keys("us-east-1")) == []


def test_wal_mode_and_persistence(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "p.sqlite3"
    PriceCache(path).put_many("us-east-1", "AmazonEC2", {"ec2:m5.large": [0.096, "Hrs"]}, None, "api")
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert PriceCache(path).get("us-east-1", "ec2:m5.large") is not None  # a new process reads it


def test_unusable_cache_is_no_cache(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    cache = PriceCache(blocker / "p.sqlite3")
    cache.put_many("us-east-1", "AmazonEC2", {"ec2:m5.large": [0.096, "Hrs"]}, None, "api")
    cache.mark_offer("us-east-1", "AmazonEC2", None)
    cache.invalidate()
    assert cache.get("us-east-1", "ec2:m5.large") is None and not cache.offer_fresh("us-east-1", "AmazonEC2")


def test_concurrent_readers_and_writers(tmp_path: Path) -> None:
    path = tmp_path / "p.sqlite3"
    errors: list[BaseException] = []

    def work(n: int) -> None:
        try:
            cache = PriceCache(path)
            for i in range(25):
                cache.put_many("us-east-1", "AmazonEC2", {f"ec2:t{n}.x{i}": [i + 0.5, "Hrs"]}, None, "bulk")
                found = cache.get("us-east-1", f"ec2:t{n}.x{i}")
                assert found is not None and found.usd == i + 0.5
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(list(PriceCache(path).keys("us-east-1"))) == 150
