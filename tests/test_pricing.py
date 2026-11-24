"""Live AWS pricing: bulk CSV parsing, providers, the hybrid lookup order. All offline."""
import csv
import io
import json
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aws_arch_agent import pricing
from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.pricing import (
    Boto3PricingProvider,
    BulkPricingProvider,
    HybridPriceProvider,
    InMemoryPriceProvider,
    OffPriceProvider,
)
from aws_arch_agent.pricing.build import OFFER_URL, PriceBuildError, build_region, read_offer
from aws_arch_agent.pricing.cache import PriceCache
from aws_arch_agent.pricing.providers import PricingUnavailable

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "aws_arch_agent" / "pricing"
COLUMNS = [
    "SKU", "TermType", "StartingRange", "Unit", "PricePerUnit", "Currency", "Product Family",
    "Instance Type", "Operating System", "Tenancy", "Pre Installed S/W", "License Model",
    "CapacityStatus", "usageType", "operation", "Volume API Name", "Database Engine",
    "Deployment Option", "Group",
]


def _offer(code: str, rows: list[dict], published: str = "2026-11-05T16:26:28Z") -> list[str]:
    out = io.StringIO()
    for key, value in (("FormatVersion", "v1.0"), ("Disclaimer", "x"), ("Publication Date", published),
                       ("Version", "1"), ("OfferCode", code)):
        out.write(f'"{key}","{value}"\n')
    writer = csv.DictWriter(out, fieldnames=COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for row in rows:
        writer.writerow({"TermType": "OnDemand", "Currency": "USD", "StartingRange": "0", **row})
    return out.getvalue().splitlines(keepends=True)


LINUX = {"Product Family": "Compute Instance", "Operating System": "Linux", "Tenancy": "Shared",
         "Pre Installed S/W": "NA", "License Model": "No License required", "CapacityStatus": "Used",
         "Unit": "Hrs", "operation": "RunInstances"}


def _offers(prefix: str = "") -> dict[str, list[str]]:
    return {
        "AmazonEC2": _offer("AmazonEC2", [
            {**LINUX, "Instance Type": "m5.large", "usageType": f"{prefix}BoxUsage:m5.large", "PricePerUnit": "0.096"},
            # Windows, dedicated, reserved and unused-capacity rows are other prices.
            {**LINUX, "Operating System": "Windows", "usageType": f"{prefix}BoxUsage:m5.large", "PricePerUnit": "0.188"},
            {**LINUX, "Tenancy": "Dedicated", "usageType": f"{prefix}DedicatedUsage:m5.large", "PricePerUnit": "0.11"},
            {**LINUX, "TermType": "Reserved", "usageType": f"{prefix}BoxUsage:m5.large", "PricePerUnit": "0.06"},
            {**LINUX, "CapacityStatus": "UnusedCapacityReservation", "usageType": f"{prefix}UnusedBox:m5.large",
             "PricePerUnit": "0.096"},
            {"Product Family": "NAT Gateway", "operation": "NatGateway", "usageType": f"{prefix}NatGateway-Hours",
             "Unit": "Hrs", "PricePerUnit": "0.045"},
            {"Product Family": "NAT Gateway", "operation": "NatGateway", "usageType": f"{prefix}NatGateway-Bytes",
             "Unit": "GB", "PricePerUnit": "0.045"},
            {"Product Family": "NAT Gateway", "operation": "NatGateway",
             "usageType": f"{prefix}RegionalNatGateway-Bytes", "Unit": "GB", "PricePerUnit": "0.09"},
            {"Product Family": "Storage", "usageType": "EBS:VolumeUsage.gp3", "Volume API Name": "gp3",
             "Unit": "GB-Mo", "PricePerUnit": "0.08"},
            {"Product Family": "Storage", "usageType": "EBS:VolumeUsage.sc1", "Volume API Name": "sc1",
             "Unit": "GB-Mo", "PricePerUnit": "0.015"},
        ]),
        "AmazonVPC": _offer("AmazonVPC", [
            {"Group": "VPCPublicIPv4Address", "usageType": f"{prefix or 'USE1-'}PublicIPv4:IdleAddress",
             "Unit": "Hrs", "PricePerUnit": "0.005"},
            {"Group": "VPCIPv4ContiguousBlocks", "usageType": f"{prefix}PublicIPv4:ContiguousBlock",
             "Unit": "Hrs", "PricePerUnit": "0.008"},
        ]),
        "AmazonS3GlacierDeepArchive": _offer("AmazonS3GlacierDeepArchive", [
            {"usageType": f"{prefix}TimedStorage-GDA-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "0.00099"},
        ]),
        "AmazonRDS": _offer("AmazonRDS", [
            {"Product Family": "Database Instance", "Instance Type": "db.m5.large", "Database Engine": "PostgreSQL",
             "Deployment Option": "Multi-AZ", "License Model": "No license required",
             "usageType": f"{prefix}Multi-AZUsage:db.m5.large", "Unit": "Hrs", "PricePerUnit": "0.356"},
            {"Product Family": "Database Instance", "Instance Type": "db.m5.large",
             "Database Engine": "PostgreSQL (on-premise for Outpost)", "Deployment Option": "Multi-AZ",
             "License Model": "No license required", "usageType": "Multi-AZUsage:db.m5.large",
             "Unit": "Hrs", "PricePerUnit": "0.164"},
        ]),
        "AWSLambda": _offer("AWSLambda", [
            # Tiers: the first paid tier wins.
            {"usageType": f"{prefix}Lambda-GB-Second", "Unit": "Lambda-GB-Second", "PricePerUnit": "0.0000150000",
             "StartingRange": "6000000000"},
            {"usageType": f"{prefix}Lambda-GB-Second", "Unit": "Lambda-GB-Second", "PricePerUnit": "0.0000166667"},
            {"usageType": "Global-Lambda-GB-Second", "Unit": "Lambda-GB-Second", "PricePerUnit": "0"},
        ]),
        "AmazonDynamoDB": _offer("AmazonDynamoDB", [
            # A free tier at 0 is skipped.
            {"usageType": f"{prefix}ReadCapacityUnit-Hrs", "Unit": "ReadCapacityUnit-Hrs", "PricePerUnit": "0"},
            {"usageType": f"{prefix}ReadCapacityUnit-Hrs", "Unit": "ReadCapacityUnit-Hrs", "PricePerUnit": "0.00013",
             "StartingRange": "18600"},
            # Infrequent Access is another table class, not a region prefix.
            {"usageType": "IA-ReadRequestUnits", "Unit": "ReadRequestUnits", "PricePerUnit": "0.00000031"},
        ]),
        "AmazonS3": _offer("AmazonS3", [
            {"Product Family": "Storage", "usageType": f"{prefix}TimedStorage-ByteHrs", "Unit": "GB-Mo",
             "PricePerUnit": "0.023"},
            {"Product Family": "Storage", "usageType": f"{prefix}Files-TimedStorage-ByteHrs", "Unit": "GB-Mo",
             "PricePerUnit": "0.3"},
        ]),
        "AmazonCloudWatch": _offer("AmazonCloudWatch", [
            {"Group": "Ingested Logs", "usageType": f"{prefix}DataProcessing-Bytes", "Unit": "GB",
             "PricePerUnit": "0.5"},
            {"Group": "Ingested Logs", "usageType": "DataProcessing-Bytes", "Unit": "GB", "PricePerUnit": "0.5"},
            {"Group": "Amazon CloudWatch Standard Storage pricing current",
             "usageType": f"{prefix}TimedStorage-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "0.03"},
            # Infrequent Access storage and the free archival tier are other prices.
            {"Group": "", "usageType": f"{prefix}TimedStorage-IA-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "0.018"},
            {"Group": "CW-MonthlyFree-Archival", "usageType": "Global-TimedStorage-ByteHrs", "Unit": "GB-Mo",
             "PricePerUnit": "0"},
        ]),
    }


@pytest.mark.parametrize("prefix", ["", "EUN1-", "EU-"])
def test_build_keeps_only_the_skus_the_rules_use(prefix: str) -> None:
    region = build_region(_offers(prefix))
    assert region["published"] == {code: "2026-11-05" for code in _offers(prefix)}
    assert region["prices"] == {
        "ec2:m5.large": [0.096, "Hrs"],
        "nat:hour": [0.045, "Hrs"],
        "nat:gb": [0.045, "GB"],
        "ebs:gp3": [0.08, "GB-Mo"],
        "ebs:sc1": [0.015, "GB-Mo"],
        "eip:idle-hour": [0.005, "Hrs"],
        "rds:postgres:multi-az:db.m5.large": [0.356, "Hrs"],
        "lambda:gb-second": [0.0000166667, "Lambda-GB-Second"],
        "dynamodb:rcu-hour": [0.00013, "ReadCapacityUnit-Hrs"],
        "s3:standard": [0.023, "GB-Mo"],
        "s3:deep-archive": [0.00099, "GB-Mo"],
        "logs:ingest-gb": [0.5, "GB"],
        "logs:storage-gb": [0.03, "GB-Mo"],
    }


def test_build_fails_when_rows_disagree() -> None:
    offers = _offers()
    offers["AmazonS3"] = _offer("AmazonS3", [
        {"Product Family": "Storage", "usageType": "TimedStorage-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "0.023"},
        {"Product Family": "Storage", "usageType": "TimedStorage-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "0.025"},
    ])
    with pytest.raises(PriceBuildError, match="s3:standard"):
        build_region(offers)


def test_offer_without_publication_date_fails() -> None:
    with pytest.raises(PriceBuildError, match="Publication Date"):
        read_offer(['"FormatVersion","v1.0"\n', "\n", "\n", "\n", "\n", '"SKU"\n'])



def _no_network(*_args, **_kwargs):
    raise AssertionError("the test suite must not open a network connection")


# --- Providers -----------------------------------------------------------------


def test_no_static_price_list_ships() -> None:
    assert not list(PACKAGE.glob("*.json*")) and not list(PACKAGE.glob("*.csv*"))
    assert not (ROOT / "scripts" / "refresh_prices.py").exists()


def test_suite_prices_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """conftest installs an in-memory provider: no test reaches AWS."""
    monkeypatch.setattr(socket, "socket", _no_network)
    assert isinstance(pricing.provider(), InMemoryPriceProvider)
    m5 = pricing.price("ec2:m5.large", "us-east-1")
    assert m5 is not None and m5.unit == "Hrs" and 0.01 < m5.usd < 1 and m5.source == "memory"


def test_in_memory_provider() -> None:
    mem = InMemoryPriceProvider({"eu-north-1": {"ec2:m5.large": [0.102, "Hrs"]}},
                                {"eu-north-1": {"AmazonEC2": "2026-11-05"}})
    found = mem.price("ec2:m5.large", "eu-north-1")
    assert found == pricing.Price(0.102, "Hrs", "eu-north-1", "2026-11-05", "memory")
    assert mem.price("ec2:m5.large", "us-east-1") is None and mem.price("nat:hour", "eu-north-1") is None
    assert InMemoryPriceProvider.from_snapshot({"regions": {"eu-north-1": build_region(_offers("EUN1-"))}}).price(
        "nat:gb", "eu-north-1") == pricing.Price(0.045, "GB", "eu-north-1", "2026-11-05", "memory")


def test_seen_prices_give_the_note() -> None:
    mem = InMemoryPriceProvider({"eu-north-1": {"ec2:m5.large": [0.102, "Hrs"], "ebs:gp3": [0.08, "GB-Mo"]}},
                                {"eu-north-1": {"AmazonEC2": "2026-11-05"}})
    with pricing.use_provider(mem):
        assert pricing.snapshot_date("eu-north-1") is None  # nothing priced yet
        pricing.price("ec2:m5.large", "eu-north-1")
        assert pricing.price_note("eu-north-1") == {
            "region": "eu-north-1", "snapshot_date": "2026-11-05",
            "pricing_source": "prices supplied in memory", "fetched_at": None, "stale": False,
        }
    assert pricing.snapshot_date("eu-north-1") is None  # the outer provider saw nothing


def test_off() -> None:
    assert isinstance(pricing.configure("off"), OffPriceProvider)
    with pricing.use_provider(pricing.configure("off")):
        assert pricing.price("ec2:m5.large", "us-east-1") is None
    with pytest.raises(ValueError, match="pricing source"):
        HybridPriceProvider(source="sometimes")


def _api_item(usage: str, usd: str, instance: str = "m5.large") -> str:
    return json.dumps({
        "product": {"productFamily": "Compute Instance", "attributes": {
            "instanceType": instance, "operatingSystem": "Linux", "tenancy": "Shared", "preInstalledSw": "NA",
            "capacitystatus": "Used", "licenseModel": "No License required", "usagetype": usage}},
        "publicationDate": "2026-11-05T16:26:28Z",
        "terms": {"OnDemand": {"T": {"priceDimensions": {"D": {"pricePerUnit": {"USD": usd}, "unit": "Hrs"}}}}},
    })


class FakeClient:
    def __init__(self, items: list[str] | None = None, error: Exception | None = None) -> None:
        self.items, self.error, self.calls = items or [], error, []

    def get_paginator(self, name: str) -> "FakeClient":
        assert name == "get_products"
        return self

    def paginate(self, **kwargs: Any) -> list[dict]:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return [{"PriceList": self.items[:1]}, {"PriceList": self.items[1:]}]


def test_boto3_provider_queries_by_region_code() -> None:
    client = FakeClient([_api_item("EUN1-BoxUsage:m5.large", "0.102"), _api_item("EUN1-BoxUsage:m5.large", "0")])
    api = Boto3PricingProvider(client)
    found = api.price("ec2:m5.large", "eu-north-1")
    assert found == pricing.Price(0.102, "Hrs", "eu-north-1", "2026-11-05", "api")
    call = client.calls[0]
    assert call["ServiceCode"] == "AmazonEC2"
    assert {"Type": "TERM_MATCH", "Field": "regionCode", "Value": "eu-north-1"} in call["Filters"]
    assert {"Type": "TERM_MATCH", "Field": "instanceType", "Value": "m5.large"} in call["Filters"]
    assert Boto3PricingProvider(FakeClient([])).price("ec2:m5.large", "eu-north-1") is None
    assert Boto3PricingProvider(FakeClient(error=RuntimeError("throttled"))).price("ec2:m5.large", "x") is None
    with pytest.raises(PricingUnavailable, match="throttled"):
        Boto3PricingProvider(FakeClient(error=RuntimeError("throttled"))).fetch("ec2:m5.large", "eu-north-1")


def test_boto3_provider_without_boto3_or_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(PricingUnavailable, match="boto3"):
        Boto3PricingProvider().fetch("ec2:m5.large", "us-east-1")

    class Session:
        def get_credentials(self) -> None:
            return None

    monkeypatch.setitem(sys.modules, "boto3", type(sys)("boto3"))
    sys.modules["boto3"].Session = Session  # type: ignore[attr-defined]
    with pytest.raises(PricingUnavailable, match="credentials"):
        Boto3PricingProvider().fetch("ec2:m5.large", "us-east-1")


class FakeBulk:
    """An opener serving the test offers by URL; counts downloads."""

    def __init__(self, prefix: str = "EUN1-", fail: bool = False) -> None:
        self.offers, self.fail, self.urls = _offers(prefix), fail, []

    def __call__(self, url: str) -> list[str]:
        self.urls.append(url)
        if self.fail:
            raise PricingUnavailable("Price List bulk API: no network")
        for code, lines in self.offers.items():
            if url == OFFER_URL.format(offer=code, region="eu-north-1"):
                return lines
        return []  # 404: no file for this region


def test_bulk_provider_streams_one_offer() -> None:
    opener = FakeBulk()
    bulk = BulkPricingProvider(opener)
    assert bulk.price("nat:hour", "eu-north-1") == pricing.Price(0.045, "Hrs", "eu-north-1", "2026-11-05", "bulk")
    assert opener.urls == [OFFER_URL.format(offer="AmazonEC2", region="eu-north-1")]
    assert bulk.price("nat:hour", "mars-north-1") is None  # no such file
    assert bulk.fetch_offer("AmazonEC2", "mars-north-1") == (None, {})

    def broken(_url: str):
        yield '"FormatVersion","v1.0"\n'
        raise OSError("connection reset")

    with pytest.raises(PricingUnavailable, match="connection reset"):
        BulkPricingProvider(broken).fetch_offer("AmazonEC2", "eu-north-1")


def _hybrid(tmp_path: Path, source: str = "auto", api: Any = None, bulk: Any = None, **kw: Any) -> HybridPriceProvider:
    return HybridPriceProvider(
        source=source, cache=PriceCache(tmp_path / "cache.sqlite3", kw.pop("ttl", 24), **kw),
        api=api or Boto3PricingProvider(FakeClient(error=PricingUnavailable("no AWS credentials"))),
        bulk=bulk or BulkPricingProvider(FakeBulk()),
    )


def test_hybrid_uses_the_api_and_caches(tmp_path: Path) -> None:
    client = FakeClient([_api_item("EUN1-BoxUsage:m5.large", "0.102")])
    first = _hybrid(tmp_path, api=Boto3PricingProvider(client), bulk=BulkPricingProvider(FakeBulk(fail=True)))
    found = first.price("ec2:m5.large", "eu-north-1")
    assert found is not None and found.usd == 0.102 and found.source == "api" and found.fetched_at
    first.price("ec2:m5.large", "eu-north-1")
    assert len(client.calls) == 1  # memory
    # A new process: the SQLite cache answers.
    again = _hybrid(tmp_path, api=Boto3PricingProvider(FakeClient(error=AssertionError("not called"))))
    cached = again.price("ec2:m5.large", "eu-north-1")
    assert cached is not None and cached.usd == 0.102 and cached.source == "api" and not cached.stale


def test_hybrid_api_miss_is_final(tmp_path: Path) -> None:
    opener = FakeBulk()
    hybrid = _hybrid(tmp_path, api=Boto3PricingProvider(FakeClient([])), bulk=BulkPricingProvider(opener))
    assert hybrid.price("ec2:m99.huge", "eu-north-1") is None
    assert opener.urls == []
    assert hybrid.price("unknown", "eu-north-1") is None


def test_hybrid_falls_back_to_bulk_and_reads_each_offer_once(tmp_path: Path) -> None:
    opener = FakeBulk()
    hybrid = _hybrid(tmp_path, bulk=BulkPricingProvider(opener))
    assert hybrid.price("nat:hour", "eu-north-1").source == "bulk"  # type: ignore[union-attr]
    assert hybrid.price("ec2:m5.large", "eu-north-1").usd == 0.096  # type: ignore[union-attr]
    assert hybrid.price("ec2:m99.huge", "eu-north-1") is None
    assert len(opener.urls) == 1 and hybrid.warnings == []
    # A new process within the TTL: hits come from the cache, and a miss does not download again.
    opener2 = FakeBulk()
    again = _hybrid(tmp_path, bulk=BulkPricingProvider(opener2))
    assert again.price("ebs:gp3", "eu-north-1").usd == 0.08  # type: ignore[union-attr]
    assert again.price("ec2:m99.huge", "eu-north-1") is None
    assert opener2.urls == []


class Clock:
    now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def test_hybrid_offline_uses_stale_cache_then_none(tmp_path: Path) -> None:
    clock = Clock()
    online = _hybrid(tmp_path, ttl=1, clock=clock)
    assert online.price("nat:hour", "eu-north-1") is not None
    clock.now += 7200
    offline = _hybrid(tmp_path, ttl=1, clock=clock, bulk=BulkPricingProvider(FakeBulk(fail=True)))
    stale = offline.price("nat:hour", "eu-north-1")
    assert stale is not None and stale.stale and stale.usd == 0.045
    assert offline.price("s3:standard", "eu-north-1") is None  # never cached
    assert any("expired cached prices" in w for w in offline.warnings)
    assert any("no network" in w for w in offline.warnings)
    assert any("offline" in w for w in offline.warnings)


def test_hybrid_refresh_and_sources(tmp_path: Path) -> None:
    opener = FakeBulk()
    _hybrid(tmp_path, bulk=BulkPricingProvider(opener)).price("nat:hour", "eu-north-1")
    refreshed = HybridPriceProvider(
        source="bulk", cache=PriceCache(tmp_path / "cache.sqlite3"), bulk=BulkPricingProvider(opener), refresh=True,
        api=Boto3PricingProvider(FakeClient(error=AssertionError("bulk only"))),
    )
    assert refreshed.price("nat:hour", "eu-north-1") is not None
    assert len(opener.urls) == 2  # --refresh-prices downloaded again
    api_only = _hybrid(tmp_path / "b", source="api", bulk=BulkPricingProvider(FakeBulk(fail=True)))
    assert api_only.price("nat:hour", "eu-north-1") is None
    assert api_only.warnings == [
        "Price List Query API: no AWS credentials",
        "Prices could not be fetched (offline?); resources without a cached price are not estimated.",
    ]
    assert _hybrid(tmp_path / "c", source="off").price("nat:hour", "eu-north-1") is None


def test_hybrid_survives_a_broken_cache(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x", encoding="utf-8")
    hybrid = HybridPriceProvider(cache=PriceCache(tmp_path / "file" / "c.sqlite3"),
                                 api=Boto3PricingProvider(FakeClient(error=RuntimeError("down"))),
                                 bulk=BulkPricingProvider(FakeBulk()))
    assert hybrid.price("nat:hour", "eu-north-1") is not None


# --- Scan wiring ----------------------------------------------------------------


def test_config_region(tmp_path: Path) -> None:
    assert load_config(tmp_path).region is None  # not set: detected per stack
    (tmp_path / ".aws-arch-agent.yaml").write_text("region: EU-North-1\n", encoding="utf-8")
    assert load_config(tmp_path).region == "eu-north-1"
    assert load_config(tmp_path, region="eu-west-1").region == "eu-west-1"  # the flag wins
    (tmp_path / ".aws-arch-agent.yaml").write_text("region: europe\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="region"):
        load_config(tmp_path)


def _repo(root: Path) -> None:
    (root / "package.json").write_text("{}", encoding="utf-8")
    (root / "lib").mkdir()
    (root / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")


def _priced_repo(root: Path) -> None:
    (root / "template.json").write_text(json.dumps({"Resources": {
        "Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": "s"}}}}), encoding="utf-8")


def test_report_states_the_price_region(tmp_path: Path) -> None:
    _repo(tmp_path)
    out = tmp_path / "report.md"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "- Prices: on-demand, us-east-1 (default; no prices used)" in out.read_text(encoding="utf-8")

    priced = tmp_path / "priced"
    priced.mkdir()
    _priced_repo(priced)
    out_json = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["--repo", str(priced), "--no-llm", "--format", "json",
                                      "--region", "eu-north-1", "--out", str(out_json)])
    assert result.exit_code == 0, result.output
    notes = json.loads(out_json.read_text(encoding="utf-8"))["context"]["notes"]
    north = notes["prices"]["snapshot_date"]
    assert north and len(north) == 10
    assert notes["prices"] == {
        "region": "eu-north-1", "snapshot_date": north, "warnings": [],
        "regions": [{"region": "eu-north-1", "source": "--region / config", "snapshot_date": north,
                     "pricing_source": "prices supplied in memory", "fetched_at": None, "stale": False}],
    }


def test_pricing_warnings_reach_the_console(tmp_path: Path) -> None:
    _priced_repo(tmp_path)

    class Down:
        warnings = ["Prices could not be fetched (offline?); resources without a cached price are not estimated."]

        def price(self, key: str, region: str) -> None:
            return None

    with pricing.use_provider(Down()):
        result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "json",
                                          "--out", str(tmp_path / "r.json")])
    assert result.exit_code == 0, result.output
    assert "Prices could not be fetched (offline?)" in result.output
    notes = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["context"]["notes"]
    assert notes["prices"]["warnings"] == Down.warnings


def test_bad_region_flag_fails(tmp_path: Path) -> None:
    _repo(tmp_path)
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--region", "nowhere",
                                      "--out", str(tmp_path / "r.md")])
    assert result.exit_code != 0
    assert "--region must be an AWS region code" in result.output


def test_short_offer_row_is_skipped_not_a_crash() -> None:
    """A row cut off before its price has no Currency, so it is not read as a price."""
    lines = _offer("AmazonS3", [
        {"Product Family": "Storage", "usageType": "TimedStorage-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "0.023"},
    ])
    lines.append('"SKU1","OnDemand","0","GB-Mo"\n')
    assert build_region({"AmazonS3": lines})["prices"] == {"s3:standard": [0.023, "GB-Mo"]}


def test_row_without_a_price_is_a_build_error() -> None:
    lines = _offer("AmazonS3", [
        {"Product Family": "Storage", "usageType": "TimedStorage-ByteHrs", "Unit": "GB-Mo", "PricePerUnit": "n/a"},
    ])
    with pytest.raises(PriceBuildError, match="bad price"):
        build_region({"AmazonS3": lines})


@pytest.mark.parametrize("region", ["us-gov-west-1", "cn-north-1", "eusc-de-east-1", "ap-southeast-5"])
def test_region_codes_accepted(tmp_path: Path, region: str) -> None:
    assert load_config(tmp_path, region=region).region == region


def test_v2_states_the_price_region(tmp_path: Path) -> None:
    from aws_arch_agent.agent.v2_graph import analyze_v2

    _repo(tmp_path)
    report, ctx, _findings, _warnings = analyze_v2(tmp_path, use_llm=False, skip_synth=True,
                                                   price_region="eu-north-1")
    assert ctx.notes["prices"]["region"] == "eu-north-1"
    assert "- Prices: on-demand, eu-north-1" in report


def test_boto3_setup_errors_are_unavailable_not_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    class Session:
        def __init__(self) -> None:
            raise RuntimeError("The config profile (nope) could not be found")

    monkeypatch.setitem(sys.modules, "boto3", type(sys)("boto3"))
    sys.modules["boto3"].Session = Session  # type: ignore[attr-defined]
    with pytest.raises(PricingUnavailable, match="could not be found"):
        Boto3PricingProvider().fetch("ec2:m5.large", "us-east-1")
    assert Boto3PricingProvider().price("ec2:m5.large", "us-east-1") is None


def test_a_page_that_is_not_an_offer_is_not_cached_as_a_miss(tmp_path: Path) -> None:
    calls: list[str] = []

    def proxy_page(url: str) -> list[str]:
        calls.append(url)
        return ["<html>Access denied</html>\n"]

    hybrid = _hybrid(tmp_path, bulk=BulkPricingProvider(proxy_page))
    assert hybrid.price("nat:hour", "eu-north-1") is None
    assert not hybrid.cache.offer_fresh("eu-north-1", "AmazonEC2")
    assert any("not an offer" in w or "Publication Date" in w for w in hybrid.warnings)


def test_truncated_query_results_are_not_known_misses(tmp_path: Path) -> None:
    client = FakeClient([_api_item("EUN1-BoxUsage:m5.large", "0.102"), _api_item("EUN1-BoxUsage:m5.large", "0.102")])
    api = Boto3PricingProvider(client, max_items=2)
    hybrid = _hybrid(tmp_path, api=api)
    assert hybrid.price("ec2:m5.xlarge", "eu-north-1") is None
    assert hybrid.cache.get("eu-north-1", "ec2:m5.xlarge") is None  # not stored as a miss
    assert hybrid.cache.get("eu-north-1", "ec2:m5.large").usd == 0.102  # type: ignore[union-attr]
    assert api.price("ec2:m5.large", "eu-north-1") is not None


def test_bulk_stream_decodes_an_octet_stream_body(monkeypatch: pytest.MonkeyPatch) -> None:
    # The bulk API serves its CSV as application/octet-stream: no charset for requests to use.
    import requests

    from aws_arch_agent.pricing.providers import _stream

    def fake_get(url: str, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        resp.headers["Content-Type"] = "application/octet-stream"
        resp.raw = io.BytesIO('"FormatVersion","v1.0"\n"Région","€"\n'.encode())
        return resp

    monkeypatch.setattr(requests, "get", fake_get)
    assert list(_stream("https://example.invalid/index.csv")) == ['"FormatVersion","v1.0"\n', '"Région","€"\n']
