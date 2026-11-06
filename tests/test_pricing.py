"""Offline AWS price snapshot."""
import csv
import importlib.util
import io
import json
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent import pricing
from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.pricing.build import (
    DEFAULT_REGIONS,
    OFFERS,
    PriceBuildError,
    build,
    build_region,
    dump,
    read_offer,
)

ROOT = Path(__file__).resolve().parents[1]
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
    assert region["published"] == {code: "2026-11-05" for code in OFFERS}
    assert region["prices"] == {
        "ec2:m5.large": [0.096, "Hrs"],
        "nat:hour": [0.045, "Hrs"],
        "nat:gb": [0.045, "GB"],
        "ebs:gp3": [0.08, "GB-Mo"],
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


def test_build_is_deterministic() -> None:
    first = dump(build({"us-east-1": _offers(), "eu-north-1": _offers("EUN1-")}))
    reordered = {"eu-north-1": dict(reversed(list(_offers("EUN1-").items()))), "us-east-1": _offers()}
    assert dump(build(reordered)) == first


def test_refresh_script_rebuilds_from_cached_offers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With the offers cached, the script needs no network and writes the same bytes twice."""
    cache = tmp_path / "cache"
    for region, prefix in (("us-east-1", ""), ("eu-north-1", "EUN1-")):
        (cache / region).mkdir(parents=True)
        for code, lines in _offers(prefix).items():
            (cache / region / f"{code}.csv").write_text("".join(lines), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("refresh_prices", ROOT / "scripts" / "refresh_prices.py")
    assert spec and spec.loader
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    monkeypatch.setattr(socket, "socket", _no_network)
    outs = []
    for name in ("a.json.gz", "b.json.gz"):
        out = tmp_path / name
        assert script.main(["--regions", "us-east-1", "eu-north-1", "--cache-dir", str(cache), "--out", str(out)]) == 0
        outs.append(out.read_bytes())
    assert outs[0] == outs[1]


def _no_network(*_args, **_kwargs):
    raise AssertionError("a scan must not open a network connection")


def test_shipped_snapshot_loads_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "socket", _no_network)
    pricing._snapshot.cache_clear()
    m5 = pricing.price("ec2:m5.large", "us-east-1")
    assert m5 is not None and m5.unit == "Hrs" and 0.01 < m5.usd < 1
    assert m5.region == "us-east-1" and len(m5.snapshot_date) == 10
    assert set(DEFAULT_REGIONS) <= set(pricing.regions())
    deep = pricing.price("s3:deep-archive", "us-east-1")
    assert deep is not None and deep.snapshot_date == pricing._snapshot()["regions"]["us-east-1"][
        "published"]["AmazonS3GlacierDeepArchive"]
    for key in ("nat:hour", "nat:gb", "ebs:gp2", "ebs:gp3", "ebs:io2", "eip:in-use-hour", "eip:idle-hour",
                "rds:postgres:single-az:db.m5.large", "rds:mysql:multi-az:db.m5.large",
                "lambda:gb-second", "lambda:gb-second-arm", "lambda:request",
                "dynamodb:read-request", "dynamodb:write-request", "dynamodb:rcu-hour",
                "dynamodb:wcu-hour", "dynamodb:storage-gb", "s3:standard", "s3:glacier-ir",
                "s3:deep-archive", "logs:ingest-gb", "logs:storage-gb"):
        assert pricing.price(key, "eu-north-1") is not None, key


def test_unknown_type_or_region_gives_no_estimate() -> None:
    assert pricing.price("ec2:m99.huge", "us-east-1") is None
    assert pricing.price("ec2:m5.large", "mars-north-1") is None
    assert pricing.price("unknown", "us-east-1") is None
    assert pricing.snapshot_date("mars-north-1") is None
    assert pricing.price_note("mars-north-1") == {"region": "mars-north-1", "snapshot_date": None}


def test_snapshot_is_small() -> None:
    assert pricing.DATA_PATH.stat().st_size < 200_000
    data = json.loads(__import__("gzip").decompress(pricing.DATA_PATH.read_bytes()))
    assert data["schema"] == 1


def test_config_region(tmp_path: Path) -> None:
    assert load_config(tmp_path).region == "us-east-1"
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


def test_report_states_the_price_region(tmp_path: Path) -> None:
    _repo(tmp_path)
    out = tmp_path / "report.md"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--out", str(out)])
    assert result.exit_code == 0, result.output
    date = pricing.snapshot_date("us-east-1")
    assert f"- Prices: on-demand, us-east-1 (AWS price list of {date})" in out.read_text()

    out_json = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "json",
                                      "--region", "eu-north-1", "--out", str(out_json)])
    assert result.exit_code == 0, result.output
    notes = json.loads(out_json.read_text())["context"]["notes"]
    assert notes["prices"] == {"region": "eu-north-1", "snapshot_date": pricing.snapshot_date("eu-north-1")}

    out_html = tmp_path / "report.html"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "html",
                                      "--region", "ap-south-2", "--out", str(out_html)])
    assert result.exit_code == 0, result.output
    assert "not in the price snapshot" in out_html.read_text()
    assert "No prices for region ap-south-2" in result.output


def test_bad_region_flag_fails(tmp_path: Path) -> None:
    _repo(tmp_path)
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--region", "nowhere",
                                      "--out", str(tmp_path / "r.md")])
    assert result.exit_code != 0
    assert "--region must be an AWS region code" in result.output


@pytest.mark.parametrize("content", [None, b"", b"not gzip", __import__("gzip").compress(b"{not json")])
def test_missing_or_broken_snapshot_gives_no_prices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes | None
) -> None:
    path = tmp_path / "prices.json.gz"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(pricing, "DATA_PATH", path)
    pricing._snapshot.cache_clear()
    try:
        assert pricing.price("ec2:m5.large") is None
        assert pricing.price_note() == {"region": "us-east-1", "snapshot_date": None}
    finally:
        monkeypatch.undo()
        pricing._snapshot.cache_clear()


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


def test_write_is_atomic(tmp_path: Path) -> None:
    from aws_arch_agent.pricing.build import write

    out = tmp_path / "prices.json.gz"
    write({"schema": 1, "regions": {}}, out)
    assert out.is_file() and not (tmp_path / "prices.json.gz.tmp").exists()


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
