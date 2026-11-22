"""The SKU catalog: which AWS price a canonical price key names.

A key such as `ec2:m5.large` or `rds:postgres:multi-az:db.r6g.large` maps to:

* an offer code (`AmazonEC2`, `AmazonRDS`, ...), shared by the Price List Query API
  (`ServiceCode`) and the bulk API (`{offer}/current/{region}/index.csv`);
* Query API filters (`TERM_MATCH` on product attributes, plus `regionCode`) that narrow
  `GetProducts` to a few products;
* a row matcher that names the key a price row is for. Bulk CSV rows are matched as they
  are. Query API products are first turned into the same row shape (`api_rows`), so one
  matcher decides for both sources and they cannot drift apart.

Price keys:
    ec2:<instance type>                         USD per hour, Linux, shared tenancy
    rds:<engine>:<single-az|multi-az>:<class>   USD per hour; engine mysql, postgres,
                                                mariadb, aurora-mysql, aurora-postgresql
    nat:hour, nat:gb                            NAT gateway hour and GB processed
    ebs:<gp2|gp3|io1|io2|st1|sc1|standard>      USD per GB-month
    eip:in-use-hour, eip:idle-hour              public IPv4 address hour
    lambda:gb-second, lambda:gb-second-arm, lambda:request
    dynamodb:read-request, dynamodb:write-request (on-demand, per request unit)
    dynamodb:rcu-hour, dynamodb:wcu-hour        provisioned capacity unit hour
    dynamodb:storage-gb                         USD per GB-month
    s3:<standard|intelligent-tiering|standard-ia|onezone-ia|glacier-ir|glacier|deep-archive>
                                                first-tier USD per GB-month
    logs:ingest-gb, logs:storage-gb             CloudWatch Logs
    ebs:<gp3|io1|io2>-iops, ebs:gp3-throughput  provisioned IOPS-month, MiBps-month
    rds:storage:<gp2|gp3|io1|io2|standard>      single-AZ USD per GB-month
    elb:<alb|nlb|gwlb|clb>-hour                 load balancer hour
    elb:<alb|nlb>-lcu                           load balancer capacity unit hour
    eks:cluster-hour                            EKS control plane hour (standard support)
    fargate:<vcpu|gb>-hour[-arm]                Fargate Linux vCPU hour, GB hour
    elasticache:<redis|memcached|valkey>:<node> cache node hour
    opensearch:<instance type>                  OpenSearch instance hour (r6g.large.search)
    opensearch:storage:<gp2|gp3|io1|standard>   OpenSearch EBS USD per GB-month
    redshift:<node type>                        Redshift node hour
    vpce:hour, vpce:gb                          interface endpoint hour per AZ, GB processed
    kms:key-month                               customer managed key per month
    secrets:secret-month                        Secrets Manager secret per month
    kinesis:shard-hour, kinesis:on-demand-stream-hour
    apigw:rest-request, apigw:http-request      API Gateway request (first paid tier)
    sqs:standard-request, sqs:fifo-request      SQS request (first paid tier)
    sns:request                                 SNS publish request (first paid tier)

Tiered prices are the first paid tier.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterator

# Usage types carry a region prefix (EUN1-, USW2-, EU- for eu-west-1; none in us-east-1).
# IA- (DynamoDB Infrequent Access) and lowercase prefixes are not regions.
_PFX = r"^(?:[A-Z]{2,4}[0-9]-|EU-)?"
_BOX = re.compile(_PFX + r"BoxUsage:(?P<type>[a-z0-9.\-]+)$")
_RDS = re.compile(_PFX + r"(?:InstanceUsage|Multi-AZUsage):(?P<class>db\.[a-z0-9.\-]+)$")
RDS_ENGINES = {
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
EBS_TYPES = ("gp2", "gp3", "io1", "io2", "st1", "sc1", "standard")
_EBS_EXTRA = re.compile(_PFX + r"EBS:VolumeP-(IOPS|Throughput)\.[a-z0-9]+$")
# RDS single-AZ storage usage types (not Aurora, not Multi-AZ, not SQL Server or Oracle).
_RDS_STORAGE = {
    "RDS:GP2-Storage": "gp2", "RDS:GP3-Storage": "gp3", "RDS:PIOPS-Storage": "io1",
    "RDS:PIOPS-IO2-Storage": "io2", "RDS:StorageUsage": "standard",
}
_ELB_FAMILIES = {
    "Load Balancer-Application": "alb", "Load Balancer-Network": "nlb",
    "Load Balancer-Gateway": "gwlb", "Load Balancer": "clb",
}
CACHE_ENGINES = {"Redis": "redis", "Memcached": "memcached", "Valkey": "valkey"}
_FARGATE = {
    "Fargate-vCPU-Hours:perCPU": "fargate:vcpu-hour", "Fargate-GB-Hours": "fargate:gb-hour",
    "Fargate-ARM-vCPU-Hours:perCPU": "fargate:vcpu-hour-arm", "Fargate-ARM-GB-Hours": "fargate:gb-hour-arm",
}
_OPENSEARCH_STORAGE = {"GP2": "gp2", "GP3": "gp3", "PIOPS": "io1", "Magnetic": "standard"}

Row = dict[str, str]
Matcher = Callable[[Row], "str | None"]


def usage(row: Row, name: str) -> bool:
    """Whether the row's usage type is `name`, with or without a region prefix."""
    return re.fullmatch(_PFX + re.escape(name), row.get("usageType") or "") is not None


def _ec2(row: Row) -> str | None:
    family = row.get("Product Family", "")
    if family in ("Compute Instance", "Compute Instance (bare metal)"):
        box = _BOX.match(row.get("usageType") or "")
        if box and (
            row.get("Operating System") == "Linux" and row.get("Tenancy") == "Shared"
            and row.get("Pre Installed S/W") == "NA" and row.get("CapacityStatus") == "Used"
            and row.get("License Model") == "No License required"
        ):
            return f"ec2:{box.group('type')}"
        return None
    if family == "NAT Gateway" and row.get("operation") == "NatGateway":
        if usage(row, "NatGateway-Hours"):
            return "nat:hour"
        if usage(row, "NatGateway-Bytes"):
            return "nat:gb"
        return None
    if family == "Storage" and re.match(_PFX + r"EBS:VolumeUsage", row.get("usageType") or ""):
        api = row.get("Volume API Name", "")
        return f"ebs:{api}" if api in EBS_TYPES else None
    extra = _EBS_EXTRA.match(row.get("usageType") or "")
    if extra and family in ("System Operation", "Provisioned Throughput"):
        api = row.get("Volume API Name", "")
        kind = "iops" if extra.group(1) == "IOPS" else "throughput"
        if (api, kind) in (("gp3", "iops"), ("io1", "iops"), ("io2", "iops"), ("gp3", "throughput")):
            return f"ebs:{api}-{kind}"
    return None


def _vpc(row: Row) -> str | None:
    """Public IPv4 addresses (Elastic IPs included) and interface endpoints are billed under Amazon VPC."""
    if row.get("Product Family") == "VpcEndpoint":
        if usage(row, "VpcEndpoint-Hours"):
            return "vpce:hour"
        if usage(row, "VpcEndpoint-Bytes"):
            return "vpce:gb"
        return None
    if row.get("Group") != "VPCPublicIPv4Address":
        return None
    if usage(row, "PublicIPv4:InUseAddress"):
        return "eip:in-use-hour"
    if usage(row, "PublicIPv4:IdleAddress"):
        return "eip:idle-hour"
    return None


def _deep_archive(row: Row) -> str | None:
    return "s3:deep-archive" if usage(row, "TimedStorage-GDA-ByteHrs") else None


def _rds(row: Row) -> str | None:
    if row.get("Product Family") == "Database Storage":
        for name, kind in _RDS_STORAGE.items():
            if usage(row, name) and row.get("Deployment Option", "Single-AZ") == "Single-AZ" and (
                row.get("Database Engine", "Any") in (*RDS_ENGINES, "Any")
            ):
                return f"rds:storage:{kind}"
        return None
    if row.get("Product Family") != "Database Instance":
        return None
    engine = RDS_ENGINES.get(row.get("Database Engine", ""))
    deployment = _RDS_DEPLOYMENTS.get(row.get("Deployment Option", ""))
    match = _RDS.match(row.get("usageType") or "")
    if not (engine and deployment and match) or row.get("License Model") != "No license required":
        return None
    return f"rds:{engine}:{deployment}:{row.get('Instance Type') or match.group('class')}"


def _lambda(row: Row) -> str | None:
    if usage(row, "Lambda-GB-Second"):
        return "lambda:gb-second"
    if usage(row, "Lambda-GB-Second-ARM"):
        return "lambda:gb-second-arm"
    if row.get("Group") == "AWS-Lambda-Requests" and usage(row, "Request"):
        return "lambda:request"
    return None


def _dynamodb(row: Row) -> str | None:
    for name, key in (
        ("ReadRequestUnits", "dynamodb:read-request"), ("WriteRequestUnits", "dynamodb:write-request"),
        ("ReadCapacityUnit-Hrs", "dynamodb:rcu-hour"), ("WriteCapacityUnit-Hrs", "dynamodb:wcu-hour"),
    ):
        if usage(row, name):
            return key
    if row.get("Product Family") == "Database Storage" and usage(row, "TimedStorage-ByteHrs"):
        return "dynamodb:storage-gb"
    return None


def _s3(row: Row) -> str | None:
    if row.get("Product Family") != "Storage":
        return None
    for name, storage_class in _S3_CLASSES.items():
        if usage(row, name):
            return f"s3:{storage_class}"
    return None


def _cloudwatch(row: Row) -> str | None:
    if row.get("Group") == "Ingested Logs" and usage(row, "DataProcessing-Bytes"):
        return "logs:ingest-gb"
    group = row.get("Group") or ""
    if group.startswith("Amazon CloudWatch Standard Storage") and usage(row, "TimedStorage-ByteHrs"):
        return "logs:storage-gb"
    return None


def _elb(row: Row) -> str | None:
    kind = _ELB_FAMILIES.get(row.get("Product Family", ""))
    if kind is None:
        return None
    if usage(row, "LoadBalancerUsage"):
        return f"elb:{kind}-hour"
    if kind in ("alb", "nlb") and usage(row, "LCUUsage"):
        return f"elb:{kind}-lcu"
    return None


def _eks(row: Row) -> str | None:
    return "eks:cluster-hour" if usage(row, "AmazonEKS-Hours:perCluster") else None


def _ecs(row: Row) -> str | None:
    for name, key in _FARGATE.items():
        if usage(row, name):
            return key
    return None


def _elasticache(row: Row) -> str | None:
    engine = CACHE_ENGINES.get(row.get("Cache Engine", ""))
    node = row.get("Instance Type", "")
    if row.get("Product Family") != "Cache Instance" or not engine or not node.startswith("cache."):
        return None
    return f"elasticache:{engine}:{node}" if usage(row, f"NodeUsage:{node}") else None


def _opensearch(row: Row) -> str | None:
    family = row.get("Product Family", "")
    if family == "Amazon OpenSearch Service Instance":
        node = row.get("Instance Type", "")
        if node.endswith(".search") and re.fullmatch(_PFX + r"ESInstance:[a-z0-9.]+", row.get("usageType") or ""):
            return f"opensearch:{node}"
        return None
    if family == "Amazon OpenSearch Service Volume":
        match = re.fullmatch(_PFX + r"ES:([A-Za-z0-9]+)-Storage", row.get("usageType") or "")
        kind = _OPENSEARCH_STORAGE.get(match.group(1)) if match else None
        return f"opensearch:storage:{kind}" if kind else None
    return None


def _redshift(row: Row) -> str | None:
    node = row.get("Instance Type", "")
    if row.get("Product Family") == "Compute Instance" and node and usage(row, f"Node:{node}"):
        return f"redshift:{node}"
    return None


def _kms(row: Row) -> str | None:
    return "kms:key-month" if usage(row, "KMS-Keys") else None


def _secrets(row: Row) -> str | None:
    return "secrets:secret-month" if usage(row, "AWSSecretsManager-Secrets") else None


def _kinesis(row: Row) -> str | None:
    if usage(row, "Storage-ShardHour"):
        return "kinesis:shard-hour"
    if usage(row, "OnDemand-StreamHour"):
        return "kinesis:on-demand-stream-hour"
    return None



def _apigateway(row: Row) -> str | None:
    if usage(row, "ApiGatewayRequest"):
        return "apigw:rest-request"
    if usage(row, "ApiGatewayHttpRequest"):
        return "apigw:http-request"
    return None


def _sqs(row: Row) -> str | None:
    if usage(row, "Requests-RBP"):
        return "sqs:standard-request"
    if usage(row, "Requests-FIFO-RBP"):
        return "sqs:fifo-request"
    return None


def _sns(row: Row) -> str | None:
    return "sns:request" if usage(row, "Requests-Tier1") else None


# Offer code -> the matcher for its rows.
MATCHERS: dict[str, Matcher] = {
    "AmazonEC2": _ec2, "AmazonRDS": _rds, "AWSLambda": _lambda,
    "AmazonDynamoDB": _dynamodb, "AmazonS3": _s3, "AmazonCloudWatch": _cloudwatch,
    "AmazonVPC": _vpc, "AmazonS3GlacierDeepArchive": _deep_archive,
    "AWSELB": _elb, "AmazonEKS": _eks, "AmazonECS": _ecs, "AmazonElastiCache": _elasticache,
    "AmazonES": _opensearch, "AmazonRedshift": _redshift, "awskms": _kms,
    "AWSSecretsManager": _secrets, "AmazonKinesis": _kinesis,
    "AmazonApiGateway": _apigateway, "AWSQueueService": _sqs, "AmazonSNS": _sns,
}
OFFERS = tuple(MATCHERS)


@dataclass(frozen=True)
class Spec:
    """Where a key's price lives: its offer, and Query API filters that narrow to it."""

    offer: str
    filters: tuple[tuple[str, str], ...] = ()

    def query(self, region: str) -> dict[str, Any]:
        """Keyword arguments for pricing.get_products."""
        return {
            "ServiceCode": self.offer,
            "Filters": [
                {"Type": "TERM_MATCH", "Field": field, "Value": value}
                for field, value in (("regionCode", region), *self.filters)
            ],
        }


_ENGINE_NAMES = {slug: name for name, slug in RDS_ENGINES.items()}
_DEPLOYMENT_NAMES = {slug: name for name, slug in _RDS_DEPLOYMENTS.items()}


def spec(key: str) -> Spec | None:
    """The catalog entry for a price key, or None for a key nothing prices."""
    kind, _, rest = key.partition(":")
    if kind == "ec2" and rest:
        return Spec("AmazonEC2", (
            ("instanceType", rest), ("operatingSystem", "Linux"), ("tenancy", "Shared"),
            ("preInstalledSw", "NA"), ("capacitystatus", "Used"),
        ))
    if key in ("nat:hour", "nat:gb"):
        return Spec("AmazonEC2", (("productFamily", "NAT Gateway"),))
    if kind == "ebs" and rest in EBS_TYPES:
        return Spec("AmazonEC2", (("productFamily", "Storage"), ("volumeApiName", rest)))
    if key in ("ebs:gp3-iops", "ebs:io1-iops", "ebs:io2-iops"):
        return Spec("AmazonEC2", (("productFamily", "System Operation"), ("volumeApiName", rest.split("-")[0])))
    if key == "ebs:gp3-throughput":
        return Spec("AmazonEC2", (("productFamily", "Provisioned Throughput"), ("volumeApiName", "gp3")))
    if key in ("eip:in-use-hour", "eip:idle-hour"):
        return Spec("AmazonVPC", (("group", "VPCPublicIPv4Address"),))
    if kind == "rds" and rest.startswith("storage:"):
        if rest.split(":", 1)[1] in _RDS_STORAGE.values():
            return Spec("AmazonRDS", (("productFamily", "Database Storage"), ("deploymentOption", "Single-AZ")))
        return None
    if kind == "rds":
        parts = rest.split(":")
        if len(parts) == 3 and parts[0] in _ENGINE_NAMES and parts[1] in _DEPLOYMENT_NAMES:
            return Spec("AmazonRDS", (
                ("instanceType", parts[2]), ("databaseEngine", _ENGINE_NAMES[parts[0]]),
                ("deploymentOption", _DEPLOYMENT_NAMES[parts[1]]),
            ))
        return None
    if kind == "lambda" and rest in ("gb-second", "gb-second-arm", "request"):
        return Spec("AWSLambda")
    if kind == "dynamodb" and rest in ("read-request", "write-request", "rcu-hour", "wcu-hour", "storage-gb"):
        return Spec("AmazonDynamoDB")
    if key == "s3:deep-archive":
        return Spec("AmazonS3GlacierDeepArchive")
    if kind == "s3" and rest in _S3_CLASSES.values():
        return Spec("AmazonS3", (("productFamily", "Storage"),))
    if key == "logs:ingest-gb":
        return Spec("AmazonCloudWatch", (("group", "Ingested Logs"),))
    if key == "logs:storage-gb":
        return Spec("AmazonCloudWatch")
    if key in ("vpce:hour", "vpce:gb"):
        return Spec("AmazonVPC", (("productFamily", "VpcEndpoint"),))
    if kind == "elb":
        lb, _, what = rest.partition("-")
        family = {v: k for k, v in _ELB_FAMILIES.items()}.get(lb)
        if family and (what == "hour" or (what == "lcu" and lb in ("alb", "nlb"))):
            return Spec("AWSELB", (("productFamily", family),))
        return None
    if key == "eks:cluster-hour":
        return Spec("AmazonEKS")
    if key in _FARGATE.values():
        return Spec("AmazonECS")
    if kind == "elasticache":
        engine, _, node = rest.partition(":")
        names = {v: k for k, v in CACHE_ENGINES.items()}
        if engine in names and node.startswith("cache."):
            return Spec("AmazonElastiCache", (("instanceType", node), ("cacheEngine", names[engine])))
        return None
    if kind == "opensearch" and rest.startswith("storage:"):
        if rest.split(":", 1)[1] in _OPENSEARCH_STORAGE.values():
            return Spec("AmazonES", (("productFamily", "Amazon OpenSearch Service Volume"),))
        return None
    if kind == "opensearch" and rest.endswith(".search"):
        return Spec("AmazonES", (("instanceType", rest),))
    if kind == "redshift" and rest:
        return Spec("AmazonRedshift", (("instanceType", rest),))
    if key == "kms:key-month":
        return Spec("awskms")
    if key == "secrets:secret-month":
        return Spec("AWSSecretsManager")
    if key in ("kinesis:shard-hour", "kinesis:on-demand-stream-hour"):
        return Spec("AmazonKinesis")
    if key in ("apigw:rest-request", "apigw:http-request"):
        return Spec("AmazonApiGateway")
    if key in ("sqs:standard-request", "sqs:fifo-request"):
        return Spec("AWSQueueService")
    if key == "sns:request":
        return Spec("AmazonSNS")
    return None


def offer_for(key: str) -> str | None:
    found = spec(key)
    return found.offer if found else None


# Query API attribute names -> the bulk CSV column names the matchers read.
_API_COLUMNS = {
    "instanceType": "Instance Type", "operatingSystem": "Operating System", "tenancy": "Tenancy",
    "preInstalledSw": "Pre Installed S/W", "licenseModel": "License Model",
    "capacitystatus": "CapacityStatus", "usagetype": "usageType", "operation": "operation",
    "volumeApiName": "Volume API Name", "databaseEngine": "Database Engine",
    "deploymentOption": "Deployment Option", "group": "Group", "cacheEngine": "Cache Engine",
}


def api_rows(price_item: str | dict) -> Iterator[Row]:
    """Bulk-CSV-shaped rows for one Query API price list item (JSON text or parsed).

    One row per on-demand price dimension, with the product's attributes under their CSV
    column names, so the offer's matcher reads them as it reads a bulk row.
    """
    item = json.loads(price_item) if isinstance(price_item, str) else price_item
    product = item.get("product") or {}
    attributes = product.get("attributes") or {}
    base: Row = {str(k): str(v) for k, v in attributes.items()}
    base.update({_API_COLUMNS[k]: str(v) for k, v in attributes.items() if k in _API_COLUMNS})
    base["Product Family"] = str(product.get("productFamily") or "")
    for term in ((item.get("terms") or {}).get("OnDemand") or {}).values():
        for dimension in (term.get("priceDimensions") or {}).values():
            usd = (dimension.get("pricePerUnit") or {}).get("USD")
            if usd is None:
                continue
            yield {
                **base, "TermType": "OnDemand", "Currency": "USD", "PricePerUnit": str(usd),
                "Unit": str(dimension.get("unit") or ""), "StartingRange": str(dimension.get("beginRange") or "0"),
            }


def publication_date(price_item: str | dict) -> str | None:
    """The YYYY-MM-DD publication date of a Query API price list item."""
    item = json.loads(price_item) if isinstance(price_item, str) else price_item
    date = str(item.get("publicationDate") or "")[:10]
    return date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else None
