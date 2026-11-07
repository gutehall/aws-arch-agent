"""Which AWS region a stack's cost estimates are priced in.

A stack is one CloudFormation template (cdk synth output included) or one Terraform root
module. Its price region is, in order:

1. `--region` or config `region`: set by hand, it applies to every stack.
2. the region the stack's own code deploys to:
   - CDK: the stack's `environment` in cdk.out/manifest.json (`env: { region }` in the app)
   - Terraform: the default `provider "aws"` region, as a literal, as `var.<name>` with a
     default, or from the --tf-plan
   - otherwise availability zones written in the template (`eu-north-1a`), when they all
     name one region
3. `AWS_REGION`, then `AWS_DEFAULT_REGION`, from the environment the scan runs in.
4. us-east-1.

Nothing here calls AWS: a scan stays offline.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aws_arch_agent.pricing import DEFAULT_REGION, current_region, snapshot_date, use_region
from aws_arch_agent.rules.resource_model import Resource

REGION = re.compile(r"[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}")
_AZ = re.compile(rf"({REGION.pattern})[a-z]")
_VAR = re.compile(r"^\$\{var\.([A-Za-z0-9_-]+)\}$")


@dataclass(frozen=True)
class Resolved:
    region: str
    source: str  # what decided it, shown in the report


_scanning = False  # detection runs only inside use_regions; outside, use_region decides
_override: Resolved | None = None
_fallback = Resolved(DEFAULT_REGION, "default")
_known: dict[str, Resolved] = {}  # stack path -> region learned before its checks run (--tf-plan)
_used: dict[str, Resolved] = {}  # stack path -> region its estimates used, in this scan


def _fallback_from(env: Mapping[str, str]) -> Resolved:
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        value = (env.get(name) or "").strip().lower()
        if REGION.fullmatch(value):
            return Resolved(value, name)
    return Resolved(DEFAULT_REGION, "default")


@contextmanager
def use_regions(override: str | None, env: Mapping[str, str] | None = None) -> Iterator[None]:
    """Resolve price regions for a scan. override is --region / config region (None: detect)."""
    global _scanning, _override, _fallback, _known, _used
    previous = (_scanning, _override, _fallback, _known, _used)
    _scanning = True
    _override = Resolved(override, "--region / config") if override else None
    _fallback = _fallback_from(os.environ if env is None else env)
    _known, _used = {}, {}
    try:
        with use_region(_override.region if _override else _fallback.region):
            yield
    finally:
        _scanning, _override, _fallback, _known, _used = previous


def remember(stack: Path, region: str, source: str) -> None:
    """Record a region found before the stack's checks run (e.g. from a Terraform plan)."""
    if REGION.fullmatch(region):
        _known[_key(stack)] = Resolved(region, source)


def _key(stack: Path) -> str:
    return str(Path(stack).resolve())


def _from_cdk_manifest(template_path: Path) -> str | None:
    """The region of a cdk.out stack from manifest.json, or None (env-agnostic stack)."""
    manifest = template_path.parent / "manifest.json"
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    artifacts = doc.get("artifacts") if isinstance(doc, dict) else None
    for artifact in (artifacts or {}).values():
        if not isinstance(artifact, dict) or artifact.get("type") != "aws:cloudformation:stack":
            continue
        props = artifact.get("properties") or {}
        if props.get("templateFile") != template_path.name:
            continue
        env = artifact.get("environment")
        region = env.rsplit("/", 1)[-1] if isinstance(env, str) else ""
        return region if REGION.fullmatch(region) else None  # "unknown-region" is agnostic
    return None


def terraform_provider_region(module_dir: Path) -> str | None:
    """The default (no alias) aws provider's region in a root module, or None if unreadable."""
    from aws_arch_agent.rules import terraform_model as tf  # heavy import, Terraform only

    defaults = {v.name: v.default for v in tf.variables_from_terraform(module_dir)}
    for path in tf._module_files(module_dir):
        try:
            doc, _text, _is_json, normalize = tf._load_tf(path)
        except Exception:  # noqa: BLE001 - resources_from_terraform already warned
            continue
        for provider_map in tf._iter_type_maps(doc.get("provider")):
            for raw_name, body in provider_map.items():
                if tf._unquote_key(raw_name) != "aws":
                    continue
                for item in tf._iter_type_maps(body):
                    if item.get("alias") is not None:
                        continue
                    raw = item.get("region")
                    value = normalize(item).get("region")  # a literal, unquoted
                    match = _VAR.match(raw.strip()) if isinstance(raw, str) else None
                    if match:
                        value = defaults.get(match.group(1))
                    if isinstance(value, str) and REGION.fullmatch(value.strip()):
                        return value.strip()
                    return None  # the default provider sets no readable region
    return None


def terraform_plan_region(plan: Path) -> str | None:
    """The default aws provider's region from `terraform show -json` output, or None."""
    try:
        doc = json.loads(plan.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    config = ((doc.get("configuration") or {}).get("provider_config") or {}).get("aws") or {}
    region = (config.get("expressions") or {}).get("region") or {}
    value = region.get("constant_value")
    if value is None:
        for ref in region.get("references") or []:
            if isinstance(ref, str) and ref.startswith("var."):
                value = ((doc.get("variables") or {}).get(ref[4:]) or {}).get("value")
                break
    return value if isinstance(value, str) and REGION.fullmatch(value) else None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _from_availability_zones(resources: Iterable[Resource]) -> str | None:
    found = set()
    for res in resources:
        for text in _strings(res.properties):
            match = _AZ.fullmatch(text)
            if match:
                found.add(match.group(1))
    return found.pop() if len(found) == 1 else None


def resolve(stack: Path, resources: Iterable[Resource]) -> Resolved:
    """The region a stack is priced in (see the module docstring for the order)."""
    if not _scanning:
        return Resolved(current_region(), "use_region")
    if _override is not None:
        return _override
    known = _known.get(_key(stack))
    if known is not None:
        return known
    stack = Path(stack)
    if stack.is_dir():
        region = terraform_provider_region(stack)
        if region:
            return Resolved(region, "Terraform provider")
    elif "cdk.out" in stack.parts or (stack.parent / "manifest.json").is_file():
        region = _from_cdk_manifest(stack)
        if region:
            return Resolved(region, "CDK stack env")
    region = _from_availability_zones(resources)
    if region:
        return Resolved(region, "availability zones")
    return _fallback


@contextmanager
def for_stack(stack: Path, resources: Iterable[Resource]) -> Iterator[Resolved]:
    """Price this stack's estimates in its region while its checks run."""
    resolved = resolve(stack, list(resources))
    _used[_key(stack)] = resolved
    with use_region(resolved.region):
        yield resolved


def used() -> dict[str, Resolved]:
    """Stack path -> the region its estimates used, for stacks seen in this scan."""
    return dict(_used)


def note() -> dict[str, Any]:
    """What the report says about prices: one entry per region the scan priced in.

    `region` and `snapshot_date` are kept for one-region reports and JSON readers; with
    several regions `region` lists them, comma-separated.
    """
    by_region: dict[str, set[str]] = {}
    for resolved in _used.values() or [_override or _fallback]:
        by_region.setdefault(resolved.region, set()).add(resolved.source)
    entries = [
        {"region": region, "source": ", ".join(sorted(sources)), "snapshot_date": snapshot_date(region)}
        for region, sources in sorted(by_region.items())
    ]
    dates = [e["snapshot_date"] for e in entries if e["snapshot_date"]]
    return {
        "region": ", ".join(str(e["region"]) for e in entries),
        "snapshot_date": max(dates) if len(dates) == len(entries) else None,
        "regions": entries,
    }
