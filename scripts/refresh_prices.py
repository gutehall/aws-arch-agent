#!/usr/bin/env python3
"""Rebuild src/aws_arch_agent/pricing/prices.json.gz from the AWS Price List bulk API.

Run by hand when prices should be refreshed; a scan never calls the network.

    python scripts/refresh_prices.py                       # default regions
    python scripts/refresh_prices.py --regions us-east-1 eu-north-1
    python scripts/refresh_prices.py --cache-dir /tmp/offers   # keep the CSVs to rebuild offline

The EC2 offer is about 300 MB per region; it is streamed, not held in memory. The same
offer files always give the same output file.
"""
from __future__ import annotations

import argparse
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Iterable, Iterator

import requests

from aws_arch_agent.pricing import DATA_PATH
from aws_arch_agent.pricing.build import DEFAULT_REGIONS, OFFER_URL, OFFERS, build, write


def _download(url: str, target: Path) -> None:
    tmp = target.with_suffix(".part")
    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
    tmp.replace(target)


def _stream(url: str) -> Iterator[str]:
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()
    with resp:
        for line in resp.iter_lines(decode_unicode=True):
            if line is not None:
                yield line


def _lines(offer: str, region: str, cache_dir: Path | None, stack: ExitStack) -> Iterable[str]:
    url = OFFER_URL.format(offer=offer, region=region)
    if cache_dir is None:
        return _stream(url)
    target = cache_dir / region / f"{offer}.csv"
    if not target.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        print(f"download {url}", file=sys.stderr)
        _download(url, target)
    return stack.enter_context(target.open(encoding="utf-8", newline=""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--regions", nargs="+", default=list(DEFAULT_REGIONS))
    parser.add_argument("--out", type=Path, default=DATA_PATH)
    parser.add_argument("--cache-dir", type=Path, default=None,
                        help="keep downloaded offer CSVs here and reuse them")
    args = parser.parse_args(argv)
    with ExitStack() as stack:
        offers = {
            region: {offer: _lines(offer, region, args.cache_dir, stack) for offer in OFFERS}
            for region in args.regions
        }
        data = build(offers)
    write(data, args.out)
    for region, body in data["regions"].items():
        print(f"{region}: {len(body['prices'])} prices", file=sys.stderr)
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
