#!/usr/bin/env python3
"""Check that every page in report/doc_topics.py still exists.

Run by hand after editing the map, or now and then because AWS moves pages; a scan never
calls the network.

    python scripts/check_doc_links.py      # after pip install -e . (or PYTHONPATH=src)

docs.aws.amazon.com answers a missing page with a redirect to the guide's start page, so a
page passes only when it answers 200 without a redirect. An #anchor must appear as an id on
the page. Exits 1 and lists the broken URLs when any fail.
"""
from __future__ import annotations

import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from aws_arch_agent.report.doc_topics import TOPICS

BASE = "https://docs.aws.amazon.com"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch(path: str) -> tuple[bool | None, str]:
    page, _, anchor = path.partition("#")
    request = urllib.request.Request(BASE + page, headers={"User-Agent": "aws-arch-agent-doc-check"})
    try:
        with _OPENER.open(request, timeout=20) as response:
            if response.status != 200:
                return False, f"status {response.status}"
            body = response.read().decode("utf-8", "replace") if anchor else ""
            if anchor and not re.search(rf"""\b(?:id|name)=["']{re.escape(anchor)}["']""", body):
                return False, f"no #{anchor} on the page"
            return True, ""
    except urllib.error.HTTPError as exc:
        if exc.code == 429 or exc.code >= 500:
            return None, f"status {exc.code}"  # throttled or server error: retry
        if 300 <= exc.code < 500:
            return False, f"status {exc.code} {exc.headers.get('Location') or ''}".strip()
        return None, f"status {exc.code}"
    except OSError as exc:
        return None, str(exc)


def check(path: str) -> tuple[str, bool, str]:
    reason = ""
    for attempt in range(4):
        ok, reason = _fetch(path)
        if ok is not None:
            return path, ok, reason
        time.sleep(2 * (attempt + 1))  # throttled or timed out: retry before failing
    return path, False, reason


def main() -> int:
    paths = sorted({p for _, svc, _, wa in TOPICS.values() for p in (svc, wa)})
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(check, paths))
    broken = [(p, why) for p, ok, why in results if not ok]
    for path, why in broken:
        print(f"BROKEN {BASE}{path}: {why}")
    print(f"{len(paths) - len(broken)} of {len(paths)} pages ok")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
