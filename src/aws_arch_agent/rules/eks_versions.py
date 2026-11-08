"""End of standard support for EKS Kubernetes versions (CF-EKS-004).

Dates live in data/eks_versions.json. Update a date or add a version with a one-line change,
then set `_as_of`. tests/test_container_checks.py fails when `_as_of` is over 6 months old.
"""
from __future__ import annotations

import json
from datetime import date
from functools import lru_cache
from pathlib import Path

DATA_PATH = Path(__file__).with_name("data") / "eks_versions.json"


@lru_cache(maxsize=1)
def _data() -> dict:
    data: dict = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return data


def as_of() -> date:
    return date.fromisoformat(_data()["_as_of"])


def _support_ends() -> dict[int, date]:
    """Kubernetes 1.x minor -> last day of EKS standard support."""
    return {
        int(version.split(".")[1]): date.fromisoformat(ends)
        for version, ends in _data()["standard_support_ends"].items()
    }


def past_standard_support(minor: int, today: date | None = None) -> tuple[bool, date | None]:
    """(past standard support, its end date when listed).

    A minor newer than the list is not judged. One older than the list is past support with
    no date to give: EKS retires versions in order, so it ended before the oldest listed.
    """
    ends = _support_ends()
    if minor < min(ends):
        return True, None
    end = ends.get(minor)
    if end is None:
        return False, None
    return end < (today or date.today()), end
