"""Lambda managed runtimes and their deprecation dates (CF-LAM-003, SEC-068).

Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
Update a date or add a runtime with a one-line change, then set LAST_CHECKED.
tests/test_lambda_runtime_checks.py fails when LAST_CHECKED is over 6 months old.
"""
from __future__ import annotations

import re
from datetime import date, timedelta

LAST_CHECKED = date(2026, 11, 5)

# Runtime identifier -> deprecation date, or None when none is scheduled (incl. preview).
DEPRECATION: dict[str, date | None] = {
    # Supported
    "nodejs26.x": None,  # preview
    "nodejs24.x": date(2028, 4, 30),
    "nodejs22.x": date(2027, 4, 30),
    "python3.15": None,  # preview
    "python3.14": date(2029, 6, 30),
    "python3.13": date(2029, 6, 30),
    "python3.12": date(2028, 10, 31),
    "python3.11": date(2027, 6, 30),
    "java25": date(2029, 6, 30),
    "java21": date(2029, 6, 30),
    "java17.al2023": date(2029, 6, 30),
    "java11.al2023": date(2029, 6, 30),
    "java8.al2023": date(2029, 6, 30),
    "java17": date(2027, 6, 30),
    "java11": date(2027, 6, 30),
    "java8.al2": date(2027, 6, 30),
    "dotnet10": date(2028, 11, 14),
    "dotnet9": date(2026, 11, 10),
    "dotnet8": date(2026, 11, 10),
    "ruby4.0": date(2029, 3, 31),
    "ruby3.4": date(2028, 3, 31),
    "ruby3.3": date(2027, 3, 31),
    "provided.al2023": date(2029, 6, 30),
    # Deprecated
    "python3.10": date(2026, 10, 31),
    "provided.al2": date(2026, 7, 31),
    "nodejs20.x": date(2026, 4, 30),
    "ruby3.2": date(2026, 3, 31),
    "python3.9": date(2025, 12, 15),
    "nodejs18.x": date(2025, 9, 1),
    "dotnet6": date(2024, 12, 20),
    "python3.8": date(2024, 10, 14),
    "nodejs16.x": date(2024, 6, 12),
    "dotnet7": date(2024, 5, 14),
    "java8": date(2024, 1, 8),
    "go1.x": date(2024, 1, 8),
    "provided": date(2024, 1, 8),
    "ruby2.7": date(2023, 12, 7),
    "nodejs14.x": date(2023, 12, 4),
    "python3.7": date(2023, 12, 4),
    "dotnetcore3.1": date(2023, 4, 3),
    "nodejs12.x": date(2023, 3, 31),
    "python3.6": date(2022, 7, 18),
    "dotnet5.0": date(2022, 5, 10),
    "dotnetcore2.1": date(2022, 1, 5),
    "nodejs10.x": date(2021, 7, 30),
    "ruby2.5": date(2021, 7, 30),
    "python2.7": date(2021, 7, 15),
    "nodejs8.10": date(2020, 3, 6),
    "nodejs4.3": date(2020, 3, 5),
    "nodejs4.3-edge": date(2020, 3, 5),
    "nodejs6.10": date(2019, 8, 12),
    "dotnetcore1.0": date(2019, 6, 27),
    "dotnetcore2.0": date(2019, 5, 30),
    "nodejs": date(2016, 8, 30),
}

# Language prefix -> the current generally available runtime to move to.
CURRENT: tuple[tuple[str, str], ...] = (
    ("nodejs", "nodejs24.x"),
    ("python", "python3.14"),
    ("java", "java25"),
    ("dotnet", "dotnet10"),
    ("ruby", "ruby4.0"),
    ("provided", "provided.al2023"),
    ("go", "provided.al2023"),  # Go runs on the OS-only runtime
)

SOON = timedelta(days=183)  # "within 6 months of deprecation"


def replacement(runtime: str) -> str | None:
    return next((current for prefix, current in CURRENT if runtime.startswith(prefix)), None)


def status(runtime: str, today: date | None = None) -> tuple[str, date] | None:
    """("deprecated" | "soon", deprecation date) for a known runtime, else None.

    An unknown identifier gives None: it may be newer than this list.
    """
    deprecated = DEPRECATION.get(runtime)
    if deprecated is None:
        return None
    today = today or date.today()
    if deprecated <= today:
        return "deprecated", deprecated
    if deprecated - today <= SOON:
        return "soon", deprecated
    return None


def cdk_runtime_id(constant: str) -> str | None:
    """CDK Runtime constant name -> runtime identifier ("NODEJS_18_X" -> "nodejs18.x")."""
    patterns = (
        (r"NODEJS_(\d+)_X", lambda m: f"nodejs{m[1]}.x"),
        (r"NODEJS_(\d+)_(\d+)", lambda m: f"nodejs{m[1]}.{m[2]}"),
        (r"PYTHON_(\d+)_(\d+)", lambda m: f"python{m[1]}.{m[2]}"),
        (r"JAVA_8_CORRETTO", lambda m: "java8.al2"),
        (r"JAVA_(\d+)", lambda m: f"java{m[1]}"),
        (r"DOTNET_CORE_(\d+)_(\d+)", lambda m: f"dotnetcore{m[1]}.{m[2]}"),
        (r"DOTNET_(\d+)", lambda m: f"dotnet{m[1]}"),
        (r"RUBY_(\d+)_(\d+)", lambda m: f"ruby{m[1]}.{m[2]}"),
        (r"GO_1_X", lambda m: "go1.x"),
        (r"PROVIDED_AL2023", lambda m: "provided.al2023"),
        (r"PROVIDED_AL2", lambda m: "provided.al2"),
        (r"PROVIDED", lambda m: "provided"),
    )
    for pattern, build in patterns:
        match = re.fullmatch(pattern, constant)
        if match:
            return build(match)
    return None
