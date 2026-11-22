"""A persistent SQLite cache of fetched AWS prices, with a time to live.

Stored at $AWS_ARCH_AGENT_CACHE_DIR/pricing.sqlite3, else
$XDG_CACHE_HOME/aws-arch-agent/pricing.sqlite3, else ~/.cache/aws-arch-agent/pricing.sqlite3.

Two tables:
* prices: one row per (region, price key). A row with no price records that the source
  has no such SKU, so a miss is not looked up again within the TTL.
* offers: when a region's bulk offer file was last read. Every key that file prices is
  stored in one pass, so a key it lacks is a miss without downloading the file again.

The database runs in WAL mode and every write is one transaction, so several scans can
read and write it at once. A cache that cannot be opened or written is no cache: errors
are swallowed and the price is fetched again.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence

DEFAULT_TTL_HOURS = 24.0
FILE_NAME = "pricing.sqlite3"

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS prices (
        region TEXT NOT NULL, price_key TEXT NOT NULL, usd REAL, unit TEXT,
        offer_code TEXT, published_date TEXT, fetched_at REAL NOT NULL, source TEXT NOT NULL,
        PRIMARY KEY (region, price_key))""",
    """CREATE TABLE IF NOT EXISTS offers (
        region TEXT NOT NULL, offer_code TEXT NOT NULL, fetched_at REAL NOT NULL,
        published_date TEXT, PRIMARY KEY (region, offer_code))""",
)


def default_path(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    if env.get("AWS_ARCH_AGENT_CACHE_DIR"):
        return Path(env["AWS_ARCH_AGENT_CACHE_DIR"]).expanduser() / FILE_NAME
    base = Path(env["XDG_CACHE_HOME"]).expanduser() if env.get("XDG_CACHE_HOME") else Path.home() / ".cache"
    return base / "aws-arch-agent" / FILE_NAME


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Entry:
    """One cached row. usd is None when the source has no such SKU."""

    usd: float | None
    unit: str
    offer_code: str
    published_date: str | None
    fetched_at: float
    source: str
    stale: bool


class PriceCache:
    def __init__(
        self, path: Path | None = None, ttl_hours: float = DEFAULT_TTL_HOURS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path) if path is not None else default_path()
        self.ttl_seconds = max(0.0, float(ttl_hours)) * 3600
        self._clock = clock
        self._ready = False

    def _connect(self) -> sqlite3.Connection:
        if not self._ready:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=30)
        try:
            self._initialise(conn)
        except BaseException:
            conn.close()
            raise
        return conn

    def _initialise(self, conn: sqlite3.Connection) -> None:
        if not self._ready:
            # Switching to WAL needs a moment alone with the file: another process creating
            # the cache at the same time makes it fail at once ("database is locked"), so retry.
            for attempt in range(20):
                try:
                    conn.execute("PRAGMA journal_mode=WAL")
                    with conn:
                        for statement in _SCHEMA:
                            conn.execute(statement)
                    break
                except sqlite3.OperationalError:
                    if attempt == 19:
                        raise
                    time.sleep(0.05)
            self._ready = True

    def _fresh(self, fetched_at: float) -> bool:
        return self._clock() - fetched_at < self.ttl_seconds

    def get(self, region: str, key: str, allow_stale: bool = False) -> Entry | None:
        """The cached row, or None. An expired row is returned only with allow_stale."""
        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT usd, unit, offer_code, published_date, fetched_at, source FROM prices "
                    "WHERE region = ? AND price_key = ?", (region, key),
                ).fetchone()
        except (sqlite3.Error, OSError):
            return None
        if row is None:
            return None
        fresh = self._fresh(row[4])
        if not fresh and not allow_stale:
            return None
        return Entry(row[0], row[1] or "", row[2] or "", row[3], row[4], row[5], stale=not fresh)

    def put_many(
        self, region: str, offer: str, prices: Mapping[str, Sequence], published: str | None,
        source: str, missing: Sequence[str] = (),
    ) -> None:
        """Store key -> (usd, unit) prices, and `missing` keys as known misses, in one transaction."""
        now = self._clock()
        rows: list[tuple[str, str, float | None, str | None, str, str | None, float, str]] = [
            (region, key, float(p[0]), str(p[1]), offer, published, now, source) for key, p in prices.items()
        ]
        rows += [(region, key, None, None, offer, published, now, source) for key in missing if key not in prices]
        try:
            with closing(self._connect()) as conn, conn:
                conn.executemany("INSERT OR REPLACE INTO prices VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        except (sqlite3.Error, OSError):
            pass

    def mark_offer(self, region: str, offer: str, published: str | None) -> None:
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute("INSERT OR REPLACE INTO offers VALUES (?, ?, ?, ?)", (region, offer, self._clock(), published))
        except (sqlite3.Error, OSError):
            pass

    def offer_fresh(self, region: str, offer: str) -> bool:
        """Whether the region's bulk offer file was read within the TTL."""
        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT fetched_at FROM offers WHERE region = ? AND offer_code = ?", (region, offer),
                ).fetchone()
        except (sqlite3.Error, OSError):
            return False
        return row is not None and self._fresh(row[0])

    def invalidate(self, region: str | None = None) -> None:
        """Forget cached prices (all, or one region's): --refresh-prices."""
        where, args = ("WHERE region = ?", (region,)) if region else ("", ())
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(f"DELETE FROM prices {where}", args)
                conn.execute(f"DELETE FROM offers {where}", args)
        except (sqlite3.Error, OSError):
            pass

    def keys(self, region: str) -> Iterator[str]:
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute("SELECT price_key FROM prices WHERE region = ? ORDER BY price_key", (region,)).fetchall()
        except (sqlite3.Error, OSError):
            return iter(())
        return iter(r[0] for r in rows)
