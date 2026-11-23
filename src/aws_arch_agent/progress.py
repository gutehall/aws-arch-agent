"""Progress lines for a long scan.

Library calls stay quiet until a caller installs a reporter. The CLI installs one
that prints a line when the step changes, and prints the step again, with its latest
count, when no line has been printed for a while.
"""
from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from rich.console import Console

Reporter = Callable[[str], None]

_reporter: ContextVar[Reporter | None] = ContextVar("aws_arch_agent_progress", default=None)

# A single ripgrep or cdk synth can sit still for well over this. Repeat the
# current step so a log does not look frozen.
IDLE_AFTER_S = 15.0
# "Checking rules (12/348, typescript)" is the step "Checking rules" with a count.
_COUNT = re.compile(r"\s*\([^()]*\)$")


def step_title(message: str) -> str:
    """The step a progress line names, without its trailing (count)."""
    return _COUNT.sub("", message)


def report(message: str) -> None:
    """Send one progress line to the active reporter. Quiet when none is set."""
    reporter = _reporter.get()
    if reporter is not None:
        reporter(message)


@contextmanager
def use_progress(reporter: Reporter | None) -> Iterator[None]:
    """Send report() calls to reporter until the block exits."""
    token = _reporter.set(reporter)
    try:
        yield
    finally:
        _reporter.reset(token)


class _StepLog:
    """Print a line when the step changes; repeat the latest line while none is printed.

    An update within the same step (a new count) is kept, not printed, and the repeat
    shows it."""

    def __init__(self, write: Reporter, *, idle_after: float) -> None:
        self._write = write
        self._idle_after = idle_after
        self._lock = threading.Lock()
        self._message = ""
        self._last = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> _StepLog:
        self._thread = threading.Thread(target=self._beat, name="scan-progress", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __call__(self, message: str) -> None:
        with self._lock:
            new_step = step_title(message) != step_title(self._message)
            self._message = message
            if new_step:
                self._last = time.monotonic()
        if new_step:
            self._write(message)

    def _beat(self) -> None:
        while not self._stop.wait(self._idle_after):
            with self._lock:
                if not self._message or time.monotonic() - self._last < self._idle_after:
                    continue
                message = f"{self._message} (still running)"
                self._last = time.monotonic()
            self._write(message)


class ScanProgress:
    """Print scan steps to a console, and repeat a step that stays quiet."""

    def __init__(self, console: Console, *, idle_after: float = IDLE_AFTER_S) -> None:
        self._console = console
        self._log = _StepLog(self._write, idle_after=idle_after)

    def __enter__(self) -> ScanProgress:
        self._log.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self._log.__exit__(*exc)

    def __call__(self, message: str) -> None:
        self._log(message)

    def _write(self, message: str) -> None:
        self._console.print(message, markup=False, highlight=False)
