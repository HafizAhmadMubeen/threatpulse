"""The FIM loop. It has no Windows-only code, so it can be tested with a fake source.

A notification only means "look now". The rescan and comparison are the same whether
a notification or the 60-second backup triggered them, so there is one path to test.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from baseline import Change, Snapshot, compare

FULL_COMPARE_SECONDS = 60


class Source(Protocol):
    def scan(self) -> Snapshot: ...

    def wait(self, timeout_seconds: float) -> bool:
        """Block until a watched item may have changed (True) or until the timeout or a stop."""
        ...


@dataclass
class Stats:
    changes: int = 0
    notifications: int = 0
    notifications_no_change: int = 0
    full_compares: int = 0


class Monitor:
    """Reports each state once.

    `last_seen` starts as the baseline, so the first check reports everything that
    differs from it, including changes made while FIM was stopped. Afterwards it follows
    the current state, so a change that is still there is not reported every 60 seconds.
    The baseline itself changes only when a change is approved (Phase 4).
    """

    def __init__(self, baseline: Snapshot, emit: Callable[[Change], None]):
        self._last_seen = dict(baseline)
        self._emit = emit
        self.stats = Stats()

    def check(self, current: Snapshot, notified: bool) -> None:
        changes = compare(self._last_seen, current)
        self._last_seen = current
        for change in changes:
            self._emit(change)
        self.stats.changes += len(changes)
        if notified:
            self.stats.notifications += 1
            if not changes:
                # The change may have been undone before the rescan. Sysmon IDs 12 and
                # 13 still have it. Other files in the hosts folder also land here.
                self.stats.notifications_no_change += 1
        else:
            self.stats.full_compares += 1


def run(
    monitor: Monitor,
    source: Source,
    should_stop: Callable[[], bool],
    clock: Callable[[], float] = time.monotonic,
    interval: float = FULL_COMPARE_SECONDS,
) -> None:
    monitor.check(source.scan(), notified=False)
    next_full = clock() + interval

    while not should_stop():
        notified = source.wait(max(0.0, next_full - clock()))
        if should_stop():
            return
        # Every rescan compares everything, so any rescan restarts the 60 seconds.
        monitor.check(source.scan(), notified)
        next_full = clock() + interval
