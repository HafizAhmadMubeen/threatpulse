"""What the pipeline remembers while it replays a session, all of it causal.

Every query is "as of now": the structures only hold events already seen, so a decision
never uses something that had not happened yet at the time it was made.
"""

import bisect
from dataclasses import dataclass, field

from detection.timeline import parse_ts
from triage.features import FIM_LINK_SECONDS, FIM_SKEW_SECONDS, WRITE_EVENTS, normalise_name

MAX_DEPTH = 16


def when(event: dict) -> float:
    return parse_ts(event["ts"]).timestamp()


def item_of(target: dict) -> str:
    """The registry key or file a change or write is about, as one comparable string."""
    return normalise_name(target.get("registry_key") or target.get("path") or "")


@dataclass(eq=False)
class Proc:
    pid: int
    image: str
    parent: "Proc | None" = None
    children: list = field(default_factory=list)
    alive: bool = True
    microsoft_root: bool | None = None
    events: list = field(default_factory=list)

    def chain(self) -> list["Proc"]:
        """This process, then its parents, nearest first."""
        found, proc = [], self
        while proc is not None and proc not in found and len(found) < MAX_DEPTH:
            found.append(proc)
            proc = proc.parent
        return found

    def root(self) -> "Proc":
        return self.chain()[-1]

    def tree_events(self) -> list[dict]:
        """Every event of the tree this process is in, so far."""
        collected, stack, seen = [], [self.root()], set()
        while stack:
            proc = stack.pop()
            if id(proc) in seen:
                continue
            seen.add(id(proc))
            collected += proc.events
            stack += proc.children
        return sorted(collected, key=lambda e: (e["ts"], e["event_id"]))


class ProcessTable:
    def __init__(self):
        self.by_pid: dict[int, Proc] = {}

    def observe(self, event: dict) -> Proc | None:
        pid = event["pid"]
        if pid <= 0:
            return None  # FIM: the writer is unknown
        info = event["process"]
        proc = self.by_pid.get(pid)
        if event["event_type"] == "process_start" or proc is None:
            # A started process is always new, even if the pid was used before.
            proc = Proc(pid=pid, image=info["image"])
            parent = self.by_pid.get(event["ppid"]) if event["ppid"] > 0 else None
            if parent is not None and parent is not proc:
                proc.parent = parent
                parent.children.append(proc)
            self.by_pid[pid] = proc
        if isinstance(info.get("microsoft_root"), bool):
            proc.microsoft_root = info["microsoft_root"]
        if event["event_type"] == "process_stop":
            proc.alive = False
        proc.events.append(event)
        return proc


class WriteIndex:
    """Who wrote each registry key or file, by time. FIM does not say who made a change,
    so the nearest write to the same item is the only link there is. The window is the
    one `triage/features.py` uses: up to 120 s before the change, or 0.5 s after it (FIM
    and Sysmon use different clocks)."""

    def __init__(self):
        self._times: dict[str, list[float]] = {}
        self._procs: dict[str, list[Proc]] = {}

    def observe(self, event: dict, proc: Proc | None) -> None:
        if proc is None or event["event_type"] not in WRITE_EVENTS:
            return
        name = item_of(event["target"])
        if name:
            self._times.setdefault(name, []).append(when(event))
            self._procs.setdefault(name, []).append(proc)

    def writer_of(self, item: str, change_time: float) -> Proc | None:
        times = self._times.get(item)
        if not times:
            return None
        after = bisect.bisect_right(times, change_time)
        near = [
            index for index in (after - 1, after)
            if 0 <= index < len(times) and -FIM_SKEW_SECONDS <= change_time - times[index] <= FIM_LINK_SECONDS
        ]
        if not near:
            return None
        return self._procs[item][min(near, key=lambda index: abs(change_time - times[index]))]


def state_after(change: dict) -> tuple[bool, object]:
    kind = change.get("kind")
    return (False, None) if kind == "removed" else (True, change.get("new_value"))


def state_before(change: dict) -> tuple[bool, object]:
    kind = change.get("kind")
    return (False, None) if kind == "added" else (True, change.get("old_value"))


class FimState:
    """Baseline and current value of each item FIM has reported on.

    APPROXIMATION: the VM's real baseline.json is not in the exported recordings, so the
    baseline of an item is taken to be what the first reported change replaced. That is
    right for an item that was untouched until the first change, which is the case in the
    recordings. An item changed before recording started would be wrong.
    """

    def __init__(self):
        self._baseline: dict[str, tuple] = {}
        self._current: dict[str, tuple] = {}
        self._last: dict[str, float] = {}

    def observe(self, event: dict) -> None:
        change = event["target"].get("change")
        if event["event_type"] != "fim_change" or not isinstance(change, dict):
            return
        item = item_of(event["target"])
        if not item:
            return
        self._baseline.setdefault(item, state_before(change))
        self._current[item] = state_after(change)
        self._last[item] = when(event)

    def last_change(self, item: str) -> float | None:
        return self._last.get(item)

    def context(self, item: str, now: float) -> dict | None:
        """The `fim` context for decide(), or None when FIM never reported this item."""
        if item not in self._current:
            return None
        return {
            "differs_from_baseline": self._current[item] != self._baseline[item],
            "settled_seconds": max(0.0, now - self._last[item]),
        }
