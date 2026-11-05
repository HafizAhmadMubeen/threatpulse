#!/usr/bin/env python3
"""List which processes started after the agent caused path and registry gaps.

Usage: python agent/tools/coverage_report.py <events.jsonl>

The shutdown summary gives only counts. This groups the same gaps by program and
parent, because a child that writes through a handle its parent opened has no path.

A process counts as started after the agent if the log has its process_start event.
Totals can be slightly below the summary's, which also counts events that the noise
filters then dropped. Only ETW events count: Sysmon events always have a full key.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as lines:
        events = [json.loads(line) for line in lines if line.strip()]
    return sorted(events, key=lambda event: event["ts"])  # the file isn't in time order


def report(title: str, events: list[dict], is_gap, images: dict[int, str]) -> None:
    def group(event: dict) -> tuple[str, str]:
        parent = images.get(event["ppid"], f"pid {event['ppid']}")
        return event["process"]["image"], parent

    totals = Counter(group(event) for event in events)
    gaps = Counter(group(event) for event in events if is_gap(event))

    print(f"{title}: {sum(gaps.values())} of {sum(totals.values())} have gaps")
    for (image, parent), count in gaps.most_common():
        print(f"  {count} of {totals[(image, parent)]}  {image}  (parent: {parent})")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Group coverage gaps by program.")
    parser.add_argument("events", type=Path)
    args = parser.parse_args()

    started_after: set[int] = set()
    images: dict[int, str] = {}
    writes: list[dict] = []
    registry: list[dict] = []

    for event in load_events(args.events):
        images[event["pid"]] = event["process"]["image"]
        if event["source"] != "etw":
            continue
        if event["event_type"] == "process_start":
            started_after.add(event["pid"])
        elif event["pid"] in started_after:
            if event["event_type"] == "file_write":
                writes.append(event)
            elif event["event_type"] == "registry_set":
                registry.append(event)

    report("File writes", writes, lambda event: not event["target"]["path"], images)
    report("Registry writes", registry,
           lambda event: event["target"]["registry_key"].startswith("<unresolved>"), images)
    return 0


if __name__ == "__main__":
    sys.exit(main())
