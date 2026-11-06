#!/usr/bin/env python3
"""Label the events of one recorded session, and write labels.csv.

Usage: python agent/tools/label_session.py <session folder>

The folder holds session.json, events.jsonl and fim.jsonl, as written by
record_session.ps1. Labels go in a separate file keyed by event_id, because the Event
schema allows no extra fields.

In a test session, the root process and its descendants are malicious, and everything
else is benign background. fim_change events have no process, so they get "none". In a
benign session, every event is benign.

A process is identified by pid and start time, so a reused pid is never mislabelled.

Exit code 0 means labels were written, 1 means the session can't be labelled.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

ORDER_START = 0
ORDER_OTHER = 1
ORDER_STOP = 2


class LabelError(Exception):
    pass


def load_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as lines:
        return [json.loads(line) for line in lines if line.strip()]


def order_key(event: dict) -> tuple[str, int]:
    """Time order. In the same millisecond, a start comes first and a stop comes last."""
    kind = event["event_type"]
    rank = ORDER_START if kind == "process_start" else ORDER_STOP if kind == "process_stop" else ORDER_OTHER
    return event["ts"], rank


def is_process_event(event: dict, kind: str) -> bool:
    return event["source"] == "etw" and event["event_type"] == kind


def label_attack_events(events: list[dict], session: dict) -> list[str]:
    """One label per event, in the same order as `events`, which must be sorted."""
    root_pid = session["root_pid"]
    in_tree: set[int] = set()  # pids of tree processes that are running now
    root_seen = False
    labels = []

    for event in events:
        pid = event["pid"]
        if is_process_event(event, "process_start"):
            is_root = (
                pid == root_pid
                and not root_seen
                and session["start_utc"] <= event["ts"] <= session["end_utc"]
            )
            if is_root:
                root_seen = True
                in_tree.add(pid)
            elif event["ppid"] in in_tree:
                in_tree.add(pid)
            else:
                in_tree.discard(pid)  # this pid was reused by an unrelated process

        if event["source"] == "fim":
            labels.append("none")
        else:
            labels.append("malicious" if pid in in_tree else "benign")

        if is_process_event(event, "process_stop"):
            in_tree.discard(pid)

    if not root_seen:
        raise LabelError(f"no process_start for root pid {root_pid} between start and end")
    return labels


def label_session(folder: Path) -> list[dict]:
    session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    events = load_events(folder / "events.jsonl") + load_events(folder / "fim.jsonl")
    events.sort(key=order_key)
    if not events:
        raise LabelError("the session has no events")

    if session["label"] == "benign":
        labels = ["benign"] * len(events)
    else:
        labels = label_attack_events(events, session)
        if "malicious" not in labels:
            raise LabelError("no event was labelled malicious")

    return [
        {
            "event_id": event["event_id"],
            "label": label,
            "technique": session["technique"] if label == "malicious" else "",
            "split": session["split"],
            "session_id": session["session_id"],
            "network": session["network"],
        }
        for event, label in zip(events, labels)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Label one recorded session.")
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()

    try:
        rows = label_session(args.folder)
    except (LabelError, FileNotFoundError) as error:
        print(f"Cannot label {args.folder}: {error}", file=sys.stderr)
        return 1

    output = args.folder / "labels.csv"
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print(f"{len(rows)} events labelled in {output}")
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
