#!/usr/bin/env python3
"""Label the events of recorded sessions, and write labels.csv.

Usage: python agent/tools/label_session.py <session folder> [--out <folder>]
       python agent/tools/label_session.py --batch <batch folder> --out <folder>

A session folder holds session.json, events.jsonl and fim.jsonl, as written by
record_session.ps1. Labels go in a separate file keyed by event_id, because the Event
schema allows no extra fields.

Each row has a label and a part:

  label   malicious for the root process and its descendants in a test session, benign
          for everything else, and none for fim_change events, which have no process.
  part    test        the test's own processes. For an Atomic test, the process the
                      Invoke-AtomicTest wrapper starts to run it, and everything below it.
                      For our own T1486 script, the whole tree.
          harness     the Atomic wrapper itself: the root PowerShell, and the hostname,
                      whoami and conhost it starts. Never part of a real attack.
          background  everything else, including every event in a benign session.

Train and evaluate on the test part against the background part, and leave the harness
part out of both. The wrapper runs in every Atomic session and in no benign one, so a model
that sees it learns the wrapper instead of behaviour.

With --out, labels.csv goes to <out>/labels.csv (or <out>/<session>/labels.csv with
--batch), and an existing file is never overwritten. Use --out for exported data: it
leaves the exported folder untouched.

A process is identified by pid and start time, so a reused pid is never mislabelled.

Exit code 0 means labels were written, 1 means a session can't be labelled.
"""

import argparse
import csv
import json
import ntpath
import sys
from pathlib import Path

ORDER_START = 0
ORDER_OTHER = 1
ORDER_STOP = 2

# Processes Invoke-AtomicTest starts for its own logging, before it runs the test.
HARNESS_HELPERS = {"conhost.exe", "hostname.exe", "whoami.exe"}

FIELDS = ["event_id", "label", "part", "technique", "pool", "session_id", "network", "warmup_seconds"]


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


def uses_harness(session: dict) -> bool:
    """Atomic tests run through the wrapper. Our own scripts run directly."""
    return session.get("atomic_commit") is not None


def child_part(event: dict, parent_part: str, root_pid: int, wrapped: bool) -> str:
    """The part of a process that starts under a process of the tree."""
    if not wrapped or parent_part == "test":
        return "test"
    # A child of the wrapper itself is a helper, or the process that runs the test.
    # Anything below a helper stays part of the wrapper.
    if event["ppid"] != root_pid:
        return "harness"
    image = ntpath.basename(event["process"]["image"]).lower()
    return "harness" if image in HARNESS_HELPERS else "test"


def label_attack_events(events: list[dict], session: dict) -> list[tuple[str, str]]:
    """One (label, part) per event, in the same order as `events`, which must be sorted."""
    root_pid = session["root_pid"]
    wrapped = uses_harness(session)
    tree: dict[int, str] = {}  # pid -> part, for the tree processes that are running now
    root_seen = False
    results = []

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
                tree[pid] = "harness" if wrapped else "test"
            elif event["ppid"] in tree:
                tree[pid] = child_part(event, tree[event["ppid"]], root_pid, wrapped)
            else:
                tree.pop(pid, None)  # this pid was reused by an unrelated process

        if event["source"] == "fim":
            results.append(("none", "background"))
        elif pid in tree:
            results.append(("malicious", tree[pid]))
        else:
            results.append(("benign", "background"))

        if is_process_event(event, "process_stop"):
            tree.pop(pid, None)

    if not root_seen:
        raise LabelError(f"no process_start for root pid {root_pid} between start and end")
    return results


def label_session(folder: Path) -> list[dict]:
    session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    events = load_events(folder / "events.jsonl") + load_events(folder / "fim.jsonl")
    events.sort(key=order_key)
    if not events:
        raise LabelError("the session has no events")

    if session["label"] == "benign":
        results = [("benign", "background")] * len(events)
    else:
        results = label_attack_events(events, session)
        if not any(part == "test" for _, part in results):
            raise LabelError("no event belongs to the test itself, only to the wrapper")

    warmup = session.get("warmup_seconds") or 0  # sessions recorded before the warm-up have none
    return [
        {
            "event_id": event["event_id"],
            "label": label,
            "part": part,
            "technique": session["technique"] if label == "malicious" else "",
            "pool": session["pool"],
            "session_id": session["session_id"],
            "network": session["network"],
            "warmup_seconds": warmup,
        }
        for event, (label, part) in zip(events, results)
    ]


def write_labels(rows: list[dict], output: Path, overwrite: bool) -> None:
    if output.exists() and not overwrite:
        raise LabelError(f"{output} already exists and is not overwritten")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def summary(rows: list[dict]) -> str:
    counts: dict[tuple[str, str], int] = {}
    for row in rows:
        key = (row["label"], row["part"])
        counts[key] = counts.get(key, 0) + 1
    return ", ".join(f"{label}/{part} {count}" for (label, part), count in sorted(counts.items()))


def session_folders(batch: Path) -> list[Path]:
    return sorted(path for path in batch.iterdir() if (path / "session.json").exists())


def main() -> int:
    parser = argparse.ArgumentParser(description="Label recorded sessions.")
    parser.add_argument("folder", type=Path, help="a session folder, or with --batch a batch folder")
    parser.add_argument("--batch", action="store_true", help="label every session folder in <folder>")
    parser.add_argument("--out", type=Path, help="write labels here instead of into the session folder")
    args = parser.parse_args()

    if args.batch and not args.out:
        parser.error("--batch needs --out, so that the exported folder is not written to")

    if args.batch:
        folders = session_folders(args.folder)
        if not folders:
            print(f"No session folders in {args.folder}", file=sys.stderr)
            return 1
    else:
        folders = [args.folder]

    for folder in folders:
        try:
            rows = label_session(folder)
            if args.batch:
                output = args.out / folder.name / "labels.csv"
            else:
                output = (args.out or folder) / "labels.csv"
            write_labels(rows, output, overwrite=args.out is None)
        except (LabelError, FileNotFoundError) as error:
            print(f"Cannot label {folder}: {error}", file=sys.stderr)
            return 1
        print(f"{len(rows)} events labelled in {output}\n  {summary(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
