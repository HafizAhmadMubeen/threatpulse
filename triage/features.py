"""Behaviour features per process tree: python -m triage.features <session folder>... --out features.csv

Follows CLAUDE.md "ML rules". A feature describes what a tree did: counts, rates, zones
touched, children, signed or not. No process name, path or command line is ever a
feature. Paths and keys are only used to answer "which zone is this", and the answer
leaves as a number. detection/zones.py is the one place that decides.

Counts and rates come from ETW events only, so one action is never counted twice. Sysmon
events give zone signals (LSASS access, network, registry writes), as PLANNING.md Section 10
allows.

A session folder holds events.jsonl, fim.jsonl, labels.csv and session.json.

Metadata columns (session, label, network, pool, batch) are for splitting and reporting.
They are never features: network mode in particular could become a shortcut for the label.
The split by session (step 3.4) uses session_id. Filtering which trees to train on is also
step 3.4, so every tree is written, with observed_start saying if its start was seen.
"""

import argparse
import bisect
import csv
import json
import logging
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from contracts.validate_samples import load_validators
from detection import zones
from detection.timeline import order_key, parse_ts, read_jsonl

log = logging.getLogger(__name__)

SESSION_FIELDS = ("session_id", "pool", "batch", "network")
FIM_LINK_SECONDS = 120.0  # FIM's polling backup runs every 60 seconds
BURST_SECONDS = 30.0
FILE_BURST_SECONDS = 10.0
FILE_EVENTS = ("file_create", "file_write", "file_rename", "file_delete")
WRITE_EVENTS = (*FILE_EVENTS, "registry_set", "registry_delete")

METADATA_COLUMNS = [
    "session_id", "tree_id", "root_pid", "pool", "batch", "label", "technique", "network",
    "activity", "observed_start", "n_events", "n_malicious_events",
]
FEATURE_COLUMNS = [
    # Shape of the tree
    "n_processes", "n_children_of_root", "max_depth", "duration_s",
    # What it did (ETW only)
    "n_file_create", "n_file_write", "n_file_rename", "n_file_delete",
    "n_registry_set", "n_network_connect",
    "rate_file_create", "rate_file_write", "rate_file_rename", "rate_file_delete",
    "rate_registry_set",
    "peak_file_ops_10s", "peak_destructive_ops_30s",
    "n_distinct_dest_ips", "n_distinct_dest_ports",
    # Zones touched (ETW counts)
    "n_document_file_events", "n_document_deletes", "n_persistence_registry_sets",
    "n_startup_folder_events", "n_hosts_file_events", "n_zones_touched",
    # Zone signals (Sysmon)
    "sysmon_lsass_access", "sysmon_lsass_vm_read", "sysmon_network_connects",
    "sysmon_persistence_registry_sets", "sysmon_persistence_registry_deletes",
    # Signed or not
    "n_unsigned_processes", "signed_fraction", "root_signed",
    # FIM changes linked to a write by this tree
    "n_fim_changes_linked",
]
COLUMNS = METADATA_COLUMNS + FEATURE_COLUMNS


class SessionError(Exception):
    pass


@dataclass(eq=False)  # compared by identity, so a process can key a dict
class Proc:
    pid: int
    start_observed: bool
    parent: "Proc | None" = None
    root: "Proc | None" = None
    depth: int = 0
    signed: bool | None = None
    children: int = 0
    stats: "TreeStats | None" = None


@dataclass(eq=False)
class TreeStats:
    root: Proc
    processes: list[Proc] = field(default_factory=list)
    first: float = float("inf")
    last: float = float("-inf")
    n_events: int = 0
    n_malicious: int = 0
    technique: str = ""
    counts: Counter = field(default_factory=Counter)
    file_times: list[float] = field(default_factory=list)
    destructive_times: list[float] = field(default_factory=list)
    dest_ips: set = field(default_factory=set)
    dest_ports: set = field(default_factory=set)
    zones: set = field(default_factory=set)
    writes: list[tuple[float, str]] = field(default_factory=list)  # for linking FIM changes


def peak_in_window(times: list[float], window: float) -> int:
    """The most events inside any span of `window` seconds. `times` must be sorted."""
    best, start = 0, 0
    for end, moment in enumerate(times):
        while moment - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def normalise_name(name: str) -> str:
    """FIM and ETW may write the same registry key as HKCU or as HKU\\<sid>."""
    parts = name.lower().rstrip("\\").split("\\")
    if len(parts) > 2 and parts[0] == "hku" and parts[1].startswith("s-1-5-21-"):
        parts = ["hkcu", *parts[2:]]
    return "\\".join(parts)


def load_session(folder: Path) -> tuple[dict, list[dict], dict[str, dict]]:
    try:
        session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise SessionError(f"{folder}: cannot read session.json ({type(error).__name__})") from error
    if not isinstance(session, dict):
        raise SessionError(f"{folder}: session.json is not an object")
    missing = [name for name in SESSION_FIELDS if session.get(name) in (None, "")]
    if missing:
        raise SessionError(f"{folder}: session.json lacks {missing}")

    validator = load_validators()["event"]
    events: list[dict] = []
    for name in ("events.jsonl", "fim.jsonl"):
        read, _ = read_jsonl(folder / name)
        events += [event for event in read if validator.is_valid(event)]
    if not events:
        raise SessionError(f"{folder}: no usable events")

    labels: dict[str, dict] = {}
    path = folder / "labels.csv"
    if path.is_file():
        with path.open(encoding="utf-8", newline="") as stream:
            labels = {row["event_id"]: row for row in csv.DictReader(stream)}
    events.sort(key=order_key)
    return session, events, labels


def is_etw(event: dict, kind: str) -> bool:
    return event["source"] == "etw" and event["event_type"] == kind


def assign_processes(events: list[dict]) -> dict[str, Proc]:
    """Maps event_id to the process it belongs to. A root is a process whose parent has no
    process_start in the session, so the label never decides what a tree is."""
    current: dict[int, Proc] = {}
    owner: dict[str, Proc] = {}
    for event in events:
        pid = event["pid"]
        if event["source"] == "fim" or pid == 0:
            continue
        if is_etw(event, "process_start"):
            proc = Proc(pid, start_observed=True)
            parent = current.get(event["ppid"]) if event["ppid"] else None
            if parent is not None and parent.start_observed:
                proc.parent, proc.root, proc.depth = parent, parent.root, parent.depth + 1
                parent.children += 1
            else:
                proc.root = proc
            current[pid] = proc
        else:
            proc = current.get(pid)
            if proc is None:
                proc = Proc(pid, start_observed=False)
                proc.root = proc
                current[pid] = proc
        if proc.signed is None:
            proc.signed = event["process"]["signed"]
        owner[event["event_id"]] = proc
    return owner


def count_event(stats: TreeStats, event: dict, when: float) -> None:
    kind, target = event["event_type"], event["target"]
    if event["source"] == "etw":
        stats.counts[kind] += 1
        if kind in FILE_EVENTS:
            stats.file_times.append(when)
            path = target["path"]
            if kind in ("file_rename", "file_delete"):
                stats.destructive_times.append(when)
            if zones.is_document_path(path):
                stats.counts["document_events"] += 1
                stats.zones.add("documents")
                if kind == "file_delete":
                    stats.counts["document_deletes"] += 1
            if zones.is_startup_path(path):
                stats.counts["startup_events"] += 1
                stats.zones.add("persistence")
            if zones.is_hosts_path(path):
                stats.counts["hosts_events"] += 1
                stats.zones.add("persistence")
        elif kind == "registry_set":
            if zones.is_persistence_key(target["registry_key"]):
                stats.counts["persistence_registry"] += 1
                stats.zones.add("persistence")
        elif kind == "network_connect":
            stats.zones.add("network")
            stats.dest_ips.add(target["dest_ip"])
            stats.dest_ports.add(target["dest_port"])
    elif event["source"] == "sysmon":
        if kind == "process_access" and zones.is_lsass_path(target["path"]):
            stats.counts["lsass_access"] += 1
            stats.zones.add("lsass")
            if "vm_read" in (target.get("access_rights") or []):
                stats.counts["lsass_vm_read"] += 1
        elif kind == "network_connect":
            stats.counts["sysmon_network"] += 1
            stats.zones.add("network")
        elif kind in ("registry_set", "registry_delete") and zones.is_persistence_key(target["registry_key"]):
            stats.counts[f"sysmon_{kind}"] += 1
            stats.zones.add("persistence")

    name = target["registry_key"] if kind.startswith("registry") else target["path"]
    if kind in WRITE_EVENTS and name:
        stats.writes.append((when, normalise_name(name)))


def link_fim(events: list[dict], trees: dict[Proc, TreeStats]) -> None:
    """A FIM change is linked to the tree that last wrote that exact item just before it.
    FIM doesn't know who made a change, so this is the only link there is."""
    found: dict[str, list[tuple[float, int, TreeStats]]] = {}
    for number, stats in enumerate(trees.values()):
        for when, name in stats.writes:
            found.setdefault(name, []).append((when, number, stats))
    writers = {name: sorted(entries, key=lambda e: e[:2]) for name, entries in found.items()}
    times = {name: [entry[0] for entry in entries] for name, entries in writers.items()}
    for event in events:
        if event["event_type"] != "fim_change":
            continue
        name = normalise_name(event["target"]["registry_key"] or event["target"]["path"] or "")
        if name not in writers:
            continue
        when = parse_ts(event["ts"]).timestamp()
        index = bisect.bisect_right(times[name], when) - 1
        if index >= 0 and when - times[name][index] <= FIM_LINK_SECONDS:
            writers[name][index][2].counts["fim_linked"] += 1


def build_trees(events: list[dict], owner: dict[str, Proc], labels: dict[str, dict]) -> dict[Proc, TreeStats]:
    trees: dict[Proc, TreeStats] = {}
    for event in events:
        proc = owner.get(event["event_id"])
        if proc is None:
            continue
        root = proc.root
        stats = trees.setdefault(root, TreeStats(root))
        if proc.stats is None:
            proc.stats = stats
            stats.processes.append(proc)
        when = parse_ts(event["ts"]).timestamp()
        stats.first, stats.last = min(stats.first, when), max(stats.last, when)
        stats.n_events += 1
        label = labels.get(event["event_id"])
        if label and label["label"] == "malicious":
            stats.n_malicious += 1
            stats.technique = stats.technique or label.get("technique", "")
        count_event(stats, event, when)
    return trees


def tree_label(stats: TreeStats, labelled: bool) -> str:
    if not labelled:
        return "unlabelled"
    return "malicious" if stats.n_malicious else "benign"


def feature_row(stats: TreeStats) -> dict:
    counts = stats.counts
    duration = max(stats.last - stats.first, 0.0)
    rate = lambda name: round(counts[name] / max(duration, 1.0), 4)  # noqa: E731
    processes = stats.processes
    unsigned = sum(1 for proc in processes if not proc.signed)
    document_events = counts["document_events"]
    return {
        "n_processes": len(processes),
        "n_children_of_root": stats.root.children,
        "max_depth": max(proc.depth for proc in processes),
        "duration_s": round(duration, 3),
        "n_file_create": counts["file_create"],
        "n_file_write": counts["file_write"],
        "n_file_rename": counts["file_rename"],
        "n_file_delete": counts["file_delete"],
        "n_registry_set": counts["registry_set"],
        "n_network_connect": counts["network_connect"],
        "rate_file_create": rate("file_create"),
        "rate_file_write": rate("file_write"),
        "rate_file_rename": rate("file_rename"),
        "rate_file_delete": rate("file_delete"),
        "rate_registry_set": rate("registry_set"),
        "peak_file_ops_10s": peak_in_window(sorted(stats.file_times), FILE_BURST_SECONDS),
        "peak_destructive_ops_30s": peak_in_window(sorted(stats.destructive_times), BURST_SECONDS),
        "n_distinct_dest_ips": len(stats.dest_ips),
        "n_distinct_dest_ports": len(stats.dest_ports),
        "n_document_file_events": document_events,
        "n_document_deletes": counts["document_deletes"],
        "n_persistence_registry_sets": counts["persistence_registry"],
        "n_startup_folder_events": counts["startup_events"],
        "n_hosts_file_events": counts["hosts_events"],
        "n_zones_touched": len(stats.zones),
        "sysmon_lsass_access": counts["lsass_access"],
        "sysmon_lsass_vm_read": counts["lsass_vm_read"],
        "sysmon_network_connects": counts["sysmon_network"],
        "sysmon_persistence_registry_sets": counts["sysmon_registry_set"],
        "sysmon_persistence_registry_deletes": counts["sysmon_registry_delete"],
        "n_unsigned_processes": unsigned,
        "signed_fraction": round(1 - unsigned / len(processes), 4),
        "root_signed": int(bool(stats.root.signed)),
        "n_fim_changes_linked": counts["fim_linked"],
    }


def extract_session(folder: Path) -> list[dict]:
    """One row per process tree, in order of first activity."""
    session, events, labels = load_session(folder)
    owner = assign_processes(events)
    trees = build_trees(events, owner, labels)
    link_fim(events, trees)
    rows = []
    for number, stats in enumerate(sorted(trees.values(), key=lambda s: s.first)):
        technique = stats.technique or (session.get("technique") if stats.n_malicious else "") or ""
        rows.append(
            {
                "session_id": session["session_id"],
                "tree_id": f"{session['session_id']}:{number}",
                "root_pid": stats.root.pid,
                "pool": session["pool"],
                "batch": session["batch"],
                "label": tree_label(stats, bool(labels)),
                "technique": technique,
                "network": session["network"],
                "activity": session.get("activity") or "",
                "observed_start": int(stats.root.start_observed),
                "n_events": stats.n_events,
                "n_malicious_events": stats.n_malicious,
                **feature_row(stats),
            }
        )
    return rows


def write_csv(rows: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract behaviour features per process tree.")
    parser.add_argument("sessions", nargs="+", type=Path, help="session folders")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    rows: list[dict] = []
    for folder in args.sessions:
        try:
            rows += extract_session(folder)
        except SessionError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    write_csv(rows, args.out)
    print(f"{len(rows)} trees from {len(args.sessions)} session(s) written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
