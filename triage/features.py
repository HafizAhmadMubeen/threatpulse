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
from detection.stream import SortedEvents
from detection.timeline import order_key, parse_ts, read_jsonl

log = logging.getLogger(__name__)

SESSION_FIELDS = ("session_id", "pool", "batch", "network")
FIM_LINK_SECONDS = 120.0  # FIM's polling backup runs every 60 seconds
# FIM and the writer's own event are stamped by different clocks. In the first real
# recordings FIM's "removed" came 45 ms before the Sysmon delete that caused it.
FIM_SKEW_SECONDS = 0.5
PARTS = {"test", "harness", "background", "none", ""}
BURST_SECONDS = 30.0
FILE_BURST_SECONDS = 10.0
FILE_EVENTS = ("file_create", "file_write", "file_rename", "file_delete")
WRITE_EVENTS = (*FILE_EVENTS, "registry_set", "registry_delete")

METADATA_COLUMNS = [
    "session_id", "tree_id", "root_pid", "pool", "batch", "label", "technique", "network",
    "activity", "observed_start", "harness_excluded", "n_events", "n_malicious_events",
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


def read_session_json(folder: Path) -> dict:
    try:
        session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise SessionError(f"{folder}: cannot read session.json ({type(error).__name__})") from error
    if not isinstance(session, dict):
        raise SessionError(f"{folder}: session.json is not an object")
    missing = [name for name in SESSION_FIELDS if session.get(name) in (None, "")]
    if missing:
        raise SessionError(f"{folder}: session.json lacks {missing}")
    return session


def load_session(folder: Path, labels_dir: Path | None = None,
                 from_start: bool = False) -> tuple[dict, list[dict], dict[str, dict]]:
    """`labels_dir` is a folder with `<session folder name>/labels.csv`, used instead of the
    labels.csv inside the session folder (labels are re-made without touching recordings).
    `from_start` drops every event before session.json's start_utc: sensor start, settle
    time and warm-up (agent/tools/record_session.ps1 says Track B computes from start_utc)."""
    session = read_session_json(folder)
    validator = load_validators()["event"]
    events: list[dict] = []
    for name in ("events.jsonl", "fim.jsonl"):
        read, _ = read_jsonl(folder / name)
        events += [event for event in read if validator.is_valid(event)]
    if not events:
        raise SessionError(f"{folder}: no usable events")

    if from_start:
        start = session.get("start_utc")
        if not isinstance(start, str):
            raise SessionError(f"{folder}: session.json has no start_utc")
        begin = parse_ts(start).timestamp()
        events = [e for e in events if parse_ts(e["ts"]).timestamp() >= begin]
        if not events:
            raise SessionError(f"{folder}: no events at or after start_utc")

    labels: dict[str, dict] = {}
    path = (labels_dir / folder.name / "labels.csv") if labels_dir is not None else folder / "labels.csv"
    if labels_dir is not None and not path.is_file():
        raise SessionError(f"{folder}: no labels at {path}")
    if path.is_file():
        with path.open(encoding="utf-8", newline="") as stream:
            labels = {row["event_id"]: row for row in csv.DictReader(stream)}
    session["_harness_excluded"] = int(bool(labels) and "part" in next(iter(labels.values())))
    if session["_harness_excluded"]:
        events = drop_harness(events, labels, folder)
    else:
        if labels:
            log.warning(
                "%s: labels.csv has no part column, so the wrapper that runs each test is counted "
                "as the test. These rows must not be used for training.", folder.name,
            )
    events.sort(key=order_key)
    return session, events, labels


def drop_harness(events: list[dict], labels: dict[str, dict], folder: Path) -> list[dict]:
    """The wrapper that runs a test is not the technique, so features must not describe it.
    Dropping its events before trees are built also removes it from the tree shape: the
    test's own process becomes the root, because its parent no longer has a start event."""
    unknown = {row.get("part") for row in labels.values()} - PARTS
    if unknown:
        raise SessionError(f"{folder}: labels.csv has unknown part values {sorted(map(str, unknown))}")
    kept = [e for e in events if (labels.get(e["event_id"]) or {}).get("part") != "harness"]
    if len(kept) != len(events):
        log.info("%s: %d harness event(s) left out", folder.name, len(events) - len(kept))
    if not kept:
        raise SessionError(f"{folder}: no events are left after leaving out the harness")
    return kept


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
    """A FIM change is linked to the tree whose write to that exact item is nearest in time:
    up to 120 seconds before it, or 0.5 seconds after it to allow for clock skew.
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
        after = bisect.bisect_right(times[name], when)
        candidates = [
            index for index in (after - 1, after)
            if 0 <= index < len(times[name])
            and -FIM_SKEW_SECONDS <= when - times[name][index] <= FIM_LINK_SECONDS
        ]
        if candidates:
            nearest = min(candidates, key=lambda index: abs(when - times[name][index]))
            writers[name][nearest][2].counts["fim_linked"] += 1


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


def tree_feature_row(events: list[dict]) -> dict | None:
    """Features of ONE process tree from its own events: what score_process uses, so
    training and scoring share the code. None when the events are not a single tree whose
    root start was observed, because training only used such trees (step 3.4).

    FIM events are not part of a tree's events, so n_fim_changes_linked is always 0 here.
    The model leaves that column out (triage/model.py)."""
    ordered = sorted(events, key=order_key)
    trees = build_trees(ordered, assign_processes(ordered), {})
    if len(trees) != 1:
        return None
    (stats,) = trees.values()
    if not stats.root.start_observed:
        return None
    return feature_row(stats)


def events_of_tree_containing(events: list[dict], pid: int) -> list[dict]:
    """The events of the process tree (as defined above) that process `pid` belongs to.

    The pipeline's own tree can reach up to a long-running process whose start was never
    seen, and everything below it is one tree there. Here each started process under such
    a parent is its own root, as in training. So this is the tree the model was trained on
    the shape of. Empty when no event has this pid."""
    ordered = sorted(events, key=order_key)
    owner = assign_processes(ordered)
    mine = [owner[e["event_id"]] for e in ordered if e["pid"] == pid and e["event_id"] in owner]
    if not mine:
        return []
    root = mine[-1].root  # the latest process with this pid
    return [e for e in ordered if e["event_id"] in owner and owner[e["event_id"]].root is root]


def extract_session(folder: Path, labels_dir: Path | None = None, from_start: bool = False) -> list[dict]:
    """One row per process tree, in order of first activity."""
    return [row for row, _ in iter_session_trees(folder, labels_dir, from_start)]


def extract_session_trees_in_memory(folder: Path, labels_dir: Path | None = None,
                                    from_start: bool = False) -> list[tuple[dict, list[dict]]]:
    """The reference implementation: reads every event into memory. It needs about 3 KB per
    event, so it fails on a session of a million events. `extract_session_trees` gives the same
    rows from a stream, and a test holds the two to each other. Kept for that test."""
    session, events, labels = load_session(folder, labels_dir, from_start)
    owner = assign_processes(events)
    trees = build_trees(events, owner, labels)
    link_fim(events, trees)
    by_root: dict[Proc, list[dict]] = {}
    for event in events:
        proc = owner.get(event["event_id"])
        if proc is not None:
            by_root.setdefault(proc.root, []).append(event)
    rows = []
    for number, stats in enumerate(sorted(trees.values(), key=lambda s: s.first)):
        technique = stats.technique or (session.get("technique") if stats.n_malicious else "") or ""
        mine = by_root.get(stats.root, [])
        rows.append(
            ({
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
                "harness_excluded": session["_harness_excluded"],
                "n_events": stats.n_events,
                "n_malicious_events": stats.n_malicious,
                **feature_row(stats),
            }, mine)
        )
    return rows


# ---- streaming ------------------------------------------------------------------------------


def read_label_codes(path: Path) -> tuple[dict[str, int], list[tuple[str, str, str]], bool]:
    """labels.csv as event_id -> a small number, and the table of the (label, part, technique)
    triples the numbers stand for. A million-event session has a million label rows, and a dict
    of dicts would need about a GB. Later rows for the same event_id win, as in a dict."""
    codes: dict[str, int] = {}
    table: list[tuple[str, str, str]] = []
    known: dict[tuple[str, str, str], int] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        has_part = reader.fieldnames is not None and "part" in reader.fieldnames
        for row in reader:
            triple = (row.get("label") or "", row.get("part") or "", row.get("technique") or "")
            number = known.get(triple)
            if number is None:
                number = known[triple] = len(table)
                table.append(triple)
            codes[row["event_id"]] = number
    return codes, table, has_part


def compact(event: dict) -> tuple:
    """The fields a tree's features read, as a tuple (about a fifth of the memory of the event)."""
    target = event["target"]
    return (event["event_id"], event["ts"], event["source"], event["event_type"], event["pid"], event["ppid"],
            event["process"]["signed"], target["path"], target["registry_key"], target["dest_ip"],
            target["dest_port"], target.get("access_rights"))


def expand(item: tuple) -> dict:
    """A slim event with exactly the fields compact() kept: all that tree_feature_row, the
    snapshots and the process assignment read."""
    event_id, ts, source, kind, pid, ppid, signed, path, key, dest_ip, dest_port, rights = item
    return {"event_id": event_id, "ts": ts, "source": source, "event_type": kind, "pid": pid, "ppid": ppid,
            "process": {"signed": signed},
            "target": {"path": path, "registry_key": key, "dest_ip": dest_ip, "dest_port": dest_port,
                       "access_rights": rights}}


def iter_session_trees(folder: Path, labels_dir: Path | None = None, from_start: bool = False):
    """Yields (row, events) for each process tree, in order of first activity. The same rows as
    the in-memory extractor, from a stream: events are read one at a time in time order,
    counted as they pass, and only the trees whose start was observed keep their events (as
    tuples, and expanded one tree at a time, so a caller that drops a tree's events after
    using them never holds more than that tree). `events` are slim: see expand()."""
    session = read_session_json(folder)
    validator = load_validators()["event"]
    paths = [folder / "events.jsonl", folder / "fim.jsonl"]
    begin = None
    if from_start:
        start = session.get("start_utc")
        if not isinstance(start, str):
            if SortedEvents(paths, validator.is_valid).valid == 0:
                raise SessionError(f"{folder}: no usable events")
            raise SessionError(f"{folder}: session.json has no start_utc")
        begin = parse_ts(start).timestamp()
    stream = SortedEvents(paths, validator.is_valid, begin)
    if stream.valid == 0:
        raise SessionError(f"{folder}: no usable events")
    if begin is not None and len(stream) == 0:
        raise SessionError(f"{folder}: no events at or after start_utc")

    path = (labels_dir / folder.name / "labels.csv") if labels_dir is not None else folder / "labels.csv"
    if labels_dir is not None and not path.is_file():
        raise SessionError(f"{folder}: no labels at {path}")
    codes, table, has_part = read_label_codes(path) if path.is_file() else ({}, [], False)
    labelled = bool(codes)
    session["_harness_excluded"] = int(labelled and has_part)
    if session["_harness_excluded"]:
        unknown = {table[number][1] for number in set(codes.values())} - PARTS
        if unknown:
            raise SessionError(f"{folder}: labels.csv has unknown part values {sorted(map(str, unknown))}")
    elif labelled:
        log.warning("%s: labels.csv has no part column, so the wrapper that runs each test is counted "
                    "as the test. These rows must not be used for training.", folder.name)

    current: dict[int, Proc] = {}
    trees: dict[Proc, TreeStats] = {}
    kept: dict[Proc, list[tuple]] = {}
    fim_events: list[dict] = []
    used = harness = 0
    for event in stream:
        number = codes.get(event["event_id"])
        if session["_harness_excluded"] and number is not None and table[number][1] == "harness":
            harness += 1
            continue
        used += 1
        if event["event_type"] == "fim_change":
            fim_events.append(event)
        pid = event["pid"]
        if event["source"] == "fim" or pid == 0:
            continue
        # Which process this event belongs to (what assign_processes does, one event at a time).
        if event["source"] == "etw" and event["event_type"] == "process_start":
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
        # Counting it in its tree (what build_trees does).
        root = proc.root
        stats = trees.get(root)
        if stats is None:
            stats = trees[root] = TreeStats(root)
        if proc.stats is None:
            proc.stats = stats
            stats.processes.append(proc)
        when = parse_ts(event["ts"]).timestamp()
        stats.first, stats.last = min(stats.first, when), max(stats.last, when)
        stats.n_events += 1
        if number is not None and table[number][0] == "malicious":
            stats.n_malicious += 1
            stats.technique = stats.technique or table[number][2]
        count_event(stats, event, when)
        if root.start_observed:
            kept.setdefault(root, []).append(compact(event))
    if used == 0:
        raise SessionError(f"{folder}: no events are left after leaving out the harness")
    if harness:
        log.info("%s: %d harness event(s) left out", folder.name, harness)
    link_fim(fim_events, trees)
    del fim_events, codes, current

    for number, stats in enumerate(sorted(trees.values(), key=lambda s: s.first)):
        technique = stats.technique or (session.get("technique") if stats.n_malicious else "") or ""
        row = {
            "session_id": session["session_id"],
            "tree_id": f"{session['session_id']}:{number}",
            "root_pid": stats.root.pid,
            "pool": session["pool"],
            "batch": session["batch"],
            "label": tree_label(stats, labelled),
            "technique": technique,
            "network": session["network"],
            "activity": session.get("activity") or "",
            "observed_start": int(stats.root.start_observed),
            "harness_excluded": session["_harness_excluded"],
            "n_events": stats.n_events,
            "n_malicious_events": stats.n_malicious,
            **feature_row(stats),
        }
        yield row, [expand(item) for item in kept.pop(stats.root, [])]


def extract_session_trees(folder: Path, labels_dir: Path | None = None,
                          from_start: bool = False) -> list[tuple[dict, list[dict]]]:
    """Each row with the events of its tree, all at once. A caller that can use the trees one
    after another should iterate iter_session_trees instead."""
    return list(iter_session_trees(folder, labels_dir, from_start))


def write_csv(rows: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract behaviour features per process tree.")
    parser.add_argument("sessions", nargs="+", type=Path, help="session folders")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--labels-dir", type=Path,
                        help="folder of <session>/labels.csv to use instead of each session's own labels.csv")
    parser.add_argument("--from-start", action="store_true",
                        help="leave out events before each session's start_utc (sensor start and warm-up)")
    args = parser.parse_args(argv)
    rows: list[dict] = []
    for folder in args.sessions:
        try:
            rows += extract_session(folder, args.labels_dir, args.from_start)
        except SessionError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    write_csv(rows, args.out)
    print(f"{len(rows)} trees from {len(args.sessions)} session(s) written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
