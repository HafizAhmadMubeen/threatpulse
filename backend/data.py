"""Reads events, alerts, decisions and reports from a data directory.

Everything here is attacker-influenced telemetry, so it is treated as data. A record
that is unreadable or fails its schema is skipped and counted, not trusted and not
fatal: one bad line must not take the dashboard down in the middle of an incident.
"""

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

from jsonschema import Draft202012Validator

from contracts.validate_samples import load_validators

# events.jsonl comes from the agent, fim.jsonl from the separate FIM module.
EVENT_FILES = ("events.jsonl", "fim.jsonl")
JSON_FILES = {"alert": "alerts.json", "decision": "decisions.json", "report": "reports.json"}


@dataclass
class DataSet:
    events: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    reports: list[dict] = field(default_factory=list)
    skipped: dict[str, int] = field(
        default_factory=lambda: {"events": 0, "alerts": 0, "decisions": 0, "reports": 0}
    )


def read_lines(path: Path) -> tuple[list[object], int]:
    """A partly written last line just fails to parse, and is read on the next change."""
    records, unreadable = [], 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            unreadable += 1
    return records, unreadable


def read_array(path: Path) -> tuple[list[object], int]:
    try:
        records = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return [], 1
    return (records, 0) if isinstance(records, list) else ([], 1)


class DataDirectory:
    """Rereads the files only when one changes."""

    def __init__(self, path: Path, validators: dict[str, Draft202012Validator] | None = None):
        self.path = path
        self.validators = validators or load_validators()
        self._lock = threading.Lock()
        self._signature: tuple | None = None
        self._data = DataSet()

    def _file_signature(self) -> tuple:
        signature = []
        for name in (*EVENT_FILES, *JSON_FILES.values()):
            target = self.path / name
            if target.is_file():
                stat = target.stat()
                signature.append((name, stat.st_mtime_ns, stat.st_size))
        return tuple(signature)

    def _valid(self, kind: str, records: list[object]) -> tuple[list[dict], int]:
        valid = [r for r in records if self.validators[kind].is_valid(r)]
        return valid, len(records) - len(valid)

    def _read(self) -> DataSet:
        data = DataSet()
        for name in EVENT_FILES:
            target = self.path / name
            if target.is_file():
                records, unreadable = read_lines(target)
                valid, invalid = self._valid("event", records)
                data.events += valid
                data.skipped["events"] += unreadable + invalid
        # Neither file is strictly in time order, and merging them needs a sort.
        data.events.sort(key=lambda event: event["ts"])

        for kind, name in JSON_FILES.items():
            target = self.path / name
            if target.is_file():
                records, unreadable = read_array(target)
                valid, invalid = self._valid(kind, records)
                setattr(data, f"{kind}s", valid)
                data.skipped[f"{kind}s"] = unreadable + invalid
        return data

    def load(self) -> DataSet:
        with self._lock:
            signature = self._file_signature()
            if signature != self._signature:
                self._data = self._read()
                self._signature = signature
            return self._data
