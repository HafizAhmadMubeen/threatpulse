"""Turns changes into fim_change Event records and writes them to fim.jsonl."""

import json
import socket
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from baseline import Change

# The agent's counter starts at 1, so IDs from a run started in the same second can't
# clash. Consumers merge the two logs.
FIRST_COUNTER = 900000000

# Registry data is attacker-controlled and can be large. The baseline keeps it all.
MAX_VALUE_CHARS = 1024


def format_ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def short(value: str | None) -> str | None:
    return None if value is None else value[:MAX_VALUE_CHARS]


def build_event(change: Change, event_id: str, host: str, moment: datetime) -> dict:
    """FIM sees what changed, not who changed it, so no writer is claimed here."""
    is_file = change.item_kind == "file"
    return {
        "event_id": event_id,
        "ts": format_ts(moment),
        "host": host,
        "source": "fim",
        "event_type": "fim_change",
        "pid": 0,
        "ppid": 0,
        "process": {
            "image": "unknown",
            "cmdline": None,
            "user": None,
            "sha256": None,
            "signed": False,
            "signer": None,
        },
        "target": {
            "path": change.name if is_file else None,
            "old_path": None,
            "registry_key": None if is_file else change.name,
            "pid": None,
            "access_mask": None,
            "access_rights": None,
            "dest_ip": None,
            "dest_port": None,
            "change": {
                "kind": change.change_kind,
                "old_value": short(change.old_value),
                "new_value": short(change.new_value),
            },
        },
    }


def rotate_existing(path: Path, moment: datetime) -> None:
    """fim.jsonl -> fim-20261105T101500.jsonl, so runs never overwrite each other."""
    if not path.exists():
        return
    stem = f"{path.stem}-{moment.strftime('%Y%m%dT%H%M%S')}"
    attempt = 0
    while True:
        suffix = f"-{attempt}" if attempt else ""
        rotated = path.with_name(f"{stem}{suffix}{path.suffix}")
        if not rotated.exists():
            path.rename(rotated)
            return
        attempt += 1


class EventWriter:
    def __init__(self, path: Path, clock: Callable[[], datetime] = utc_now):
        self._clock = clock
        self._host = socket.gethostname().lower()
        self._run_id = clock().strftime("%Y%m%dT%H%M%S")
        self._counter = FIRST_COUNTER
        path.parent.mkdir(parents=True, exist_ok=True)
        rotate_existing(path, clock())
        self._file = path.open("x", encoding="utf-8", newline="\n")

    def write(self, change: Change) -> None:
        event_id = f"e-{self._run_id}-{self._counter:06d}"
        self._counter += 1
        event = build_event(change, event_id, self._host, self._clock())
        # Escaped as ASCII: registry data can hold invalid Unicode, which must not stop FIM.
        self._file.write(json.dumps(event) + "\n")
        self._file.flush()  # changes are rare, and each one matters

    def close(self) -> None:
        self._file.close()
