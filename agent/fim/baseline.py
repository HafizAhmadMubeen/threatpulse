"""Snapshots of the watched items: comparing them, and saving the approved baseline.

A snapshot maps an item's name to its state. The name is a registry value
(HKCU\\...\\Run\\Name) or a full file path. This module has no Windows-only code, so
it can be tested in WSL.
"""

import hashlib
import json
import os
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from targets import FolderTarget

UNREADABLE = "unreadable"  # a locked file is reported, because it could be hiding a change
TRUNCATED = "scan truncated"
READ_ATTEMPTS = 3
READ_RETRY_SECONDS = 0.05
MAX_TREE_KEYS = 5000
MAX_TREE_DEPTH = 16


@dataclass(frozen=True)
class Item:
    kind: str  # "registry" or "file"
    value: str  # the registry data, or the file's SHA-256
    reg_type: int | None = None  # kept so that Phase 3 can restore the exact type


@dataclass(frozen=True)
class Change:
    name: str
    item_kind: str  # "registry" or "file"
    change_kind: str  # "added", "modified" or "removed"
    old_value: str | None
    new_value: str | None


Snapshot = dict[str, Item]


def compare(old: Mapping[str, Item], new: Mapping[str, Item]) -> list[Change]:
    """What changed from `old` to `new`, sorted by name."""
    changes = []
    for name in sorted(old.keys() | new.keys()):
        before = old.get(name)
        after = new.get(name)
        if before is None:
            changes.append(Change(name, after.kind, "added", None, after.value))
        elif after is None:
            changes.append(Change(name, before.kind, "removed", before.value, None))
        elif before != after:
            changes.append(Change(name, after.kind, "modified", before.value, after.value))
    return changes


def encode_registry_data(data: object) -> str:
    """Registry data as text: bytes as hex, lists one item per line, nothing as empty."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        return "\n".join(str(entry) for entry in data)
    return str(data)


@dataclass(frozen=True)
class KeyContents:
    values: tuple[tuple[str, object, int], ...] = ()  # (name, data, registry type)
    subkeys: tuple[str, ...] = ()
    unreadable: bool = False


def read_key_tree(
    read_key: Callable[[str], KeyContents | None], name: str, subkey: str, subtree: bool
) -> Snapshot:
    """The values of a key, and with `subtree` those of every key below it.

    `read_key(path)` gives one key's contents, or None if it doesn't exist. Items are named
    <name>\\<subkeys>\\<value>, with (Default) for an unnamed value. A key that can't be
    read, and a tree that is too big, each add an item that says so. A gap then shows up
    as a change, not as silence. This has no Windows-only code, so it can be tested in WSL.
    """
    items: Snapshot = {}
    pending = [(subkey, name, 0)]
    visited = 0
    while pending:
        path, shown, depth = pending.pop()
        contents = read_key(path)
        if contents is None:
            continue
        visited += 1
        if contents.unreadable:
            items[f"{shown}\\({UNREADABLE})"] = Item("registry", UNREADABLE)
            continue
        for value_name, data, reg_type in contents.values:
            items[f"{shown}\\{value_name or '(Default)'}"] = Item(
                "registry", encode_registry_data(data), reg_type
            )
        if not subtree:
            continue
        if visited >= MAX_TREE_KEYS or depth >= MAX_TREE_DEPTH:
            if contents.subkeys:
                items[f"{shown}\\({TRUNCATED})"] = Item("registry", TRUNCATED)
            continue
        for child in contents.subkeys:
            pending.append((f"{path}\\{child}", f"{shown}\\{child}", depth + 1))
    return items


def hash_file(path: str | Path) -> str:
    """The file's SHA-256, or UNREADABLE. A writer can hold a file for a moment, so retry."""
    for attempt in range(READ_ATTEMPTS):
        try:
            with open(path, "rb") as file:
                return hashlib.file_digest(file, "sha256").hexdigest()
        except OSError:
            if attempt + 1 < READ_ATTEMPTS:
                time.sleep(READ_RETRY_SECONDS)
    return UNREADABLE


def scan_folder(target: FolderTarget) -> Snapshot:
    """The files directly in the folder. A missing folder is empty, not an error."""
    items: Snapshot = {}
    try:
        entries = list(os.scandir(target.path))
    except (FileNotFoundError, NotADirectoryError):
        return items
    for entry in entries:
        if not entry.is_file():
            continue
        if target.only_file and entry.name.lower() != target.only_file:
            continue
        items[entry.path] = Item("file", hash_file(entry.path))
    return items


def create_baseline(folder: Path, snapshot: Snapshot) -> None:
    """Save the approved state, with a copy of each file for Phase 3 to restore from.

    Refuses to replace a baseline: the baseline defines what is trusted, so replacing
    it must be a deliberate step, not a side effect of running a command twice.
    """
    baseline_path = folder / "baseline.json"
    if baseline_path.exists():
        raise FileExistsError(f"{baseline_path} already exists. Delete it first to replace it.")

    files = folder / "files"
    files.mkdir(parents=True, exist_ok=True)
    for name, item in snapshot.items():
        if item.kind == "file" and item.value != UNREADABLE:
            shutil.copyfile(name, files / item.value)

    data = {
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "items": {name: asdict(item) for name, item in snapshot.items()},
    }
    partial = baseline_path.with_suffix(".json.tmp")
    partial.write_text(json.dumps(data, indent=2), encoding="utf-8")
    partial.replace(baseline_path)  # a crash can't leave a half-written baseline


def load_baseline(folder: Path) -> Snapshot:
    data = json.loads((folder / "baseline.json").read_text(encoding="utf-8"))
    return {name: Item(**item) for name, item in data["items"].items()}
