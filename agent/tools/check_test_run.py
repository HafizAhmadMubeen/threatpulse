#!/usr/bin/env python3
"""Check events.jsonl after a run of vm_test_activity.ps1.

Usage: python agent/tools/check_test_run.py <events.jsonl> <test_pid.txt>

Exit code 0 means every check passed, 1 means at least one failed.

A write with no path can't be placed in a folder, so "every write under the
Documents test folder has a path" is checked through the process that made them:
every write by the test process must have a path.

ETW and Sysmon can report the same action, so each check names the source it proves.
"""

import argparse
import json
import sys
from pathlib import Path

TEST_FOLDER = "\\documents\\threatpulsetest"
RUN_ROOT = "hkcu\\software\\microsoft\\windows\\currentversion\\"
RUN_KEY = RUN_ROOT + "run\\threatpulsetest"
RUN_ONCE_KEY = RUN_ROOT + "runonce\\threatpulsetest"
EXPECTED_FILES = 25
WEB_PORT = 443
DUMMY_MASK = "0x21410"


def load_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as lines:
        return [json.loads(line) for line in lines if line.strip()]


def path_of(event: dict) -> str:
    return (event["target"]["path"] or "").lower()


def key_of(event: dict) -> str:
    return (event["target"]["registry_key"] or "").lower()


def in_test_folder(event: dict) -> bool:
    return TEST_FOLDER + "\\" in path_of(event)


def run_checks(events: list[dict], test_pid: int) -> list[tuple[str, bool, str]]:
    def of_type(event_type: str, source: str = "etw") -> list[dict]:
        return [
            event for event in events
            if event["event_type"] == event_type and event["source"] == source
        ]

    def registry(event_type: str, source: str, key: str) -> list[dict]:
        return [event for event in of_type(event_type, source) if key_of(event) == key]

    def connections(source: str) -> list[dict]:
        return [
            event for event in of_type("network_connect", source)
            if event["pid"] == test_pid and event["target"]["dest_port"] == WEB_PORT
        ]

    creates = [event for event in of_type("file_create") if in_test_folder(event)]
    folder_writes = [event for event in of_type("file_write") if in_test_folder(event)]
    test_writes = [event for event in of_type("file_write") if event["pid"] == test_pid]
    test_pathless = [event for event in test_writes if not event["target"]["path"]]
    renames = [event for event in of_type("file_rename") if in_test_folder(event)]
    deletes = [event for event in of_type("file_delete") if in_test_folder(event)]
    run_keys = registry("registry_set", "etw", RUN_KEY)

    deleted = {path_of(event).rsplit("\\", 1)[-1] for event in deletes}
    originals = {f"dummy{number}.txt" for number in range(1, EXPECTED_FILES + 1)}
    written = {path_of(event).rsplit("\\", 1)[-1] for event in folder_writes}
    folder_reported = any(path_of(event).endswith(TEST_FOLDER) for event in of_type("file_delete"))
    good_renames = [
        event for event in renames
        if path_of(event).endswith("\\renamed.locked")
        and (event["target"]["old_path"] or "").lower().endswith("\\dummy1.locked")
    ]

    stale_writes = []
    if good_renames:
        after_rename = events[events.index(good_renames[0]) + 1:]
        stale_writes = [
            event for event in after_rename
            if event["event_type"] == "file_write"
            and path_of(event).endswith("\\dummy1.locked")
        ]

    sysmon_run = registry("registry_set", "sysmon", RUN_KEY)
    sysmon_run_once = registry("registry_set", "sysmon", RUN_ONCE_KEY)
    sysmon_delete = registry("registry_delete", "sysmon", RUN_KEY)

    etw_connections = connections("etw")
    sysmon_connections = connections("sysmon")
    etw_ips = {event["target"]["dest_ip"] for event in etw_connections}
    sysmon_ips = {event["target"]["dest_ip"] for event in sysmon_connections}

    dummy_access = [
        event for event in of_type("process_access", "sysmon")
        if event["pid"] == test_pid
        and path_of(event).endswith("\\ping.exe")
        and event["target"]["pid"]
        and str(event["target"]["access_mask"]).lower() == DUMMY_MASK
        and "vm_read" in (event["target"]["access_rights"] or [])
    ]

    return [
        ("Run key has the full key", bool(run_keys), f"{len(run_keys)} events"),
        ("files created in the test folder", len(creates) >= EXPECTED_FILES, f"{len(creates)} events"),
        ("writes under the test folder have paths", len(folder_writes) >= EXPECTED_FILES,
         f"{len(folder_writes)} events"),
        ("every test process write has a path", bool(test_writes) and not test_pathless,
         f"{len(test_writes) - len(test_pathless)} of {len(test_writes)}"),
        ("rename has new path and old_path", bool(good_renames), f"{len(good_renames)} events"),
        ("write after rename reports the new name", "renamed.locked" in written, ""),
        ("no write after rename reports the old name", not stale_writes,
         f"{len(stale_writes)} events"),
        ("file_delete for every original", originals <= deleted,
         f"{len(originals & deleted)} of {len(originals)}"),
        ("file_delete for the delete-on-close file", "delete-on-close.tmp" in deleted, ""),
        ("the folder itself is not a file_delete", not folder_reported, ""),
        ("Sysmon: registry_set for the HKCU Run key", bool(sysmon_run),
         f"{len(sysmon_run)} events"),
        ("Sysmon: registry_set for the HKCU RunOnce key", bool(sysmon_run_once),
         f"{len(sysmon_run_once)} events"),
        ("Sysmon: registry_delete for the HKCU Run key", bool(sysmon_delete),
         f"{len(sysmon_delete)} events"),
        ("ETW: network_connect to port 443 by the test process", bool(etw_connections),
         f"{len(etw_connections)} events"),
        ("Sysmon: network_connect to port 443 by the test process", bool(sysmon_connections),
         f"{len(sysmon_connections)} events"),
        ("ETW and Sysmon report the same destination IP", bool(etw_ips & sysmon_ips),
         f"etw {sorted(etw_ips)}, sysmon {sorted(sysmon_ips)}"),
        ("Sysmon: process_access on the dummy process has vm_read", bool(dummy_access),
         f"{len(dummy_access)} events"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a run of vm_test_activity.ps1.")
    parser.add_argument("events", type=Path)
    parser.add_argument("pid_file", type=Path)
    args = parser.parse_args()

    # Set-Content writes this file with the system code page, which is plain digits.
    test_pid = int(args.pid_file.read_text(encoding="utf-8-sig").strip())
    results = run_checks(load_events(args.events), test_pid)

    for label, passed, detail in results:
        suffix = f" ({detail})" if detail else ""
        print(f"{'PASS' if passed else 'FAIL'}  {label}{suffix}")

    failed = sum(1 for _, passed, _ in results if not passed)
    print(f"\n{len(results) - failed} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
