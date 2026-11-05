#!/usr/bin/env python3
"""Check fim.jsonl after a run of vm_test_fim.ps1.

Usage: python agent/tools/check_fim_run.py <fim.jsonl> <fim_test_keys.txt> --events <events.jsonl>
       python agent/tools/check_fim_run.py <fim.jsonl> <fim_test_keys.txt> --poll-only

Exit code 0 means every check passed, 1 means at least one failed.

The first form also compares FIM's time with Sysmon's for the same Run key write, which
shows that a notification, not the 60-second compare, found it. Run the agent as well.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

VALUE_NAME = "threatpulsefimtest"
STARTUP_FILE = "threatpulse-fim-test.txt"
MAX_DELAY_SECONDS = 5.0


def load_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as lines:
        return [json.loads(line) for line in lines if line.strip()]


def key_of(event: dict) -> str:
    return (event["target"]["registry_key"] or "").lower()


def path_of(event: dict) -> str:
    return (event["target"]["path"] or "").lower()


def kind_of(event: dict) -> str:
    return event["target"]["change"]["kind"]


def seconds(event: dict) -> float:
    return datetime.fromisoformat(event["ts"].replace("Z", "+00:00")).timestamp()


def key_checks(fim: list[dict], keys: list[str]) -> list[tuple[str, bool, str]]:
    results = []
    for key in keys:
        name = f"{key}\\{VALUE_NAME}".lower()
        kinds = sorted(kind_of(event) for event in fim if key_of(event) == name)
        unchanged = [kind for kind in kinds if kind != "modified"]
        results.append((f"added and removed once: {key}", unchanged == ["added", "removed"], str(kinds)))
    return results


def writer_check(fim: list[dict]) -> tuple[str, bool, str]:
    claimed = [event for event in fim if event["pid"] != 0 or event["process"]["image"] != "unknown"]
    return ("no event claims a writer", not claimed, f"{len(claimed)} events")


def full_checks(fim: list[dict], keys: list[str], agent_events: list[dict]) -> list[tuple[str, bool, str]]:
    first_key = f"{keys[0]}\\{VALUE_NAME}".lower()
    modified = [event for event in fim if key_of(event) == first_key and kind_of(event) == "modified"]
    changed_value = bool(modified) and (modified[0]["target"]["change"]["new_value"] or "").endswith("/changed")

    hosts = [event for event in fim if path_of(event).endswith("\\drivers\\etc\\hosts")]
    hosts = sorted(hosts, key=lambda event: event["ts"])
    restored = (
        len(hosts) >= 2
        and all(kind_of(event) == "modified" for event in hosts)
        and hosts[0]["target"]["change"]["old_value"] == hosts[-1]["target"]["change"]["new_value"]
    )

    startup = [kind_of(event) for event in fim if path_of(event).endswith(f"\\{STARTUP_FILE}")]

    found = [event for event in fim if key_of(event) == first_key and kind_of(event) == "added"]
    sysmon = [
        event for event in agent_events
        if event["source"] == "sysmon" and event["event_type"] == "registry_set" and key_of(event) == first_key
    ]
    delay = abs(seconds(found[0]) - min(seconds(event) for event in sysmon)) if found and sysmon else None

    return [
        ("a changed Run value is modified, with its new data", changed_value, f"{len(modified)} events"),
        ("hosts changed, then restored to the first hash", restored, f"{len(hosts)} events"),
        ("startup file added once and removed once",
         startup.count("added") == 1 and startup.count("removed") == 1, str(startup)),
        ("startup file change seen", "modified" in startup, ""),
        (f"found within {MAX_DELAY_SECONDS:.0f} seconds of Sysmon's event",
         delay is not None and delay <= MAX_DELAY_SECONDS,
         "no matching events" if delay is None else f"{delay:.1f} seconds"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a run of vm_test_fim.ps1.")
    parser.add_argument("fim", type=Path)
    parser.add_argument("keys", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--events", type=Path, help="the agent's events.jsonl from the same period")
    mode.add_argument("--poll-only", action="store_true", help="after -Quick with --poll-only")
    args = parser.parse_args()

    fim = [event for event in load_events(args.fim) if event["event_type"] == "fim_change"]
    keys = [line.strip() for line in args.keys.read_text(encoding="utf-8-sig").splitlines() if line.strip()]

    results = key_checks(fim, keys)
    results.append(writer_check(fim))
    if args.events:
        results += full_checks(fim, keys, load_events(args.events))

    for label, passed, detail in results:
        suffix = f" ({detail})" if detail else ""
        print(f"{'PASS' if passed else 'FAIL'}  {label}{suffix}")

    failed = sum(1 for _, passed, _ in results if not passed)
    print(f"\n{len(results) - failed} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
