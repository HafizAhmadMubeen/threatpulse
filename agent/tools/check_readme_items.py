#!/usr/bin/env python3
"""Check three agent/README.md items in one go, from one events.jsonl.

Usage: python agent/tools/check_readme_items.py <events.jsonl>

Exit code 0 means every check passed, 1 means at least one failed.

The last check can only show that nothing got through: a process that wrote nothing
looks the same as one that was dropped. `threatpulse_agent --check-image` gives the
direct answer, and `activity` shows that those processes were at least running.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CMD_IMAGE = "c:\\windows\\system32\\cmd.exe"
CMD_SIGNER = "Microsoft Windows"
AGENT_NAME = "threatpulse_agent"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
FILTERED_PREFIXES = (
    "c:\\program files\\windows defender\\",
    "c:\\programdata\\microsoft\\windows defender\\platform\\",
    "c:\\windows\\sysmon64.exe",
)
# Only these event types can be dropped by the process filter.
FILTERED_TYPES = {
    "file_create",
    "file_write",
    "file_rename",
    "file_delete",
    "registry_set",
}


def load_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as lines:
        return [json.loads(line) for line in lines if line.strip()]


def image_of(event: dict) -> str:
    return event["process"]["image"].lower()


def good_cmd_start(event: dict) -> bool:
    process = event["process"]
    return (
        process["signed"] is True
        and process["signer"] == CMD_SIGNER
        and bool(SHA256.match(process["sha256"] or ""))
    )


def run_checks(events: list[dict]) -> list[tuple[str, bool, str]]:
    cmd_starts = [
        event for event in events
        if event["event_type"] == "process_start" and image_of(event) == CMD_IMAGE
    ]
    bad_cmd = [event for event in cmd_starts if not good_cmd_start(event)]
    own = [event for event in events if AGENT_NAME in image_of(event)]

    filtered_images = [event for event in events if image_of(event).startswith(FILTERED_PREFIXES)]
    leaked = [
        event for event in filtered_images
        if event["source"] == "etw" and event["event_type"] in FILTERED_TYPES
    ]

    return [
        ("cmd.exe is signed by Microsoft Windows, with a SHA-256", bool(cmd_starts) and not bad_cmd,
         f"{len(cmd_starts) - len(bad_cmd)} of {len(cmd_starts)} starts"),
        ("no event has the agent as its process", not own, f"{len(own)} events"),
        ("no file or registry event from Defender or Sysmon got through", not leaked,
         f"{len(leaked)} events, activity: {len(filtered_images) - len(leaked)} other events"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check three agent/README.md items.")
    parser.add_argument("events", type=Path)
    args = parser.parse_args()

    results = run_checks(load_events(args.events))
    for label, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {label} ({detail})")

    failed = sum(1 for _, passed, _ in results if not passed)
    print(f"\n{len(results) - failed} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
