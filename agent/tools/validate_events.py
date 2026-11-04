#!/usr/bin/env python3
"""Check a recorded events.jsonl against contracts/schemas/event.schema.json.

Usage: python agent/tools/validate_events.py <events.jsonl> [--max-errors N]

Checks every line against the Event schema, and checks that event_id values are
unique, which a per-line schema cannot do. Exit code 0 means valid, 1 means
problems were found, 2 means the file or schema could not be read.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "contracts" / "schemas" / "event.schema.json"


def load_validator(schema_path: Path) -> Draft202012Validator:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def find_line_problems(line: str, validator: Draft202012Validator) -> tuple[dict | None, list[str]]:
    """Return the parsed event (if it is JSON) and any problems found on this line."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        return None, [f"not valid JSON: {error}"]

    problems = []
    for error in sorted(validator.iter_errors(event), key=lambda item: list(item.absolute_path)):
        location = "/".join(str(part) for part in error.absolute_path) or "(root)"
        problems.append(f"{location}: {error.message}")
    return event, problems


def validate_file(events_path: Path, validator: Draft202012Validator, max_errors: int) -> int:
    """Print a report and return the number of invalid lines."""
    event_types: Counter[str] = Counter()
    seen_ids: dict[str, int] = {}
    total = 0
    invalid = 0

    with events_path.open(encoding="utf-8") as lines:
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            total += 1
            event, problems = find_line_problems(line, validator)

            if isinstance(event, dict):
                event_types[str(event.get("event_type"))] += 1
                event_id = event.get("event_id")
                if isinstance(event_id, str):
                    if event_id in seen_ids:
                        problems.append(f"event_id {event_id} repeats line {seen_ids[event_id]}")
                    else:
                        seen_ids[event_id] = number

            if problems:
                invalid += 1
                if invalid <= max_errors:
                    for problem in problems:
                        print(f"line {number}: {problem}")

    if invalid > max_errors:
        print(f"... {invalid - max_errors} more invalid lines not shown")

    print(f"\n{total} events, {invalid} invalid")
    for event_type, count in sorted(event_types.items()):
        print(f"  {event_type}: {count}")

    if total == 0:
        print("The file has no events.")
        return 1
    return invalid


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate events.jsonl against the Event schema.")
    parser.add_argument("events", type=Path, help="path to the JSONL file")
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH, help="schema file to use")
    parser.add_argument("--max-errors", type=int, default=20, help="invalid lines to print")
    args = parser.parse_args()

    try:
        validator = load_validator(args.schema)
        return 1 if validate_file(args.events, validator, args.max_errors) else 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"Cannot read input: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
