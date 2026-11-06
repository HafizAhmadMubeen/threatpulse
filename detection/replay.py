"""Replay recorded events through the behaviour rules: python -m detection.replay <events.jsonl> ...

Reads the files, merges them by time, and prints the alerts as JSON. This changes nothing,
so it's safe anywhere. It is how the rules are checked against a recorded session.
"""

import argparse
import json
from pathlib import Path

from detection.behaviour import RuleEngine, sort_events
from detection.timeline import read_jsonl


def replay(events: list[dict], engine: RuleEngine | None = None) -> list[dict]:
    """Sorts first, because the agents write events out of time order."""
    engine = engine or RuleEngine()
    alerts: list[dict] = []
    for event in sort_events(events):
        alerts += engine.process(event)
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay events through the behaviour rules.")
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    events: list[dict] = []
    for path in args.files:
        events += read_jsonl(path)[0]
    engine = RuleEngine()
    alerts = replay(events, engine)
    print(json.dumps(alerts, indent=2))
    print(f"{len(events)} events, {len(alerts)} alerts, {engine.rejected} rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
