"""Which rules fire on recorded sessions: python -m detection.session_report <folder>... --out <dir>

Reads sessions and writes a report. It never changes a session folder, and the report
goes to --out only, which must not be inside any of the folders it reads.

On a benign session every alert is a false positive. On an attack session an alert is a
detection if its evidence is in the test part of the labels, and otherwise it comes from
the harness (the wrapper that runs the test) or from background activity.
"""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from detection.behaviour import RuleEngine, sort_events
from detection.timeline import read_jsonl


def read_labels(folder: Path) -> dict[str, dict]:
    path = folder / "labels.csv"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8", newline="") as stream:
        return {row["event_id"]: row for row in csv.DictReader(stream)}


def part_of(row: dict | None) -> str:
    """Labels v2 have a part column. Before that, malicious is all there is."""
    if row is None:
        return "unlabelled"
    return row.get("part") or ("malicious" if row["label"] == "malicious" else row["label"])


def report_session(folder: Path) -> dict:
    session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    events = read_jsonl(folder / "events.jsonl")[0] + read_jsonl(folder / "fim.jsonl")[0]
    labels = read_labels(folder)
    engine = RuleEngine()
    alerts = []
    for event in sort_events(events):
        alerts += engine.process(event)

    rows = []
    for alert in alerts:
        parts = Counter(part_of(labels.get(event_id)) for event_id in alert["evidence_event_ids"])
        rows.append(
            {
                "rule_id": alert["rule_id"],
                "ts": alert["ts"],
                "event_type": alert["event_type"],
                "pid": alert["subject"]["pid"],
                "part": parts.most_common(1)[0][0] if parts else "none",
                "evidence": len(alert["evidence_event_ids"]),
                "key": alert["object"]["registry_key"] or alert["object"]["path"],
            }
        )
    return {
        "session_id": session["session_id"],
        "test_id": session.get("test_id"),
        "label": session["label"],
        "pool": session["pool"],
        "network": session["network"],
        "events": len(events),
        "rejected": engine.rejected,
        "alerts": rows,
    }


def summary_line(result: dict) -> str:
    counts = Counter((row["rule_id"], row["part"]) for row in result["alerts"])
    fired = ", ".join(f"{rule} x{n} [{part}]" for (rule, part), n in sorted(counts.items())) or "nothing"
    return (f"{result['session_id']}  {result['label']:9} {result['pool']:18} "
            f"{result['events']:6} events  {result['rejected']} rejected  ->  {fired}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report which rules fire on recorded sessions.")
    parser.add_argument("sessions", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="folder for the report")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    for folder in args.sessions:
        if out == folder.resolve() or folder.resolve() in out.parents:
            parser.error(f"--out must not be inside a session folder: {folder}")
    out.mkdir(parents=True, exist_ok=True)
    results = [report_session(folder) for folder in sorted(args.sessions)]
    for result in results:
        print(summary_line(result))
    (out / "session_report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
