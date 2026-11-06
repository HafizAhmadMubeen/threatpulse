"""python -m backend.pipeline <session folder>... --out <dir> [--labels <dir>] [--scan-files]

Replays recorded sessions. It only reads the session folders and refuses an --out inside
one. Real recordings must go to a gitignored folder such as data/runs/.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from backend.pipeline.output import write_merged, write_session
from backend.pipeline.run import run_session


def expand(folders: list[Path]) -> list[Path]:
    """A session folder has events.jsonl. A batch folder has session folders in it."""
    sessions = []
    for folder in folders:
        if (folder / "events.jsonl").is_file():
            sessions.append(folder)
        else:
            sessions += sorted(p for p in folder.iterdir() if (p / "events.jsonl").is_file())
    return sessions


def line(summary: dict) -> str:
    rules = ", ".join(f"{r} x{n}" for r, n in summary["alerts_by_rule"].items()) or "no alerts"
    return (f"{summary['session_id']:42} {str(summary['label']):9} {summary['events']:6} ev  "
            f"{summary['alerts']:3} alerts  {summary['decisions']:3} decisions  "
            f"{summary['reports']:2} reports  {rules}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay recorded sessions through the pipeline.")
    parser.add_argument("sessions", nargs="+", type=Path, help="session folders, or batch folders")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--labels", type=Path, action="append",
                        help="labels folder, for the summary only. Repeat it: the first folder with a session wins")
    parser.add_argument("--scan-files", action="store_true",
                        help="also run scan_file on process images that exist on this machine (for the VM)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    sessions = expand(args.sessions)
    if not sessions:
        parser.error("no session folders found")
    out = args.out.resolve()
    for folder in [*args.sessions, *sessions]:
        if out == folder.resolve() or folder.resolve() in out.parents:
            parser.error(f"--out must not be inside an input folder: {folder}")

    print("NOTE: score_process and write_report are STUBS: every risk_score is null, and decisions stay pending.",
          file=sys.stderr)
    results, summaries = [], []
    for folder in sessions:
        result = run_session(folder, scan_files=args.scan_files)
        summary = write_session(result, folder, out, args.labels)
        results.append((result, folder))
        summaries.append(summary)
        print(line(summary))
    if len(results) > 1:
        merged = write_merged(results, out)
        print(f"merged view: {merged}")
    totals = {k: sum(s[k] for s in summaries) for k in ("events", "alerts", "decisions", "reports")}
    (out / "summary.json").write_text(json.dumps({"totals": totals, "sessions": summaries}, indent=2), encoding="utf-8")
    print(f"{len(summaries)} sessions: {totals['alerts']} alerts, {totals['decisions']} decisions, {totals['reports']} reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
