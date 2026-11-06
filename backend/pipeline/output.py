"""Writes a replayed session where the backend can serve it, and the summaries.

The backend reads one folder: events.jsonl, fim.jsonl, alerts.json, decisions.json and
reports.json. Copies of the recording are written there because the dashboard shows an
alert's evidence events. Real recordings stay under the gitignored data/runs/.
"""

import csv
import json
import shutil
from collections import Counter
from pathlib import Path

from backend.pipeline.run import SessionResult
from contracts.validate_samples import load_validators
from detection.session_report import part_of, read_labels
from detection.timeline import read_jsonl

FIM_NOTE = (
    "APPROXIMATION: the VM's baseline.json is not in the exported recordings, so an item's "
    "baseline is taken to be what the first reported FIM change replaced."
)


class OutputError(ValueError):
    pass


def check_valid(kind: str, items: list[dict]) -> None:
    validator = load_validators()[kind]
    for item in items:
        errors = [e.message for e in validator.iter_errors(item)]
        if errors:
            raise OutputError(f"invalid {kind}: {errors[0]}")


def label_source(folder: Path, labels_dirs: list[Path] | Path | None) -> Path | None:
    """The first labels folder that has this session, else None (the session's own file)."""
    if isinstance(labels_dirs, Path):
        labels_dirs = [labels_dirs]
    for directory in labels_dirs or []:
        if (directory / folder.name / "labels.csv").is_file():
            return directory / folder.name
    return None


def labels_for(folder: Path, labels_dirs: list[Path] | Path | None) -> dict[str, dict]:
    return read_labels(label_source(folder, labels_dirs) or folder)


def summarise(result: SessionResult, labels: dict[str, dict], labels_used: str) -> dict:
    alerts, decisions = result.alerts, result.decisions
    actions = [a for d in decisions for a in d["actions"]]
    summary = {
        "session_id": result.session["session_id"],
        "label": result.session.get("label"),
        "pool": result.session.get("pool"),
        "test_id": result.session.get("test_id"),
        "events": result.events,
        "fim_events": result.fim_events,
        "skipped_events": result.skipped_events,
        "rejected_by_rules": result.rejected_by_rules,
        "alerts": len(alerts),
        "decisions": len(decisions),
        "reports": len(result.reports),
        "alerts_by_rule": dict(sorted(Counter(a["rule_id"] for a in alerts).items())),
        "decisions_by_rule": dict(sorted(Counter(r for d in decisions for r in d["policy_rules"]).items())),
        "actions": dict(sorted(Counter(f"{a['action']}:{a['status']}" for a in actions).items())),
        "notes": {
            "scorer": "STUB: score_process returns None, so every risk_score is null",
            "report_writer": "STUB: no LLM call",
            "suspended_pids": "always empty: nothing is executed, decisions stay pending",
            "fim_baseline": FIM_NOTE,
            "microsoft_root": (
                f"{result.microsoft_root_events} of {result.events + result.fim_events} events carry "
                "process.microsoft_root; 0 means every process is 'unknown' to the never-suspend check"
            ),
            "labels": labels_used,
        },
    }
    if labels:
        by_part: dict[str, Counter] = {}
        for alert in alerts:
            parts = Counter(part_of(labels.get(i)) for i in alert["evidence_event_ids"])
            part = parts.most_common(1)[0][0] if parts else "none"
            by_part.setdefault(part, Counter())[alert["rule_id"]] += 1
        summary["alerts_by_part"] = {p: dict(sorted(c.items())) for p, c in sorted(by_part.items())}
        summary["note_labels"] = "labels are used for this summary only, never by a decision"
    return summary


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_session(result: SessionResult, folder: Path, out: Path, labels_dir: list[Path] | Path | None) -> dict:
    """Validates everything first, then writes. Returns the summary."""
    check_valid("alert", result.alerts)
    check_valid("decision", result.decisions)
    check_valid("report", result.reports)
    target = out / result.session["session_id"]
    target.mkdir(parents=True, exist_ok=True)
    write_json(target / "alerts.json", result.alerts)
    write_json(target / "decisions.json", result.decisions)
    write_json(target / "reports.json", result.reports)
    for name in ("events.jsonl", "fim.jsonl"):
        if (folder / name).is_file():
            shutil.copyfile(folder / name, target / name)
        elif (target / name).exists():
            (target / name).unlink()
    labels = labels_for(folder, labels_dir)
    source = label_source(folder, labels_dir)
    used = f"{source.parent.name}" if source else "the session's own labels.csv"
    summary = summarise(result, labels, used if labels else "none")
    write_json(target / "pipeline_summary.json", summary)
    return summary


def write_merged(results: list[tuple[SessionResult, Path]], out: Path) -> Path:
    """One folder with every session, so the dashboard shows them together. Alert and event
    IDs carry each recording's run start, so they can't meet. It holds all FIM events and
    only the evidence events of agent sources, not every event."""
    merged = out / "_all"
    merged.mkdir(parents=True, exist_ok=True)
    alerts, decisions, reports, events = [], [], [], []
    seen_alerts: set[str] = set()
    seen_events: set[str] = set()
    for result, folder in results:
        wanted = {i for alert in result.alerts for i in alert["evidence_event_ids"]}
        for alert in result.alerts:
            if alert["alert_id"] in seen_alerts:
                raise OutputError(f"alert ID {alert['alert_id']} appears in two sessions")
            seen_alerts.add(alert["alert_id"])
        for name in ("events.jsonl", "fim.jsonl"):
            for event in read_jsonl(folder / name)[0]:
                event_id = event.get("event_id")
                if name == "fim.jsonl" or event_id in wanted:
                    if event_id in seen_events:
                        raise OutputError(f"event ID {event_id} appears in two sessions")
                    seen_events.add(event_id)
                    events.append(event)
        alerts += result.alerts
        decisions += result.decisions
        reports += result.reports
    events.sort(key=lambda e: (e["ts"], e["event_id"]))
    write_json(merged / "alerts.json", alerts)
    write_json(merged / "decisions.json", decisions)
    write_json(merged / "reports.json", reports)
    (merged / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    (merged / "fim.jsonl").unlink(missing_ok=True)
    return merged
