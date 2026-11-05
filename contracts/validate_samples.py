#!/usr/bin/env python3
"""Check the shared sample files in contracts/samples/.

Usage: python contracts/validate_samples.py [samples_dir]

Three kinds of check:
- every sample validates against its schema in contracts/schemas/
- the files agree with each other: IDs are unique and every reference resolves,
  which a schema for one object can't check
- every file in samples/invalid/ fails. The name's first word selects the schema,
  for example alert_bad_layer.json. These are .json, not .jsonl, because .gitignore
  ignores .jsonl below contracts/samples/.

Exit code 0 means valid, 1 means problems were found, 2 means a file could not be read.
"""

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

CONTRACTS_DIR = Path(__file__).resolve().parent
SCHEMA_DIR = CONTRACTS_DIR / "schemas"
SAMPLES_DIR = CONTRACTS_DIR / "samples"
KINDS = ("event", "alert", "decision", "report")
ATTRIBUTE_FIELDS = ("signed", "trusted_path")


def load_validators(schema_dir: Path = SCHEMA_DIR) -> dict[str, Draft202012Validator]:
    validators = {}
    for kind in KINDS:
        schema = json.loads((schema_dir / f"{kind}.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validators[kind] = Draft202012Validator(schema)
    return validators


def schema_errors(validator: Draft202012Validator, instance: object, label: str) -> list[str]:
    problems = []
    for error in validator.iter_errors(instance):
        location = "/".join(str(part) for part in error.absolute_path) or "(root)"
        problems.append(f"{label}: {location}: {error.message}")
    return problems


def load_jsonl(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def load_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def repeated(items: list[dict], key: str) -> list[str]:
    seen = set()
    problems = []
    for item in items:
        value = item.get(key)
        if value in seen:
            problems.append(f"{key} {value} repeats")
        seen.add(value)
    return problems


def suffix(identifier: str) -> str:
    return identifier.split("-", 1)[-1]


def check_alert_links(alert: dict, events: dict[str, dict]) -> list[str]:
    alert_id = alert["alert_id"]
    problems = []
    evidence = []
    for event_id in alert["evidence_event_ids"]:
        if event_id in events:
            evidence.append(events[event_id])
        else:
            problems.append(f"{alert_id}: evidence {event_id} is not in events.jsonl")
    if not evidence:
        return problems

    if alert["event_type"] not in {event["event_type"] for event in evidence}:
        problems.append(f"{alert_id}: no evidence event has type {alert['event_type']}")

    subject = alert["subject"]
    if subject["pid"] == 0:
        return problems
    own_events = [event for event in evidence if event["pid"] == subject["pid"]]
    if not own_events:
        problems.append(f"{alert_id}: no evidence event comes from subject pid {subject['pid']}")
    for event in own_events:
        if event["process"]["image"] != subject["image"]:
            problems.append(f"{alert_id}: {event['event_id']} has a different image from the subject")
        if subject["ancestors"] and event["ppid"] != subject["ancestors"][0]["pid"]:
            problems.append(f"{alert_id}: {event['event_id']} has a different parent from the subject")
    return problems


def check_decision_links(decision: dict, alert: dict) -> list[str]:
    decision_id = decision["decision_id"]
    problems = []
    if suffix(decision_id) != suffix(alert["alert_id"]):
        problems.append(f"{decision_id}: counter differs from {alert['alert_id']}")
    attributes = decision["attributes"]
    if attributes["zone"] != alert["object"]["zone"]:
        problems.append(f"{decision_id}: zone differs from {alert['alert_id']}")
    if attributes["risk_score"] != alert["risk_score"]:
        problems.append(f"{decision_id}: risk_score differs from {alert['alert_id']}")
    for field in ATTRIBUTE_FIELDS:
        if attributes[field] != alert["subject"][field]:
            problems.append(f"{decision_id}: {field} differs from {alert['alert_id']}")
    return problems


def check_report_links(report: dict, alert: dict) -> list[str]:
    report_id = report["report_id"]
    problems = []
    if suffix(report_id) != suffix(alert["alert_id"]):
        problems.append(f"{report_id}: counter differs from {alert['alert_id']}")
    for technique in report["techniques"]:
        if technique["id"] not in alert["technique_ids"]:
            problems.append(f"{report_id}: {technique['id']} is not on {alert['alert_id']}")
    return problems


def check_references(
    events: list[dict], alerts: list[dict], decisions: list[dict], reports: list[dict]
) -> list[str]:
    problems = repeated(events, "event_id") + repeated(alerts, "alert_id")
    problems += repeated(decisions, "decision_id") + repeated(reports, "report_id")
    # One alert has one decision and one report: GET /reports/{alert_id} returns a single one.
    problems += repeated(decisions, "alert_id") + repeated(reports, "alert_id")

    events_by_id = {event["event_id"]: event for event in events}
    alerts_by_id = {alert["alert_id"]: alert for alert in alerts}
    for alert in alerts:
        problems += check_alert_links(alert, events_by_id)
    for decision in decisions:
        alert = alerts_by_id.get(decision["alert_id"])
        if alert is None:
            problems.append(f"{decision['decision_id']}: {decision['alert_id']} is not in alerts.json")
        else:
            problems += check_decision_links(decision, alert)
    for report in reports:
        alert = alerts_by_id.get(report["alert_id"])
        if alert is None:
            problems.append(f"{report['report_id']}: {report['alert_id']} is not in alerts.json")
        else:
            problems += check_report_links(report, alert)
    return problems


def check_coverage(
    validators: dict[str, Draft202012Validator],
    events: list[dict],
    alerts: list[dict],
    decisions: list[dict],
) -> list[str]:
    """The samples must show every value, so no consumer meets one for the first time in the VM."""
    event_schema = validators["event"].schema["properties"]
    alert_schema = validators["alert"].schema["properties"]
    action_schema = validators["decision"].schema["$defs"]["action"]["properties"]["action"]
    wanted = {
        "event_type": (event_schema["event_type"]["enum"], {e["event_type"] for e in events}),
        "source": (event_schema["source"]["enum"], {e["source"] for e in events}),
        "layer": (alert_schema["layer"]["enum"], {a["layer"] for a in alerts}),
        "zone": (
            alert_schema["object"]["properties"]["zone"]["enum"],
            {a["object"]["zone"] for a in alerts},
        ),
        "action": (
            action_schema["enum"],
            {action["action"] for d in decisions for action in d["actions"]},
        ),
    }
    problems = []
    for name, (allowed, used) in wanted.items():
        for value in sorted(set(allowed) - used):
            problems.append(f"no sample uses {name} {value}")
    return problems


def check_invalid_samples(
    invalid_dir: Path, validators: dict[str, Draft202012Validator]
) -> list[str]:
    problems = []
    for path in sorted(invalid_dir.glob("*.json")):
        kind = path.name.split("_", 1)[0]
        if kind not in validators:
            problems.append(f"{path.name}: name must start with one of {', '.join(KINDS)}")
        elif not list(validators[kind].iter_errors(json.loads(path.read_text(encoding="utf-8")))):
            problems.append(f"{path.name}: should fail the {kind} schema but passes")
    return problems


def check_samples(samples_dir: Path = SAMPLES_DIR) -> list[str]:
    validators = load_validators()
    events = load_jsonl(samples_dir / "events.jsonl")
    alerts = load_json(samples_dir / "alerts.json")
    decisions = load_json(samples_dir / "decisions.json")
    reports = load_json(samples_dir / "reports.json")

    problems = []
    groups = (("event", events), ("alert", alerts), ("decision", decisions), ("report", reports))
    for kind, items in groups:
        for number, item in enumerate(items, 1):
            problems += schema_errors(validators[kind], item, f"{kind} {number}")
    if problems:
        return problems  # The other checks assume objects of the right shape.

    problems += check_references(events, alerts, decisions, reports)
    problems += check_coverage(validators, events, alerts, decisions)
    problems += check_invalid_samples(samples_dir / "invalid", validators)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the shared contract samples.")
    parser.add_argument("samples_dir", type=Path, nargs="?", default=SAMPLES_DIR)
    args = parser.parse_args(argv)
    try:
        problems = check_samples(args.samples_dir)
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(problem)
    print(f"{len(problems)} problem(s) in {args.samples_dir}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
