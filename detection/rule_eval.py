"""Evaluate the behaviour rules (match_rules) on recorded batches.

python -m detection.rule_eval --batch N SESSIONS LABELS ... --out DIR [--only-labelled]

READ-ONLY and rule-neutral: it replays each session through a fresh RuleEngine and counts
what fires. It never changes a rule, a threshold, a session folder or a labels folder, and
a test checks the rule files byte for byte.

What counts:
- An attack session's alert is "in the test part" when most of its evidence events are
  labelled part=test. Alerts from the harness (the wrapper that runs a test) or from
  background activity are counted apart and are never detections. FIM alerts carry no
  label, so they are placed by time instead: inside the session's test window (start_utc to
  end_utc) or not. The report says which rows are window-based.
- A technique is "detected" in a session when a rule written for that technique fired in the
  test part. A rule of another technique firing there is listed as a cross-fire, not a hit.
- A benign session is a false positive source for any alert inside its window (start_utc to
  end_utc). Alerts before start_utc (sensor start-up and warm-up) or after end_utc are
  counted apart.

IN-SAMPLE. Which batches each rule was written or tuned against is in RULE_HISTORY and
BATCH_STATUS below, taken from git and from the docs, and printed with every report.
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from contracts.validate_samples import load_validators
from detection.behaviour import RuleEngine, load_rules, sort_events
from detection.timeline import parse_ts, read_jsonl
from triage.metrics import show


# From git: `git log -- rules/behaviour/*.yaml` lists one commit, 9a68638 (2026-11-06 19:00
# +0500). No rule file has changed since, after any batch.
RULE_HISTORY = {
    "written": "9a68638, 2026-11-06 19:00 +0500, from the design (PLANNING.md, ATT&CK) and tests that build their own events",
    "yaml_changed_since": False,
    "thresholds": "starting guesses, never tuned (detection/README.md): 10 deletes or renames in 30 s (T1486), "
                  "connect then write within 30 s (T1105)",
    "engine_change_after_data": {
        "commit": "5959aee (2026-11-06 19:19 +0500), after replaying batch 1",
        "what": "de-duplication ignores case, because ETW and Sysmon spell one registry key differently",
        "affects": ["R-T1547-001", "R-T1547-002", "R-T1685-001"],  # rules whose dedupe_by holds a text field
    },
}
# Honest status of each batch for the rules. "seen" means the results were looked at and
# written up, with nothing changed.
BATCH_STATUS = {
    1: "IN-SAMPLE: replayed while the rules were being finished. It produced the de-duplication fix, and the "
       "README's first-real-recordings notes. No rule or threshold changed.",
    2: "SEEN, not tuned: replayed through the orchestrator work, which noted the R-T1486-001 false positive "
       "on the benign zip session. Nothing was changed.",
    3: "OUT-OF-SAMPLE: not looked at before this evaluation.",
    4: "OUT-OF-SAMPLE: not looked at before this evaluation.",
}
OUT_OF_SAMPLE = (3, 4)


def written_or_tuned_against(rule_id: str) -> str:
    """One line per rule: what it was written from and which batches are in-sample for it."""
    if rule_id in RULE_HISTORY["engine_change_after_data"]["affects"]:
        return "design and synthetic events; batch 1 IN-SAMPLE (de-duplication fixed after replaying it); batch 2 seen; batches 3 and 4 out-of-sample"
    extra = {
        "R-T1486-001": "; threshold 10 in 30 s is a guess, batch 2's zip false positive was seen and not tuned",
        "R-T1003-002": "; added from the LSA-protection design (PLANNING.md 4.3), not from data",
    }.get(rule_id, "")
    return f"design and synthetic events; nothing tuned; batches 1 and 2 seen; batches 3 and 4 out-of-sample{extra}"


class RuleEvalError(ValueError):
    pass


def read_labels(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8", newline="") as stream:
        return {row["event_id"]: row for row in csv.DictReader(stream)}


def part_of(row: dict | None) -> str:
    if row is None:
        return "unlabelled"
    return row.get("part") or row["label"]


def session_folders(sessions_dir: Path, labels_dir: Path, only_labelled: bool) -> list[Path]:
    folders = sorted(p for p in sessions_dir.iterdir() if (p / "events.jsonl").is_file())
    if only_labelled:
        folders = [p for p in folders if (labels_dir / p.name / "labels.csv").is_file()]
    return folders


def seconds(stamp: str) -> float:
    return parse_ts(stamp).timestamp()


def evaluate_session(folder: Path, labels_dir: Path, batch: int) -> dict:
    session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    if session.get("batch") != batch:
        raise RuleEvalError(f"{folder.name}: session.json says batch {session.get('batch')}, expected {batch}")
    labels = read_labels(labels_dir / folder.name / "labels.csv")
    if not labels:
        raise RuleEvalError(f"{folder.name}: no labels in {labels_dir}")
    if "part" not in next(iter(labels.values())):
        raise RuleEvalError(f"{folder.name}: labels have no part column")
    validator = load_validators()["event"]
    agent, _ = read_jsonl(folder / "events.jsonl")
    fim, _ = read_jsonl(folder / "fim.jsonl")
    events = [e for e in (*agent, *fim) if validator.is_valid(e)]
    skipped = len(agent) + len(fim) - len(events)  # invalid against the Event schema: counted, never silent
    techniques = {rule.id: rule.techniques for rule in load_rules()}
    start, end = seconds(session["start_utc"]), seconds(session["end_utc"])

    engine = RuleEngine()
    rows = []
    for event in sort_events(events):
        for alert in engine.process(event):
            when = seconds(alert["ts"])
            parts = Counter(part_of(labels.get(i)) for i in alert["evidence_event_ids"])
            by_window = alert["layer"] == "fim"  # FIM events carry no label
            part = "test" if by_window and start <= when <= end else (
                "fim-outside-test-window" if by_window else (parts.most_common(1)[0][0] if parts else "none"))
            rows.append({
                "rule_id": alert["rule_id"], "layer": alert["layer"], "ts": alert["ts"], "part": part,
                "placed_by_window": by_window,
                "when": "before_start" if when < start else "after_end" if when > end else "in_window",
                "techniques": list(techniques.get(alert["rule_id"], ())),
            })
    return {"session_id": session["session_id"], "batch": batch, "label": session["label"],
            "technique": session.get("technique"), "pool": session["pool"], "events": len(events),
            "skipped_invalid_events": skipped, "rejected": engine.rejected, "alerts": rows}


def evaluate(spec: list[tuple[int, Path, Path]], only_labelled: bool) -> dict:
    sessions = []
    for batch, sessions_dir, labels_dir in spec:
        for folder in session_folders(sessions_dir, labels_dir, only_labelled):
            sessions.append(evaluate_session(folder, labels_dir, batch))
    if not sessions:
        raise RuleEvalError("no sessions")
    return {"rules": {r.id: list(r.techniques) for r in load_rules()}, "history": RULE_HISTORY,
            "batch_status": {str(k): v for k, v in BATCH_STATUS.items()}, "sessions": sessions,
            "summary": summarise(sessions)}


# ---- aggregation ---------------------------------------------------------------------------


def hit(rows: list[dict], rule_techniques: dict[str, list[str]], technique: str | None) -> bool:
    """A rule written for the session's technique fired in the test part, inside the window."""
    return any(r["part"] == "test" and r["when"] == "in_window" and technique in rule_techniques.get(r["rule_id"], [])
               for r in rows)


def summarise(sessions: list[dict]) -> dict:
    rule_techniques = {r.id: list(r.techniques) for r in load_rules()}
    attacks = [s for s in sessions if s["label"] == "malicious"]
    benign = [s for s in sessions if s["label"] == "benign"]

    per_technique = {}
    for technique in sorted({s["technique"] for s in attacks}):
        mine = [s for s in attacks if s["technique"] == technique]
        entry = {"sessions": len(mine), "by_batch": {}, "rules_fired_in_test_part": {}, "harness_alerts": {}, "background_alerts": {}}
        fired, harness, background = Counter(), Counter(), Counter()
        for s in mine:
            detected = hit(s["alerts"], rule_techniques, technique)
            entry["by_batch"][str(s["batch"])] = entry["by_batch"].get(str(s["batch"]), {"sessions": 0, "detected": 0})
            entry["by_batch"][str(s["batch"])]["sessions"] += 1
            entry["by_batch"][str(s["batch"])]["detected"] += int(detected)
            for a in s["alerts"]:
                if a["when"] != "in_window":
                    continue
                (fired if a["part"] == "test" else harness if a["part"] == "harness" else background)[a["rule_id"]] += 1
        entry["detected"] = sum(v["detected"] for v in entry["by_batch"].values())
        entry["detected_out_of_sample_batches_3_4"] = {
            "detected": sum(v["detected"] for b, v in entry["by_batch"].items() if int(b) in OUT_OF_SAMPLE),
            "sessions": sum(v["sessions"] for b, v in entry["by_batch"].items() if int(b) in OUT_OF_SAMPLE)}
        entry["rules_fired_in_test_part"] = dict(sorted(fired.items()))
        entry["harness_alerts"] = dict(sorted(harness.items()))
        entry["background_alerts"] = dict(sorted(background.items()))
        per_technique[technique] = entry

    per_rule = {}
    for rule_id, techniques in rule_techniques.items():
        own = [s for s in attacks if s["technique"] in techniques]
        cross = [s for s in attacks if s["technique"] not in techniques]
        fired_own = [s for s in own if any(a["rule_id"] == rule_id and a["part"] == "test" and a["when"] == "in_window" for a in s["alerts"])]
        fired_cross = [s for s in cross if any(a["rule_id"] == rule_id and a["part"] == "test" and a["when"] == "in_window" for a in s["alerts"])]
        benign_fired = [s for s in benign if any(a["rule_id"] == rule_id and a["when"] == "in_window" for a in s["alerts"])]
        per_rule[rule_id] = {
            "techniques": techniques,
            "own_technique_sessions": len(own), "fired_in_test_part_of_own": len(fired_own),
            "fired_in_test_part_of_own_batches_3_4": {
                "fired": sum(1 for s in fired_own if s["batch"] in OUT_OF_SAMPLE),
                "sessions": sum(1 for s in own if s["batch"] in OUT_OF_SAMPLE)},
            "cross_fired_in_test_part_of_other_techniques": sorted({s["technique"] for s in fired_cross}),
            "attack_sessions_total": len(attacks),
            "benign_sessions": len(benign), "benign_sessions_with_alert": len(benign_fired),
            "benign_alerts": sum(1 for s in benign for a in s["alerts"] if a["rule_id"] == rule_id and a["when"] == "in_window"),
            "benign_sessions_with_alert_batches_3_4": {
                "with_alert": sum(1 for s in benign_fired if s["batch"] in OUT_OF_SAMPLE),
                "sessions": sum(1 for s in benign if s["batch"] in OUT_OF_SAMPLE)},
            "harness_alerts": sum(1 for s in attacks for a in s["alerts"] if a["rule_id"] == rule_id and a["part"] == "harness" and a["when"] == "in_window"),
            "background_alerts_in_attack_sessions": sum(1 for s in attacks for a in s["alerts"] if a["rule_id"] == rule_id and a["part"] not in ("test", "harness") and a["when"] == "in_window"),
            "placed_by_window_only": rule_id.startswith("R-FIM"),
            "written_or_tuned_against": written_or_tuned_against(rule_id),
        }

    by_batch = defaultdict(lambda: {"sessions": 0, "with_alert": 0})
    for s in benign:
        by_batch[str(s["batch"])]["sessions"] += 1
        by_batch[str(s["batch"])]["with_alert"] += int(any(a["when"] == "in_window" for a in s["alerts"]))
    outside = Counter(a["when"] for s in sessions for a in s["alerts"] if a["when"] != "in_window")
    outside_detail = Counter((a["when"], a["rule_id"], s["label"], a["part"]) for s in sessions for a in s["alerts"]
                             if a["when"] != "in_window")
    oos = [v for b, v in by_batch.items() if int(b) in OUT_OF_SAMPLE]
    return {
        "attack_sessions": len(attacks), "benign_sessions": len(benign),
        "benign_sessions_with_any_alert": sum(v["with_alert"] for v in by_batch.values()),
        "benign_by_batch": dict(sorted(by_batch.items())),
        "benign_sessions_detail": [{"session": s["session_id"], "batch": s["batch"],
                                    "alerts": dict(Counter(a["rule_id"] for a in s["alerts"] if a["when"] == "in_window"))}
                                   for s in benign],
        "benign_sessions_with_any_alert_batches_3_4": {"with_alert": sum(v["with_alert"] for v in oos),
                                                       "sessions": sum(v["sessions"] for v in oos)},
        "alerts_outside_the_window": dict(outside),
        "alerts_outside_the_window_detail": [
            {"when": w, "rule_id": r, "session_label": label, "part": part, "alerts": n}
            for (w, r, label, part), n in sorted(outside_detail.items())],
        "events_replayed": sum(s["events"] for s in sessions),
        "events_skipped_as_invalid": sum(s["skipped_invalid_events"] for s in sessions),
        "events_rejected_by_the_engine": sum(s["rejected"] for s in sessions),
        "per_technique": per_technique, "per_rule": per_rule,
    }


# ---- text ----------------------------------------------------------------------------------


def markdown(result: dict) -> str:
    sm, history = result["summary"], result["history"]
    lines = ["## Where each rule comes from (in-sample or not)", "",
             f"- Written: {history['written']}.", f"- Rule files changed since: {'yes' if history['yaml_changed_since'] else 'no, never'}.",
             f"- Thresholds: {history['thresholds']}.",
             f"- Engine change made after data: {history['engine_change_after_data']['commit']}: "
             f"{history['engine_change_after_data']['what']}. Affects {', '.join(history['engine_change_after_data']['affects'])}.", ""]
    lines += ["| Batch | Status for the rules |", "|---|---|"] + [f"| {b} | {t} |" for b, t in result["batch_status"].items()]
    lines += ["", "## Per technique: which rules fired in the test part", "",
              "| Technique | Detected (a rule for it fired in the test part) | Batches 3 and 4 only (out-of-sample) | Rules fired in the test part (alerts) | Harness alerts | Background alerts |",
              "|---|---|---|---|---|---|"]
    for technique, e in sm["per_technique"].items():
        oos = e["detected_out_of_sample_batches_3_4"]
        fmt = lambda d: ", ".join(f"{k} x{v}" for k, v in d.items()) or "none"  # noqa: E731
        lines.append(f"| {technique} | {show(e['detected'], e['sessions'])} | {show(oos['detected'], oos['sessions']) if oos['sessions'] else 'no sessions'} | "
                     f"{fmt(e['rules_fired_in_test_part'])} | {fmt(e['harness_alerts'])} | {fmt(e['background_alerts'])} |")
    lines += ["", "## Per rule", "",
              "| Rule | Written or tuned against | Techniques | Fired in the test part of its own technique | of which batches 3 and 4 | Cross-fired in another technique's test part | Benign sessions with this rule | Benign alerts | Harness alerts | Background alerts (attack sessions) |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for rule_id, r in sm["per_rule"].items():
        oos = r["fired_in_test_part_of_own_batches_3_4"]
        own = show(r["fired_in_test_part_of_own"], r["own_technique_sessions"]) if r["own_technique_sessions"] else "no sessions of its own technique"
        note = " (by time window, FIM has no labels)" if r["placed_by_window_only"] else ""
        lines.append(f"| {rule_id} | {r['written_or_tuned_against']} | {', '.join(r['techniques']) or 'none'} | {own}{note} | "
                     f"{(str(oos['fired']) + ' of ' + str(oos['sessions'])) if oos['sessions'] else 'none'} | "
                     f"{', '.join(r['cross_fired_in_test_part_of_other_techniques']) or 'none'} | "
                     f"{show(r['benign_sessions_with_alert'], r['benign_sessions'])} | {r['benign_alerts']} | "
                     f"{r['harness_alerts']} | {r['background_alerts_in_attack_sessions']} |")
    lines += ["", "## Benign sessions", "",
              f"Benign sessions with any alert in their window: {show(sm['benign_sessions_with_any_alert'], sm['benign_sessions'])}. "
              f"Batches 3 and 4 only (out-of-sample): {show(sm['benign_sessions_with_any_alert_batches_3_4']['with_alert'], sm['benign_sessions_with_any_alert_batches_3_4']['sessions'])}.", "",
              "| Batch | Benign sessions with any alert |", "|---|---|"]
    lines += [f"| {b} | {show(v['with_alert'], v['sessions'])} |" for b, v in sm["benign_by_batch"].items()]
    lines += ["", "| Benign session | Batch | Alerts by rule (in the window) |", "|---|---|---|"]
    for d in sm["benign_sessions_detail"]:
        lines.append(f"| {d['session']} | {d['batch']} | {', '.join(f'{k} x{v}' for k, v in sorted(d['alerts'].items())) or 'none'} |")
    outside = sm["alerts_outside_the_window"]
    lines += ["", f"Events replayed: {sm['events_replayed']}. Skipped as invalid against the Event schema: "
                  f"{sm['events_skipped_as_invalid']}. Rejected by the engine as malformed: {sm['events_rejected_by_the_engine']}."]
    lines += ["", f"Alerts outside a session's window (before start_utc or after end_utc), not counted above: "
                  f"{', '.join(f'{k} {v}' for k, v in sorted(outside.items())) or 'none'}."]
    if sm["alerts_outside_the_window_detail"]:
        lines += ["", "| Outside the window | Rule | Session | Part | Alerts |", "|---|---|---|---|---|"]
        lines += [f"| {d['when']} | {d['rule_id']} | {d['session_label']} | {d['part']} | {d['alerts']} |"
                  for d in sm["alerts_outside_the_window_detail"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the behaviour rules on recorded batches (read-only).")
    parser.add_argument("--batch", nargs=3, action="append", metavar=("NUMBER", "SESSIONS", "LABELS"), required=True)
    parser.add_argument("--only-labelled", action="store_true")
    parser.add_argument("--out", type=Path, required=True, help="where rule_eval.json and rule_eval.md go (not inside an input)")
    args = parser.parse_args(argv)
    spec = [(int(n), Path(s), Path(l)) for n, s, l in args.batch]
    out = args.out.resolve()
    for _, sessions, labels in spec:
        for folder in (sessions.resolve(), labels.resolve()):
            if out == folder or folder in out.parents:
                parser.error(f"--out must not be inside an input folder: {folder}")
    try:
        result = evaluate(spec, args.only_labelled)
    except RuleEvalError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "rule_eval.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "rule_eval.md").write_text(markdown(result), encoding="utf-8")
    print(markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
