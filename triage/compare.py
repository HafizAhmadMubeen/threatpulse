"""Tables that put training reports side by side: python -m triage.compare LABEL=report.json ...

Every rate is a count with its 95% interval (triage/metrics.show). Reads reports only.
"""

import argparse
import json
import sys
from pathlib import Path

from triage.metrics import show

MODES = ("complete", "snapshots")


def at(group: dict, threshold: float) -> dict:
    return next(t for t in group["by_threshold"] if t["threshold"] == threshold)


def attacks(c: dict) -> str:
    return show(c["tp"], c["tp"] + c["fn"])


def benign(c: dict) -> str:
    return show(c["fp"], c["fp"] + c["tn"])


def pooled_table(reports: dict[str, dict], mode: str) -> list[str]:
    labels = list(reports)
    rows = [f"| {mode} model, summed over the held-out batches | " + " | ".join(labels) + " |",
            "|---|" + "---|" * len(labels)]

    def row(name: str, get) -> None:
        rows.append(f"| {name} | " + " | ".join(get(reports[label]["pooled"][mode]) for label in labels) + " |")

    for key, title in (("fixed_0.5", "at 0.50"), ("fixed_0.8", "at 0.80"), ("chosen_on_training_folds", "at the threshold chosen on training folds")):
        row(f"Ordinary attacks caught, {title}", lambda p, k=key: attacks(p["test"][k]))
        row(f"Benign trees flagged, {title}", lambda p, k=key: benign(p["test"][k]))
    for key, title in (("fixed_0.8", "at 0.80"), ("chosen_on_training_folds", "at the threshold chosen on training folds")):
        row(f"Held-out attacks caught, {title}", lambda p, k=key: attacks(p["held_out_techniques"][k]) if p["held_out_techniques"][k] else "none")
        row(f"Held-out benign flagged, {title}", lambda p, k=key: benign(p["held_out_techniques"][k]) if p["held_out_techniques"][k] else "none")
    row("T1003.001 flagged at 0.80 (NOT in recall)", lambda p: f"{p['documented_limitation']['flagged_at_0.8']} of {p['documented_limitation']['trees']}")
    row("Attacks still flagged at 0.50 on 25 to 75% of their span", lambda p: show(p["attacks_flagged_early_25_to_75_percent"]["flagged"], p["attacks_flagged_early_25_to_75_percent"]["of"]))
    row("Benign trees flagged early only", lambda p: show(p["benign_flagged_early_only_25_to_75_percent"]["flagged"], p["benign_flagged_early_only_25_to_75_percent"]["of"]))
    row("Benign-session alerts at or above 0.80 when they fire", lambda p: show(p["alert_time"]["benign_session_alerts_at_or_above_0.8"]["alert_time"], p["alert_time"]["benign_session_alerts_at_or_above_0.8"]["of"]))
    row("Malicious-session alerts at or above 0.80 when they fire", lambda p: show(p["alert_time"]["malicious_session_alerts_at_or_above_0.8"]["alert_time"], p["alert_time"]["malicious_session_alerts_at_or_above_0.8"]["of"]))
    return rows


def fold_table(label: str, report: dict, mode: str) -> list[str]:
    rows = [f"{label}, {mode} model, one row per test batch (the model never saw that batch):", "",
            "| Test batch | Threshold chosen on training folds | Ordinary attacks caught at 0.80 | Benign flagged at 0.80 | Held-out caught at 0.80 | T1003.001 score (events) |",
            "|---|---|---|---|---|---|"]
    for fold in report["folds"]:
        m = fold["models"][mode]
        chosen = m["threshold_chosen_on_training_folds"]
        held = m["held_out_techniques"]
        held_text = attacks(at(held, 0.8)) if held["trees"] else "none"
        lim = ", ".join(f"{i['score']} ({i['n_events']})" for i in m["documented_limitation"]["items"]) or "none"
        rows.append(f"| {fold['test_batch']} | {chosen['threshold']}{'' if chosen['met_fpr_cap'] else ' (cap not met)'} | "
                    f"{attacks(at(m['test'], 0.8))} | {benign(at(m['test'], 0.8))} | {held_text} | {lim} |")
    return rows


def markdown(reports: dict[str, dict]) -> str:
    out: list[str] = []
    for mode in MODES:
        out += pooled_table(reports, mode) + [""]
    for label, report in reports.items():
        for mode in MODES:
            out += fold_table(label, report, mode) + [""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare training reports.")
    parser.add_argument("reports", nargs="+", metavar="LABEL=report.json")
    args = parser.parse_args(argv)
    reports = {}
    for item in args.reports:
        label, _, path = item.partition("=")
        if not path:
            parser.error("give each report as LABEL=path")
        reports[label] = json.loads(Path(path).read_text(encoding="utf-8"))
    print(markdown(reports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
