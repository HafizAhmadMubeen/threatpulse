"""Train and evaluate the triage model: python -m triage.train --batch N SESSIONS LABELS ... --out DIR

Reads the exported batches (read-only) and writes a report. For each labelled batch in turn
it trains on the OTHER batches and tests on that one (whole-batch split). Held-out
techniques are only ever in the test side, and are reported separately.

Two models are trained per fold, so the skew between partial and complete trees can be
compared like for like:
  complete   one row per complete process tree (the first version)
  snapshots  one row per snapshot of each tree as it grew (triage/dataset.py)
The model that score_process uses is the snapshot model, trained on all labelled batches
and saved to triage/models/.

Every result here is PRELIMINARY until all 11 batches exist. With a few positive trees per
batch, a rate is a few counts, and its interval says so.
"""

import argparse
import json
import logging
import statistics
import sys
from pathlib import Path

from backend.pipeline import run_session
from contracts.validate_samples import load_validators
from detection.timeline import read_jsonl
from triage import model as model_module
from triage import score as score_module
from triage.dataset import (HELD_OUT_TECHNIQUES, MIN_SNAPSHOT_EVENTS, SNAPSHOT_FRACTIONS, DatasetError, Tree,
                            balance_table, evaluation_trees, load_batch, session_folders, snapshot_rows,
                            snapshot_training_rows, training_trees, unlabelled_sessions)
from triage.features import events_of_tree_containing, tree_feature_row
from triage.metrics import confusion

log = logging.getLogger(__name__)

THRESHOLDS = (0.5, 0.8)  # 0.50 = dashboard "alert", 0.80 = policy auto_contain
TOP_NEGATIVES = 5
MODES = ("complete", "snapshots")


def preliminary_banner(batch_count: int, positives: int) -> str:
    return (f"PRELIMINARY: {batch_count} of 11 batches and {positives} training positives (complete trees) in total. "
            "These numbers show that the pipeline works. They do not say how well it detects.")


def training_rows(mode: str, trees: list[Tree]) -> list[dict]:
    return [t.row for t in trees] if mode == "complete" else snapshot_training_rows(trees)


def describe(tree: Tree, score: float) -> dict:
    return {"session": tree.row["session_id"], "technique": tree.row["technique"] or None,
            "n_events": tree.row["n_events"], "score": round(score, 4)}


def evaluate_group(booster, trees: list[Tree]) -> dict:
    """Complete trees: the same view the first version of this report had."""
    if not trees:
        return {"trees": 0}
    scores = model_module.predict(booster, [t.row for t in trees])
    flags = [t.positive for t in trees]
    negatives = sorted(((s, t) for s, t in zip(scores, trees) if not t.positive), key=lambda p: -p[0])
    return {
        "trees": len(trees),
        "positives": sum(flags),
        "negatives": len(flags) - sum(flags),
        "by_threshold": [confusion(scores, flags, threshold) for threshold in THRESHOLDS],
        "positive_scores": [describe(t, s) for s, t in zip(scores, trees) if t.positive],
        "top_negative_scores": [describe(t, s) for s, t in negatives[:TOP_NEGATIVES]],
    }


def snapshot_evaluation(booster, trees: list[Tree], snaps: dict[str, list[tuple[float, dict]]]) -> dict:
    """Score every tree at each point of its growth and compare with the complete tree.

    by_fraction: precision, recall and false-positive rate on the snapshots at that fraction.
    skew: how far the partial score is from the complete-tree score (|difference|), the share
    of attacks still flagged at 0.5 early on, and how many benign trees were flagged early
    that the complete tree is not."""
    by_fraction, skew = [], []
    mismatch = 0.0
    full = {}
    for tree in trees:
        for fraction, row in snaps[tree.row["tree_id"]]:
            if fraction == 1.0:
                full[tree.row["tree_id"]] = None  # filled below
    flat = [(tree, fraction, row) for tree in trees for fraction, row in snaps[tree.row["tree_id"]]]
    scores = model_module.predict(booster, [row for _, _, row in flat])
    scored = {(tree.row["tree_id"], fraction): s for (tree, fraction, _), s in zip(flat, scores)}
    for tree in trees:  # the scoring path and the training path must agree on the complete tree
        key = (tree.row["tree_id"], 1.0)
        if key in scored:
            mismatch = max(mismatch, abs(scored[key] - model_module.predict(booster, [tree.row])[0]))
            full[tree.row["tree_id"]] = scored[key]
    for fraction in SNAPSHOT_FRACTIONS:
        members = [(t, scored[(t.row["tree_id"], fraction)]) for t in trees if (t.row["tree_id"], fraction) in scored]
        if not members:
            continue
        flags = [t.positive for t, _ in members]
        values = [s for _, s in members]
        by_fraction.append({"fraction": fraction, "positives": sum(flags), "negatives": len(flags) - sum(flags),
                            "by_threshold": [confusion(values, flags, th) for th in THRESHOLDS]})
        if fraction == 1.0:
            continue
        entry = {"fraction": fraction}
        for name, wanted in (("positives", True), ("negatives", False)):
            diffs = [abs(s - full[t.row["tree_id"]]) for t, s in members
                     if t.positive == wanted and full.get(t.row["tree_id"]) is not None]
            entry[name] = ({"n": len(diffs), "median_abs_diff": round(statistics.median(diffs), 4),
                            "max_abs_diff": round(max(diffs), 4)} if diffs else {"n": 0})
        flagged_full = [(t, s) for t, s in members if t.positive and (full.get(t.row["tree_id"]) or 0) >= 0.5]
        entry["attacks_flagged_early"] = {"flagged": sum(1 for _, s in flagged_full if s >= 0.5), "of": len(flagged_full)}
        benign = [(t, s) for t, s in members if not t.positive and full.get(t.row["tree_id"]) is not None]
        entry["benign_flagged_early_only"] = {
            "flagged": sum(1 for t, s in benign if s >= 0.5 and full[t.row["tree_id"]] < 0.5), "of": len(benign)}
        skew.append(entry)
    return {"by_fraction": by_fraction, "skew": skew, "max_difference_serving_vs_training": round(mismatch, 8)}


def session_events(folder: Path) -> list[dict]:
    validator = load_validators()["event"]
    agent, _ = read_jsonl(folder / "events.jsonl")
    fim, _ = read_jsonl(folder / "fim.jsonl")
    return [e for e in (*agent, *fim) if validator.is_valid(e)]


def alert_time_skew(booster, folders: list[Path]) -> dict:
    """The pipeline's own view. Each alert is scored when it fires (a partial tree), and again
    on the whole of the same tree at the end of the recording. Both are label-free: the
    wrapper that runs each test is in both, which is the scorer's real situation."""
    rows, benign_high, attack_high = [], 0, 0
    for folder in folders:
        events = session_events(folder)
        result = run_session(folder, scorer=lambda tree: score_module.score_with(booster, tree))
        for alert in result.alerts:
            partial = alert["risk_score"]
            pid = alert["subject"]["pid"]
            if partial is None or pid <= 0:
                continue
            features = tree_feature_row(events_of_tree_containing(events, pid))
            if features is None:
                continue
            complete = model_module.predict_vector(booster, features)
            rows.append({"session": folder.name, "label": result.session.get("label"),
                         "alert_time": round(partial, 4), "complete": round(complete, 4)})
    diffs = [abs(r["alert_time"] - r["complete"]) for r in rows]
    group = lambda label, key: [r[key] for r in rows if r["label"] == label]  # noqa: E731
    count = lambda label, key: sum(1 for v in group(label, key) if v >= 0.8)  # noqa: E731
    return {
        "alerts_scored": len(rows),
        "median_abs_diff": round(statistics.median(diffs), 4) if diffs else None,
        "max_abs_diff": round(max(diffs), 4) if diffs else None,
        "alerts_in_benign_sessions": len(group("benign", "alert_time")),
        "benign_session_alerts_at_or_above_0.8": {"alert_time": count("benign", "alert_time"),
                                                  "complete_tree": count("benign", "complete")},
        "alerts_in_malicious_sessions": len(group("malicious", "alert_time")),
        "malicious_session_alerts_at_or_above_0.8": {"alert_time": count("malicious", "alert_time"),
                                                     "complete_tree": count("malicious", "complete")},
    }


def run(batches_spec: list[tuple[int, Path, Path]], save_to: Path | None, only_labelled: bool = False) -> dict:
    batches = {n: load_batch(n, sessions, labels, only_labelled) for n, sessions, labels in batches_spec}
    folders = {n: session_folders(sessions, labels, only_labelled) for n, sessions, labels in batches_spec}
    skipped = ({n: unlabelled_sessions(sessions, labels) for n, sessions, labels in batches_spec}
               if only_labelled else {})
    numbers = sorted(batches)
    if len(numbers) < 2:
        raise DatasetError("need at least two labelled batches to split by batch")
    all_training = training_trees(batches, numbers)
    positives = sum(t.positive for t in all_training)
    report = {
        "status": preliminary_banner(len(numbers), positives),
        "held_out_techniques": list(HELD_OUT_TECHNIQUES),
        "held_out_note": "T1685 has no recording yet, so held-out results cover the others only",
        "features": model_module.MODEL_FEATURES,
        "features_not_modelled": list(model_module.NOT_MODELLED),
        "params": {**model_module.PARAMS, "rounds": model_module.ROUNDS},
        "snapshots": {"fractions": list(SNAPSHOT_FRACTIONS), "min_events_for_a_partial_snapshot": MIN_SNAPSHOT_EVENTS},
        "balance": balance_table(batches),
        "sessions_left_out_for_having_no_labels": {str(n): names for n, names in skipped.items() if names},
        "folds": [],
    }
    for test in numbers:
        train_numbers = [n for n in numbers if n != test]
        trained = training_trees(batches, train_numbers)
        ordinary, held_out = evaluation_trees(batches[test])
        snaps = {t.row["tree_id"]: snapshot_rows(t) for t in ordinary + held_out}
        fold = {"train_batches": train_numbers, "test_batch": test, "models": {}}
        for mode in MODES:
            rows = training_rows(mode, trained)
            booster, info = model_module.train(rows)
            fold["models"][mode] = {
                "train": info,
                "test": evaluate_group(booster, ordinary),
                "held_out_techniques": evaluate_group(booster, held_out),
                "snapshots_of_test_trees": snapshot_evaluation(booster, ordinary, snaps),
                "snapshots_of_held_out_trees": snapshot_evaluation(booster, held_out, snaps),
                "alert_time_skew": alert_time_skew(booster, folders[test]),
            }
        report["folds"].append(fold)

    booster, info = model_module.train(training_rows("snapshots", all_training))
    report["final_model"] = {
        "trained_on_batches": numbers, "training": "prefix snapshots", **info,
        "note": "The snapshot model, trained on every training-pool tree of the labelled batches. It has no "
                "held-out evaluation of its own: the fold results above are the evidence, and they are preliminary.",
    }
    if save_to is not None:
        path = model_module.save(booster, save_to, {
            "status": report["status"], "trained_on_batches": numbers, "training": "prefix snapshots",
            "snapshot_fractions": list(SNAPSHOT_FRACTIONS), **info,
            "trained_sessions": sorted({t.row["session_id"] for t in all_training}),
            "held_out_techniques_excluded": list(HELD_OUT_TECHNIQUES),
        })
        score_module.reset_model()
        report["final_model"]["saved_to"] = str(path)
        report["final_model"]["sha256"] = model_module.sha256_of(path)
    return report


def fmt_rate(r: dict) -> str:
    return "n/a" if r["value"] is None else f"{r['value']:.2f} {r['ci95']} of {r['of']}"


def text_report(report: dict) -> str:
    lines = [report["status"], "", "Class balance (usable trees: start observed, harness left out):"]
    for n, names in report.get("sessions_left_out_for_having_no_labels", {}).items():
        lines.append(f"Batch {n}: {len(names)} session(s) left out, no labels (decided out): " + ", ".join(names))
    for row in report["balance"]:
        lines.append(f"  batch {row['batch']} {row['group']:9} positives {row['positive_trees']:3}  "
                     f"negatives {row['negative_trees']:4}  dropped (no start event) {row['unobserved_start_dropped']}")
    for fold in report["folds"]:
        lines += ["", f"=== Train on batches {fold['train_batches']}, test on batch {fold['test_batch']} ==="]
        for mode, m in fold["models"].items():
            lines.append(f"--- {mode} model ({m['train']['n_positive']} positive / {m['train']['n_negative']} negative training rows)")
            for name in ("test", "held_out_techniques"):
                group = m[name]
                if not group["trees"]:
                    lines.append(f"  {name}: no trees")
                    continue
                lines.append(f"  {name} (complete trees): {group['positives']} positive, {group['negatives']} negative")
                for c in group["by_threshold"]:
                    lines.append(f"    at {c['threshold']}: TP {c['tp']} FP {c['fp']} FN {c['fn']} TN {c['tn']}  precision "
                                 f"{fmt_rate(c['precision'])}  recall {fmt_rate(c['recall'])}  FPR {fmt_rate(c['false_positive_rate'])}")
                for p in group["positive_scores"]:
                    lines.append(f"    positive {p['technique']}: score {p['score']} ({p['n_events']} events)")
            snap = m["snapshots_of_test_trees"]
            lines.append("  snapshots of test trees, by how much of the tree is seen (at 0.5: recall, false positives):")
            for b in snap["by_fraction"]:
                c = b["by_threshold"][0]
                lines.append(f"    {b['fraction']:>4}: {b['positives']} pos / {b['negatives']} neg   TP {c['tp']} FN {c['fn']}  FP {c['fp']} of {b['negatives']}")
            lines.append("  skew to the complete tree (|difference|, attacks still flagged, benign flagged only early):")
            for s in snap["skew"]:
                pos, neg = s["positives"], s["negatives"]
                lines.append(f"    {s['fraction']:>4}: attacks median {pos.get('median_abs_diff')} max {pos.get('max_abs_diff')}, "
                             f"flagged {s['attacks_flagged_early']['flagged']}/{s['attacks_flagged_early']['of']};  "
                             f"benign median {neg.get('median_abs_diff')} max {neg.get('max_abs_diff')}, "
                             f"early-only {s['benign_flagged_early_only']['flagged']}/{s['benign_flagged_early_only']['of']}")
            a = m["alert_time_skew"]
            lines.append(f"  pipeline replay, alert-time vs complete tree ({a['alerts_scored']} scored alerts, median |diff| {a['median_abs_diff']}, max {a['max_abs_diff']}):")
            lines.append(f"    benign sessions: {a['alerts_in_benign_sessions']} alerts, at or above 0.8: alert-time "
                         f"{a['benign_session_alerts_at_or_above_0.8']['alert_time']}, complete tree {a['benign_session_alerts_at_or_above_0.8']['complete_tree']}")
            lines.append(f"    malicious sessions: {a['alerts_in_malicious_sessions']} alerts, at or above 0.8: alert-time "
                         f"{a['malicious_session_alerts_at_or_above_0.8']['alert_time']}, complete tree {a['malicious_session_alerts_at_or_above_0.8']['complete_tree']}")
    final = report["final_model"]
    lines += ["", final["note"]] + ([f"Model file SHA-256: {final['sha256']}"] if "sha256" in final else [])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and evaluate the triage model, split by batch.")
    parser.add_argument("--batch", nargs=3, action="append", metavar=("NUMBER", "SESSIONS", "LABELS"), required=True,
                        help="a batch number, its session folder, and its labels folder. Repeat per batch")
    parser.add_argument("--out", type=Path, required=True, help="where report.json and report.txt go (not inside an input)")
    parser.add_argument("--only-labelled", action="store_true",
                        help="leave out sessions that have no labels (a batch that holds a first attempt that was "
                             "decided out). They are listed by name in the report. Without it, a session "
                             "without labels stops the run")
    parser.add_argument("--no-save", action="store_true", help="do not write triage/models/")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    spec = [(int(n), Path(s), Path(l)) for n, s, l in args.batch]
    out = args.out.resolve()
    for _, sessions, labels in spec:
        for folder in (sessions.resolve(), labels.resolve()):
            if out == folder or folder in out.parents:
                parser.error(f"--out must not be inside an input folder: {folder}")
    try:
        report = run(spec, None if args.no_save else score_module.MODEL_DIR, args.only_labelled)
    except (DatasetError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "report.txt").write_text(text_report(report), encoding="utf-8")
    print(text_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
