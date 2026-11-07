"""Train and evaluate the triage model: python -m triage.train --batch N SESSIONS LABELS ... --out DIR

Reads the exported batches (read-only) and writes a report. It is leave-one-batch-out: each
labelled batch is tested in turn by a model trained on all the OTHER batches (whole-batch
split, never by event or session). Held-out techniques are only ever on the test side and
are reported separately. T1003.001 is a documented limitation (LSA protection leaves its
test part with almost nothing to see): it is reported on its own and never counts toward
recall.

Two models are trained per fold, so the skew between partial and complete trees can be
compared like for like:
  complete   one row per complete process tree
  snapshots  one row per snapshot of each tree as it grew (triage/dataset.py)
The model that score_process uses is the snapshot model, trained on all labelled batches
and saved to triage/models/.

THRESHOLDS. The two fixed thresholds (0.50 alert, 0.80 policy auto_contain) are reported as
they are. A threshold is also PROPOSED, chosen by a rule fixed before any result was seen,
from training folds only:
  for the test batch B, train on the other batches, and run leave-one-batch-out INSIDE them;
  from the grid in THRESHOLD_GRID take the lowest value whose pooled inner false-positive
  rate is at most FPR_CAP (if none, the highest). Ordinary trees only: held-out techniques
  and T1003.001 are not used for choosing.
B's own trees are never looked at when choosing B's threshold. The threshold proposed for the
saved model uses leave-one-batch-out over all the labelled batches it is trained on, so its
own numbers are in-sample for that choice and are not a test result.

Every result is PRELIMINARY until all 11 batches exist.
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
from triage.dataset import (HELD_OUT_TECHNIQUES, LIMITATION_TECHNIQUES, MIN_SNAPSHOT_EVENTS, SNAPSHOT_FRACTIONS,
                            DatasetError, Tree, balance_table, evaluation_trees, limited_trees, load_batch,
                            session_folders, snapshot_rows, snapshot_training_rows, training_trees,
                            unlabelled_sessions)
from triage.features import events_of_tree_containing, tree_feature_row
from triage.metrics import confusion, pool, rate, show

log = logging.getLogger(__name__)

FIXED_THRESHOLDS = (0.5, 0.8)  # 0.50 = dashboard "alert", 0.80 = policy auto_contain
THRESHOLD_GRID = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)
FPR_CAP = 0.02  # at most 2% of benign trees flagged, pooled over the inner folds
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


# ---- choosing a threshold from training folds only -----------------------------------------


def choose_threshold(scores: list[float], flags: list[bool]) -> dict:
    """The lowest grid value whose false-positive rate on these trees is within FPR_CAP."""
    negatives = sum(1 for y in flags if not y)
    positives = len(flags) - negatives
    for threshold in THRESHOLD_GRID:
        fp = sum(1 for s, y in zip(scores, flags) if not y and s >= threshold)
        if negatives and fp / negatives <= FPR_CAP:
            tp = sum(1 for s, y in zip(scores, flags) if y and s >= threshold)
            return {"threshold": threshold, "met_fpr_cap": True, "fpr_cap": FPR_CAP,
                    "chosen_on": {"negatives": negatives, "false_positives": fp, "positives": positives, "true_positives": tp}}
    return {"threshold": THRESHOLD_GRID[-1], "met_fpr_cap": False, "fpr_cap": FPR_CAP,
            "chosen_on": {"negatives": negatives, "positives": positives}}


def inner_scores(mode: str, batches: dict[int, list[Tree]], train_numbers: list[int]) -> tuple[list[float], list[bool]]:
    """Leave-one-batch-out inside the training batches. Scores ordinary trees only."""
    scores, flags = [], []
    for held in train_numbers:
        others = [n for n in train_numbers if n != held]
        if not others:
            raise DatasetError("choosing a threshold needs at least two training batches")
        booster, _ = model_module.train(training_rows(mode, training_trees(batches, others)))
        ordinary, _ = evaluation_trees(batches[held])
        scores += model_module.predict(booster, [t.row for t in ordinary])
        flags += [t.positive for t in ordinary]
    return scores, flags


# ---- evaluation ----------------------------------------------------------------------------


def evaluate_group(booster, trees: list[Tree], chosen: float) -> dict:
    """Complete trees, at the two fixed thresholds and at the one chosen on the training folds."""
    if not trees:
        return {"trees": 0}
    scores = model_module.predict(booster, [t.row for t in trees])
    flags = [t.positive for t in trees]
    negatives = sorted(((s, t) for s, t in zip(scores, trees) if not t.positive), key=lambda p: -p[0])
    by_threshold = []
    for threshold in sorted({*FIXED_THRESHOLDS, chosen}):
        by_threshold.append({**confusion(scores, flags, threshold), "chosen_on_training_folds": threshold == chosen})
    return {
        "trees": len(trees),
        "positives": sum(flags),
        "negatives": len(flags) - sum(flags),
        "by_threshold": by_threshold,
        "positive_scores": [describe(t, s) for s, t in zip(scores, trees) if t.positive],
        "top_negative_scores": [describe(t, s) for s, t in negatives[:TOP_NEGATIVES]],
    }


def evaluate_limited(booster, trees: list[Tree], chosen: float) -> dict:
    """The documented limitation (T1003.001): scored and listed, never part of recall."""
    scores = model_module.predict(booster, [t.row for t in trees])
    thresholds = sorted({*FIXED_THRESHOLDS, chosen})
    return {"trees": len(trees),
            "items": [describe(t, s) for t, s in zip(trees, scores)],
            "flagged": {str(th): sum(1 for s in scores if s >= th) for th in thresholds}}


def snapshot_evaluation(booster, trees: list[Tree], snaps: dict[str, list[tuple[float, dict]]]) -> dict:
    """Score every tree at each point of its growth and compare with the complete tree.

    by_fraction: precision, recall and false-positive rate on the snapshots at that fraction.
    skew: how far the partial score is from the complete-tree score (|difference|), the share
    of attacks still flagged at 0.5 early on, and how many benign trees were flagged early
    that the complete tree is not."""
    by_fraction, skew = [], []
    mismatch = 0.0
    full = {}
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
                            "by_threshold": [confusion(values, flags, th) for th in FIXED_THRESHOLDS]})
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
    wrapper that runs each test is in both, which is the scorer's real situation. Alerts of
    T1003.001 sessions are counted apart (documented limitation)."""
    rows = []
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
                         "limitation": result.session.get("technique") in LIMITATION_TECHNIQUES,
                         "alert_time": round(partial, 4), "complete": round(complete, 4)})
    main = [r for r in rows if not r["limitation"]]
    diffs = [abs(r["alert_time"] - r["complete"]) for r in main]
    group = lambda label, key: [r[key] for r in main if r["label"] == label]  # noqa: E731
    count = lambda label, key: sum(1 for v in group(label, key) if v >= 0.8)  # noqa: E731
    return {
        "alerts_scored": len(main),
        "median_abs_diff": round(statistics.median(diffs), 4) if diffs else None,
        "max_abs_diff": round(max(diffs), 4) if diffs else None,
        "alerts_in_benign_sessions": len(group("benign", "alert_time")),
        "benign_session_alerts_at_or_above_0.8": {"alert_time": count("benign", "alert_time"),
                                                  "complete_tree": count("benign", "complete")},
        "alerts_in_malicious_sessions": len(group("malicious", "alert_time")),
        "malicious_session_alerts_at_or_above_0.8": {"alert_time": count("malicious", "alert_time"),
                                                     "complete_tree": count("malicious", "complete")},
        "documented_limitation_alerts": [{"alert_time": r["alert_time"], "complete": r["complete"]}
                                         for r in rows if r["limitation"]],
    }


# ---- pooling the folds ---------------------------------------------------------------------


def pooled_summary(report_folds: list[dict], mode: str) -> dict:
    """Sums over the held-out batches. Each batch was scored by a different model, so these
    are not one model's result. Counts first, every rate with its interval."""
    models = [f["models"][mode] for f in report_folds]
    out: dict = {}
    for name in ("test", "held_out_techniques"):
        groups = [m[name] for m in models if m[name]["trees"]]
        entry = {}
        for key, pick in (("fixed_0.5", lambda t: t["threshold"] == 0.5), ("fixed_0.8", lambda t: t["threshold"] == 0.8),
                          ("chosen_on_training_folds", lambda t: t["chosen_on_training_folds"])):
            entry[key] = pool([next(t for t in g["by_threshold"] if pick(t)) for g in groups]) if groups else None
        out[name] = entry
    limited = [m["documented_limitation"] for m in models if m["documented_limitation"]["trees"]]
    out["documented_limitation"] = {
        "trees": sum(g["trees"] for g in limited),
        "flagged_at_0.5": sum(g["flagged"]["0.5"] for g in limited),
        "flagged_at_0.8": sum(g["flagged"]["0.8"] for g in limited),
        "scores": [i["score"] for g in limited for i in g["items"]],
    }
    flagged = of = early_only = benign_of = 0
    for m in models:
        for s in m["snapshots_of_test_trees"]["skew"]:
            if s["fraction"] in (0.25, 0.5, 0.75):
                flagged += s["attacks_flagged_early"]["flagged"]
                of += s["attacks_flagged_early"]["of"]
                early_only += s["benign_flagged_early_only"]["flagged"]
                benign_of += s["benign_flagged_early_only"]["of"]
    out["attacks_flagged_early_25_to_75_percent"] = {"flagged": flagged, "of": of}
    out["benign_flagged_early_only_25_to_75_percent"] = {"flagged": early_only, "of": benign_of}
    alerts = [m["alert_time_skew"] for m in models]
    out["alert_time"] = {
        "benign_session_alerts_at_or_above_0.8": {"alert_time": sum(a["benign_session_alerts_at_or_above_0.8"]["alert_time"] for a in alerts),
                                                  "of": sum(a["alerts_in_benign_sessions"] for a in alerts)},
        "malicious_session_alerts_at_or_above_0.8": {"alert_time": sum(a["malicious_session_alerts_at_or_above_0.8"]["alert_time"] for a in alerts),
                                                     "of": sum(a["alerts_in_malicious_sessions"] for a in alerts)},
    }
    return out


def run(batches_spec: list[tuple[int, Path, Path]], save_to: Path | None, only_labelled: bool = False) -> dict:
    batches = {n: load_batch(n, sessions, labels, only_labelled) for n, sessions, labels in batches_spec}
    folders = {n: session_folders(sessions, labels, only_labelled) for n, sessions, labels in batches_spec}
    skipped = ({n: unlabelled_sessions(sessions, labels) for n, sessions, labels in batches_spec}
               if only_labelled else {})
    numbers = sorted(batches)
    if len(numbers) < 3:
        raise DatasetError("leave-one-batch-out with a threshold chosen on the training folds needs at least three batches")
    all_training = training_trees(batches, numbers)
    positives = sum(t.positive for t in all_training)
    report = {
        "status": preliminary_banner(len(numbers), positives),
        "scheme": "leave-one-batch-out",
        "held_out_techniques": list(HELD_OUT_TECHNIQUES),
        "held_out_note": "T1685 has no recording yet, so held-out results cover the others only",
        "documented_limitation": {
            "techniques": list(LIMITATION_TECHNIQUES),
            "note": "LSA protection blocks the dump, so the test part has about 2 events. Reported on its own, "
                    "never counted toward recall. These trees are still in training.",
        },
        "features": model_module.MODEL_FEATURES,
        "features_not_modelled": list(model_module.NOT_MODELLED),
        "params": {**model_module.PARAMS, "rounds": model_module.ROUNDS},
        "snapshots": {"fractions": list(SNAPSHOT_FRACTIONS), "min_events_for_a_partial_snapshot": MIN_SNAPSHOT_EVENTS},
        "threshold_rule": {"grid": list(THRESHOLD_GRID), "fpr_cap": FPR_CAP,
                           "rule": "the lowest grid value whose pooled false-positive rate, in leave-one-batch-out "
                                   "inside the training batches, is at most the cap. Training folds only."},
        "balance": balance_table(batches),
        "sessions_left_out_for_having_no_labels": {str(n): names for n, names in skipped.items() if names},
        "folds": [],
    }
    out_of_fold: dict[str, tuple[list[float], list[bool]]] = {m: ([], []) for m in MODES}
    for test in numbers:
        train_numbers = [n for n in numbers if n != test]
        trained = training_trees(batches, train_numbers)
        ordinary, held_out = evaluation_trees(batches[test])
        limited = limited_trees(batches[test])
        snaps = {t.row["tree_id"]: snapshot_rows(t) for t in ordinary + held_out}
        fold = {"train_batches": train_numbers, "test_batch": test, "models": {}}
        for mode in MODES:
            chosen = choose_threshold(*inner_scores(mode, batches, train_numbers))
            booster, info = model_module.train(training_rows(mode, trained))
            scores = model_module.predict(booster, [t.row for t in ordinary])
            out_of_fold[mode][0].extend(scores)
            out_of_fold[mode][1].extend(t.positive for t in ordinary)
            fold["models"][mode] = {
                "train": info,
                "threshold_chosen_on_training_folds": chosen,
                "test": evaluate_group(booster, ordinary, chosen["threshold"]),
                "held_out_techniques": evaluate_group(booster, held_out, chosen["threshold"]),
                "documented_limitation": evaluate_limited(booster, limited, chosen["threshold"]),
                "snapshots_of_test_trees": snapshot_evaluation(booster, ordinary, snaps),
                "snapshots_of_held_out_trees": snapshot_evaluation(booster, held_out, snaps),
                "alert_time_skew": alert_time_skew(booster, folders[test]),
            }
        report["folds"].append(fold)
    report["pooled"] = {mode: pooled_summary(report["folds"], mode) for mode in MODES}

    final_threshold = choose_threshold(*out_of_fold["snapshots"])
    booster, info = model_module.train(training_rows("snapshots", all_training))
    report["final_model"] = {
        "trained_on_batches": numbers, "training": "prefix snapshots", **info,
        "proposed_threshold": {
            **final_threshold,
            "note": "Chosen by leave-one-batch-out over the same batches the saved model is trained on, so its "
                    "own numbers are in-sample for the choice. It is a proposal, not a test result, and it is not "
                    "applied anywhere: the policy keeps its own thresholds.",
        },
        "note": "The snapshot model, trained on every training-pool tree of the labelled batches. It has no "
                "held-out evaluation of its own: the fold results above are the evidence, and they are preliminary.",
    }
    if save_to is not None:
        path = model_module.save(booster, save_to, {
            "status": report["status"], "trained_on_batches": numbers, "training": "prefix snapshots",
            "snapshot_fractions": list(SNAPSHOT_FRACTIONS), **info,
            "trained_sessions": sorted({t.row["session_id"] for t in all_training}),
            "held_out_techniques_excluded": list(HELD_OUT_TECHNIQUES),
            "proposed_threshold": final_threshold["threshold"],
        })
        score_module.reset_model()
        report["final_model"]["saved_to"] = str(path)
        report["final_model"]["sha256"] = model_module.sha256_of(path)
    return report


# ---- text ----------------------------------------------------------------------------------


def confusion_line(c: dict) -> str:
    tag = "  (chosen on the training folds)" if c.get("chosen_on_training_folds") else ""
    return (f"at {c['threshold']}: attacks caught {show(c['tp'], c['tp'] + c['fn'])}; "
            f"benign flagged {show(c['fp'], c['fp'] + c['tn'])}; "
            f"flagged that were attacks {show(c['tp'], c['tp'] + c['fp'])}{tag}")


def pooled_lines(pooled: dict) -> list[str]:
    lines = []
    for name, label in (("test", "ordinary trees"), ("held_out_techniques", "held-out techniques")):
        entry = pooled[name]
        for key in ("fixed_0.5", "fixed_0.8", "chosen_on_training_folds"):
            c = entry[key]
            if c is None:
                continue
            lines.append(f"    {label}, {key.replace('_', ' ')}: attacks caught {show(c['tp'], c['tp'] + c['fn'])}; "
                         f"benign flagged {show(c['fp'], c['fp'] + c['tn'])}")
    lim = pooled["documented_limitation"]
    lines.append(f"    T1003.001 (documented limitation, NOT in recall): flagged at 0.5 {lim['flagged_at_0.5']} of {lim['trees']}, "
                 f"at 0.8 {lim['flagged_at_0.8']} of {lim['trees']}, scores {lim['scores']}")
    e = pooled["attacks_flagged_early_25_to_75_percent"]
    b = pooled["benign_flagged_early_only_25_to_75_percent"]
    lines.append(f"    attacks still flagged at 0.5 on 25 to 75% of their span: {show(e['flagged'], e['of'])}; "
                 f"benign flagged early only: {show(b['flagged'], b['of'])}")
    a = pooled["alert_time"]
    lines.append(f"    alerts at or above 0.8 when they fire: benign sessions "
                 f"{show(a['benign_session_alerts_at_or_above_0.8']['alert_time'], a['benign_session_alerts_at_or_above_0.8']['of'])}; "
                 f"malicious sessions {show(a['malicious_session_alerts_at_or_above_0.8']['alert_time'], a['malicious_session_alerts_at_or_above_0.8']['of'])}")
    return lines


def text_report(report: dict) -> str:
    lines = [report["status"], f"Scheme: {report['scheme']}. Held-out techniques: {report['held_out_techniques']} "
                               f"({report['held_out_note']}).",
             f"T1003.001 is a documented limitation: {report['documented_limitation']['note']}", "",
             "Class balance (usable trees: start observed, harness left out; positives exclude T1003.001):"]
    for n, names in report.get("sessions_left_out_for_having_no_labels", {}).items():
        lines.append(f"Batch {n}: {len(names)} session(s) left out, no labels (decided out): " + ", ".join(names))
    for row in report["balance"]:
        lines.append(f"  batch {row['batch']} {row['group']:9} attacks {row['positive_trees']:3}  "
                     f"T1003.001 {row['documented_limitation_trees']}  benign {row['negative_trees']:4}  "
                     f"dropped (no start event) {row['unobserved_start_dropped']}")
    for fold in report["folds"]:
        lines += ["", f"=== Train on batches {fold['train_batches']}, test on batch {fold['test_batch']} ==="]
        for mode, m in fold["models"].items():
            chosen = m["threshold_chosen_on_training_folds"]
            lines.append(f"--- {mode} model ({m['train']['n_positive']} positive / {m['train']['n_negative']} negative "
                         f"training rows). Threshold chosen on the training folds: {chosen['threshold']}"
                         f"{'' if chosen['met_fpr_cap'] else ' (no value met the false-positive cap)'}")
            for name in ("test", "held_out_techniques"):
                group = m[name]
                if not group["trees"]:
                    lines.append(f"  {name}: no trees")
                    continue
                lines.append(f"  {name} (complete trees): {group['positives']} attacks, {group['negatives']} benign")
                for c in group["by_threshold"]:
                    lines.append("    " + confusion_line(c))
                for p in group["positive_scores"]:
                    lines.append(f"    attack {p['technique']}: score {p['score']} ({p['n_events']} events)")
            lim = m["documented_limitation"]
            if lim["trees"]:
                lines.append(f"  T1003.001 (documented limitation, NOT in recall): {[(i['score'], i['n_events']) for i in lim['items']]} "
                             f"(score, events); flagged at 0.5 {lim['flagged']['0.5']} of {lim['trees']}, at 0.8 {lim['flagged']['0.8']} of {lim['trees']}")
            snap = m["snapshots_of_test_trees"]
            lines.append("  snapshots of test trees, by how much of the tree is seen (at 0.5):")
            for b in snap["by_fraction"]:
                c = b["by_threshold"][0]
                lines.append(f"    {b['fraction']:>4}: attacks caught {show(c['tp'], c['tp'] + c['fn'])}; benign flagged {show(c['fp'], c['fp'] + c['tn'])}")
            lines.append("  skew to the complete tree (|difference|, attacks still flagged, benign flagged only early):")
            for s in snap["skew"]:
                pos, neg = s["positives"], s["negatives"]
                lines.append(f"    {s['fraction']:>4}: attacks median {pos.get('median_abs_diff')} max {pos.get('max_abs_diff')}, "
                             f"flagged {show(s['attacks_flagged_early']['flagged'], s['attacks_flagged_early']['of'])};  "
                             f"benign median {neg.get('median_abs_diff')} max {neg.get('max_abs_diff')}, "
                             f"early-only {show(s['benign_flagged_early_only']['flagged'], s['benign_flagged_early_only']['of'])}")
            a = m["alert_time_skew"]
            lines.append(f"  pipeline replay, alert-time vs complete tree ({a['alerts_scored']} scored alerts, median |diff| {a['median_abs_diff']}, max {a['max_abs_diff']}):")
            lines.append(f"    benign sessions: at or above 0.8 at alert time "
                         f"{show(a['benign_session_alerts_at_or_above_0.8']['alert_time'], a['alerts_in_benign_sessions'])}, "
                         f"on the complete tree {show(a['benign_session_alerts_at_or_above_0.8']['complete_tree'], a['alerts_in_benign_sessions'])}")
            lines.append(f"    malicious sessions: at or above 0.8 at alert time "
                         f"{show(a['malicious_session_alerts_at_or_above_0.8']['alert_time'], a['alerts_in_malicious_sessions'])}, "
                         f"on the complete tree {show(a['malicious_session_alerts_at_or_above_0.8']['complete_tree'], a['alerts_in_malicious_sessions'])}")
    lines += ["", "=== Summed over the held-out batches (each batch was scored by a different model) ==="]
    for mode in MODES:
        lines.append(f"  {mode} model:")
        lines += pooled_lines(report["pooled"][mode])
    final = report["final_model"]
    p = final["proposed_threshold"]
    lines += ["", final["note"],
              f"Proposed threshold for the saved model: {p['threshold']} ({p['note']})"]
    if "sha256" in final:
        lines.append(f"Model file SHA-256: {final['sha256']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and evaluate the triage model, leave-one-batch-out.")
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
