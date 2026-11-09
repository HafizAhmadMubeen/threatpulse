"""Train and evaluate the triage model: python -m triage.train --batch N SESSIONS LABELS ... --out DIR

Reads the exported batches (read-only) and writes a report. It is leave-one-batch-out: each
labelled batch is tested in turn by a model trained on all the OTHER batches (whole-batch
split, never by event or session). Held-out techniques are only ever on the test side and
are reported separately. T1003.001 is a documented limitation (LSA protection leaves its
test part with almost nothing to see): it is reported on its own, never counts toward recall,
and is LEFT OUT of training by default (a tree of about 2 events has no behaviour to learn;
--include-limited-in-training puts it back).

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
import resource
import statistics
import sys
from pathlib import Path

from backend.pipeline import run_session
from contracts.validate_samples import load_validators
from detection.timeline import read_jsonl
from triage import model as model_module
from triage import score as score_module
from triage.dataset import (DEFAULT_RECORDING_TESTS, HELD_OUT_TECHNIQUES, LIMITATION_REASONS, LIMITATION_TECHNIQUES,
                            MIN_SNAPSHOT_EVENTS, SNAPSHOT_FRACTIONS,
                            DatasetError, Tree, balance_table, evaluation_trees, limited_trees, load_batch,
                            load_excluded_pools, pool_excluded_sessions, session_folders, snapshot_rows,
                            snapshot_training_rows, training_trees, unlabelled_sessions)
from triage.features import events_of_tree_containing, tree_feature_row
from triage.metrics import confusion, pool, rate, show

log = logging.getLogger(__name__)

FIXED_THRESHOLDS = (0.5, 0.8)  # 0.50 = dashboard "alert", 0.80 = policy auto_contain
THRESHOLD_GRID = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)
FPR_CAP = 0.02  # at most 2% of benign trees flagged, pooled over the inner folds
TOP_NEGATIVES = 5
# The pipeline replay keeps every event of a session in memory (about 3 KB each). A session larger than
# this is not replayed for the alert-time view, and the report names it.
REPLAY_MAX_EVENTS = 400_000
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


def inner_scores(mode: str, batches: dict[int, list[Tree]], train_numbers: list[int],
                 include_limited: bool = False) -> tuple[list[float], list[bool]]:
    """Leave-one-batch-out inside the training batches. Scores ordinary trees only."""
    scores, flags = [], []
    for held in train_numbers:
        others = [n for n in train_numbers if n != held]
        if not others:
            raise DatasetError("choosing a threshold needs at least two training batches")
        booster, _ = model_module.train(training_rows(mode, training_trees(batches, others, include_limited)))
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
    """The documented limitations (T1003.001, T1105): scored and listed, never part of recall.
    Listed per technique, each tree with its real number of events."""
    scores = model_module.predict(booster, [t.row for t in trees])
    thresholds = sorted({*FIXED_THRESHOLDS, chosen})
    by_technique = {}
    for technique in LIMITATION_TECHNIQUES:
        mine = [(t, s) for t, s in zip(trees, scores) if t.row["technique"] == technique]
        if mine:
            by_technique[technique] = {
                "trees": len(mine), "items": [describe(t, s) for t, s in mine],
                "flagged": {str(th): sum(1 for _, s in mine if s >= th) for th in thresholds}}
    return {"trees": len(trees),
            "items": [describe(t, s) for t, s in zip(trees, scores)],
            "flagged": {str(th): sum(1 for s in scores if s >= th) for th in thresholds},
            "by_technique": by_technique}


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


def count_lines(path: Path) -> int:
    """Lines of a file, read in chunks (a session's size without loading it)."""
    if not path.is_file():
        return 0
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 22):
            total += chunk.count(b"\n")
    return total


def alert_time_skew(booster, folders: list[Path]) -> dict:
    """The pipeline's own view. Each alert is scored when it fires (a partial tree), and again
    on the whole of the same tree at the end of the recording. Both are label-free: the
    wrapper that runs each test is in both, which is the scorer's real situation. Alerts of
    T1003.001 sessions are counted apart (documented limitation)."""
    rows, not_replayed = [], []
    for folder in folders:
        size = count_lines(folder / "events.jsonl") + count_lines(folder / "fim.jsonl")
        if size > REPLAY_MAX_EVENTS:  # the replay would hold every event in memory
            not_replayed.append({"session": folder.name, "events": size, "limit": REPLAY_MAX_EVENTS})
            continue
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
        "sessions_not_replayed": not_replayed,
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
        "by_technique": {
            technique: {
                "trees": sum(g["by_technique"][technique]["trees"] for g in limited if technique in g["by_technique"]),
                "flagged_at_0.5": sum(g["by_technique"][technique]["flagged"]["0.5"] for g in limited if technique in g["by_technique"]),
                "flagged_at_0.8": sum(g["by_technique"][technique]["flagged"]["0.8"] for g in limited if technique in g["by_technique"]),
                "items": [{"score": i["score"], "n_events": i["n_events"]} for g in limited
                          if technique in g["by_technique"] for i in g["by_technique"][technique]["items"]],
            } for technique in LIMITATION_TECHNIQUES if any(technique in g["by_technique"] for g in limited)},
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
        "sessions_not_replayed": [item for a in alerts for item in a.get("sessions_not_replayed", [])],
        "benign_session_alerts_at_or_above_0.8": {"alert_time": sum(a["benign_session_alerts_at_or_above_0.8"]["alert_time"] for a in alerts),
                                                  "of": sum(a["alerts_in_benign_sessions"] for a in alerts)},
        "malicious_session_alerts_at_or_above_0.8": {"alert_time": sum(a["malicious_session_alerts_at_or_above_0.8"]["alert_time"] for a in alerts),
                                                     "of": sum(a["alerts_in_malicious_sessions"] for a in alerts)},
    }
    return out


def prepare(batches_spec: list[tuple[int, Path, Path]], only_labelled: bool,
            excluded_pools: tuple[str, ...]) -> tuple[dict, dict, dict, dict]:
    """Load the batches, skipping what is skipped on purpose. Nothing here trains anything.

    Returns the trees per batch, the session folders per batch (the same ones: replays use
    them too), the sessions left out for having no labels, and the sessions left out because
    their pool is in excluded_from_ml_pools. A session of an excluded pool is skipped before its
    labels are looked at, and it reaches neither training nor evaluation."""
    batches = {n: load_batch(n, sessions, labels, only_labelled, excluded_pools, keep_events=False)
               for n, sessions, labels in batches_spec}
    folders = {n: session_folders(sessions, labels, only_labelled, excluded_pools) for n, sessions, labels in batches_spec}
    no_labels = ({n: unlabelled_sessions(sessions, labels, excluded_pools) for n, sessions, labels in batches_spec}
                 if only_labelled else {})
    pool_left_out = {n: pool_excluded_sessions(sessions, excluded_pools) for n, sessions, _ in batches_spec}
    return batches, folders, no_labels, pool_left_out


def composition(trees: list[Tree]) -> dict:
    """What the benign training rows are made of, by session and by activity, for the complete
    model (one row per tree) and the snapshot model (a few per tree). Answers whether one big
    session, such as the Windows Update one, dominates."""
    sessions: dict[str, dict] = {}
    for tree in trees:
        if tree.positive:
            continue
        entry = sessions.setdefault(tree.row["session_id"], {
            "session": tree.row["session_id"], "activity": tree.row["activity"] or None, "batch": tree.row["batch"],
            "trees": 0, "snapshot_rows": 0, "largest_tree_events": 0})
        entry["trees"] += 1
        entry["snapshot_rows"] += len(snapshot_rows(tree))
        entry["largest_tree_events"] = max(entry["largest_tree_events"], tree.row["n_events"])
    total_trees = sum(e["trees"] for e in sessions.values())
    total_snapshots = sum(e["snapshot_rows"] for e in sessions.values())
    for e in sessions.values():
        e["share_of_benign_complete_rows"] = {"of": total_trees, "k": e["trees"]}
        e["share_of_benign_snapshot_rows"] = {"of": total_snapshots, "k": e["snapshot_rows"]}
    ordered = sorted(sessions.values(), key=lambda e: -e["snapshot_rows"])
    by_activity: dict[str, dict] = {}
    for e in ordered:
        a = by_activity.setdefault(e["activity"] or "none", {"sessions": 0, "trees": 0, "snapshot_rows": 0})
        a["sessions"] += 1
        a["trees"] += e["trees"]
        a["snapshot_rows"] += e["snapshot_rows"]
    return {"benign_complete_rows": total_trees, "benign_snapshot_rows": total_snapshots,
            "largest_sessions": ordered[:5], "by_activity": by_activity}


def peak_memory_mb() -> int:
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)  # Linux reports kilobytes


def report_header(batches: dict, skipped: dict, pool_left_out: dict, include_limited_in_training: bool,
                  excluded_pools: tuple[str, ...], excluded_source: dict | None) -> tuple[dict, list]:
    """Everything in the report that is known before any model is trained. Returns it and the
    trees of the final model's training set. Nothing here trains anything."""
    numbers = sorted(batches)
    all_training = training_trees(batches, numbers, include_limited_in_training)
    positives = sum(t.positive for t in all_training)
    header = {
        "status": preliminary_banner(len(numbers), positives),
        "scheme": "leave-one-batch-out",
        "held_out_techniques": list(HELD_OUT_TECHNIQUES),
        "held_out_note": "T1685 has no recording yet, so held-out results cover the others only",
        "documented_limitation": {
            "in_training": include_limited_in_training,
            "techniques": list(LIMITATION_TECHNIQUES),
            "reasons": LIMITATION_REASONS,
            "note": "The test part of these techniques holds almost nothing of the technique (see reasons). "
                    "Reported on its own, by technique and never by size, and never counted toward recall. "
                    + ("These trees are IN training in this run (--include-limited-in-training)."
                       if include_limited_in_training else
                       "These trees are LEFT OUT of training (the default): a tree of about 2 events has no behaviour to learn."),
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
        "excluded_from_ml_pools": list(excluded_pools),
        "excluded_pools_source": excluded_source,
        "sessions_left_out_for_an_excluded_pool": {str(n): items for n, items in pool_left_out.items() if items},
        "folds": [],
    }
    return header, all_training


def run(batches_spec: list[tuple[int, Path, Path]], save_to: Path | None, only_labelled: bool = False,
        include_limited_in_training: bool = False, excluded_pools: tuple[str, ...] = (),
        excluded_source: dict | None = None) -> dict:
    """`excluded_pools` comes from recording_tests.json (the CLI always supplies it). Programs
    that call run() directly pass it themselves: the default of none is only for tests."""
    batches, folders, skipped, pool_left_out = prepare(batches_spec, only_labelled, excluded_pools)
    numbers = sorted(batches)
    if len(numbers) < 3:
        raise DatasetError("leave-one-batch-out with a threshold chosen on the training folds needs at least three batches")
    report, all_training = report_header(batches, skipped, pool_left_out, include_limited_in_training,
                                         excluded_pools, excluded_source)
    out_of_fold: dict[str, tuple[list[float], list[bool]]] = {m: ([], []) for m in MODES}
    for test in numbers:
        train_numbers = [n for n in numbers if n != test]
        trained = training_trees(batches, train_numbers, include_limited_in_training)
        ordinary, held_out = evaluation_trees(batches[test])
        limited = limited_trees(batches[test])
        snaps = {t.row["tree_id"]: snapshot_rows(t) for t in ordinary + held_out}
        fold = {"train_batches": train_numbers, "test_batch": test, "training_composition": composition(trained),
                "models": {}}
        for mode in MODES:
            chosen = choose_threshold(*inner_scores(mode, batches, train_numbers, include_limited_in_training))
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
    report["final_training_composition"] = composition(all_training)

    final_threshold = choose_threshold(*out_of_fold["snapshots"])
    booster, info = model_module.train(training_rows("snapshots", all_training))
    report["final_model"] = {
        "trained_on_batches": numbers, "training": "prefix snapshots", **info,
        "t1003_in_training": include_limited_in_training,
        "proposed_threshold": {
            **final_threshold,
            "note": "Chosen by leave-one-batch-out over the same batches the saved model is trained on, so its "
                    "own numbers are in-sample for the choice. It is a proposal, not a test result, and it is not "
                    "applied anywhere: the policy keeps its own thresholds.",
        },
        "note": "The snapshot model, trained on every training-pool tree of the labelled batches. It has no "
                "held-out evaluation of its own: the fold results above are the evidence, and they are preliminary.",
    }
    report["peak_memory_mb"] = peak_memory_mb()
    if save_to is not None:
        path = model_module.save(booster, save_to, {
            "status": report["status"], "trained_on_batches": numbers, "training": "prefix snapshots",
            "snapshot_fractions": list(SNAPSHOT_FRACTIONS), **info,
            "trained_sessions": sorted({t.row["session_id"] for t in all_training}),
            "held_out_techniques_excluded": list(HELD_OUT_TECHNIQUES),
            "proposed_threshold": final_threshold["threshold"],
            "t1003_in_training": include_limited_in_training,
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
    for technique, t in lim.get("by_technique", {}).items():
        lines.append(f"    {technique} (documented limitation, NOT in recall): flagged at 0.5 {t['flagged_at_0.5']} of {t['trees']}, "
                     f"at 0.8 {t['flagged_at_0.8']} of {t['trees']}, (score, events) {[(i['score'], i['n_events']) for i in t['items']]}")
    e = pooled["attacks_flagged_early_25_to_75_percent"]
    b = pooled["benign_flagged_early_only_25_to_75_percent"]
    lines.append(f"    attacks still flagged at 0.5 on 25 to 75% of their span: {show(e['flagged'], e['of'])}; "
                 f"benign flagged early only: {show(b['flagged'], b['of'])}")
    a = pooled["alert_time"]
    lines.append(f"    alerts at or above 0.8 when they fire: benign sessions "
                 f"{show(a['benign_session_alerts_at_or_above_0.8']['alert_time'], a['benign_session_alerts_at_or_above_0.8']['of'])}; "
                 f"malicious sessions {show(a['malicious_session_alerts_at_or_above_0.8']['alert_time'], a['malicious_session_alerts_at_or_above_0.8']['of'])}")
    return lines


def left_out_lines(report: dict) -> list[str]:
    """The sessions skipped on purpose, by name, with the reason."""
    lines = []
    pools = report.get("excluded_from_ml_pools", [])
    lines.append(f"Pools left out of training and evaluation (excluded_from_ml_pools): {pools or 'none given'}")
    for n, items in report.get("sessions_left_out_for_an_excluded_pool", {}).items():
        lines.append(f"Batch {n}: {len(items)} session(s) left out for an excluded pool: "
                     + ", ".join(f"{i['session']} (pool {i['pool']})" for i in items))
    for n, names in report.get("sessions_left_out_for_having_no_labels", {}).items():
        lines.append(f"Batch {n}: {len(names)} session(s) left out, no labels (decided out): " + ", ".join(names))
    return lines


def composition_lines(report: dict) -> list[str]:
    """What the benign training rows are made of, and the peak memory of the run."""
    lines = []
    comp = report.get("final_training_composition")
    if comp:
        lines += ["", f"What the benign training rows are made of (final model): {comp['benign_complete_rows']} trees, "
                      f"{comp['benign_snapshot_rows']} snapshot rows"]
        for e in comp["largest_sessions"]:
            lines.append(f"  {e['session']} ({e['activity']}, batch {e['batch']}): "
                         f"trees {show(e['trees'], comp['benign_complete_rows'])}; snapshot rows "
                         f"{show(e['snapshot_rows'], comp['benign_snapshot_rows'])}; largest tree {e['largest_tree_events']} events")
    if "peak_memory_mb" in report:
        lines += ["", f"Peak memory of this run: {report['peak_memory_mb']} MB."]
    return lines


def text_report(report: dict) -> str:
    lines = [report["status"], f"Scheme: {report['scheme']}. Held-out techniques: {report['held_out_techniques']} "
                               f"({report['held_out_note']}).",
             f"Documented limitations {report['documented_limitation']['techniques']}: {report['documented_limitation']['note']}"]
    lines += [f"  {t}: {why}" for t, why in report["documented_limitation"].get("reasons", {}).items()] + [""]
    lines += left_out_lines(report)
    lines += ["", "Class balance (usable trees: start observed, harness left out; positives exclude the documented-limitation trees):"]
    for row in report["balance"]:
        lines.append(f"  batch {row['batch']} {row['group']:9} attacks {row['positive_trees']:3}  "
                     f"limited {row['documented_limitation_trees']}  benign {row['negative_trees']:4}  "
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
            for technique, t in m["documented_limitation"].get("by_technique", {}).items():
                lines.append(f"  {technique} (documented limitation, NOT in recall): {[(i['score'], i['n_events']) for i in t['items']]} "
                             f"(score, events); flagged at 0.5 {t['flagged']['0.5']} of {t['trees']}, at 0.8 {t['flagged']['0.8']} of {t['trees']}")
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
            for item in a.get("sessions_not_replayed", []):
                lines.append(f"  NOT replayed for alert-time scores (too large to hold in memory): {item['session']}, "
                             f"{item['events']} events (limit {item['limit']})")
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
    lines += composition_lines(report)
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
    parser.add_argument("--include-limited-in-training", action="store_true",
                        help="put the T1003.001 attack trees (about 2 events) into training. By default they are left "
                             "out (outer folds, threshold choice and the saved model), because a tree that small has no "
                             "behaviour to learn. They are reported apart either way")
    parser.add_argument("--recording-tests", type=Path, default=DEFAULT_RECORDING_TESTS,
                        help="Track A's recording_tests.json. Its excluded_from_ml_pools (today: fim-test-only) lists "
                             "pools whose sessions are skipped for training and evaluation. The file and the key are "
                             "required, and the run stops without them")
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
        pools = load_excluded_pools(args.recording_tests)
        source = {"path": str(args.recording_tests), "sha256": model_module.sha256_of(args.recording_tests)}
        report = run(spec, None if args.no_save else score_module.MODEL_DIR, args.only_labelled,
                     args.include_limited_in_training, pools, source)
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
