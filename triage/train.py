"""Train and evaluate the triage model: python -m triage.train --batch N SESSIONS LABELS ... --out DIR

Reads the exported batches (read-only) and writes a report. For each labelled batch in turn
it trains on the OTHER batches and tests on that one (whole-batch split). Held-out
techniques are only ever in the test side, and are reported separately. Then it trains the
model that score_process uses on all training-pool trees, and saves it to triage/models/.

Every result here is PRELIMINARY until all 11 batches exist. With a few positive trees per
batch, a rate is a few counts, and its interval says so.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from backend.pipeline import run_session
from triage import model as model_module
from triage import score as score_module
from triage.dataset import (HELD_OUT_TECHNIQUES, DatasetError, Tree, balance_table, evaluation_trees,
                            load_batch, session_folders, training_trees)
from triage.features import order_key, tree_feature_row
from triage.metrics import confusion

log = logging.getLogger(__name__)

THRESHOLDS = (0.5, 0.8)  # 0.50 = dashboard "alert", 0.80 = policy auto_contain
FRACTIONS = (0.1, 0.25, 0.5, 1.0)  # how much of a tree has been seen
TOP_NEGATIVES = 5


def preliminary_banner(batch_count: int, positives: int) -> str:
    return (f"PRELIMINARY: {batch_count} of 11 batches and {positives} training positives in total. "
            "These numbers show that the pipeline works. They do not say how well it detects.")


def describe(tree: Tree, score: float) -> dict:
    return {"session": tree.row["session_id"], "technique": tree.row["technique"] or None,
            "n_events": tree.row["n_events"], "score": round(score, 4)}


def evaluate_group(booster, trees: list[Tree]) -> dict:
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


def prefix_scores(booster, trees: list[Tree]) -> dict:
    """Score a tree after only a fraction of its events (by time), the way the pipeline
    sees it when an alert fires part-way through. If the score at 25% is far below the
    score at 100%, scoring alerts early would miss attacks that training would catch."""
    result = {"fractions": list(FRACTIONS), "positives": [], "worst_negative_by_fraction": []}
    worst = {f: 0.0 for f in FRACTIONS}
    mismatch = 0.0
    for tree in trees:
        ordered = sorted(tree.events, key=order_key)
        scored = {}
        for fraction in FRACTIONS:
            cut = max(1, round(len(ordered) * fraction))
            features = tree_feature_row(ordered[:cut])
            scored[fraction] = None if features is None else model_module.predict_vector(booster, features)
        full_row = model_module.predict(booster, [tree.row])[0]
        if scored[1.0] is not None:  # the scoring path and the training path must agree
            mismatch = max(mismatch, abs(scored[1.0] - full_row))
        if tree.positive:
            result["positives"].append({"session": tree.row["session_id"], "technique": tree.row["technique"],
                                        "n_events": len(ordered),
                                        "scores": {str(f): None if v is None else round(v, 4) for f, v in scored.items()}})
        else:
            for fraction, value in scored.items():
                if value is not None:
                    worst[fraction] = max(worst[fraction], value)
    result["worst_negative_by_fraction"] = {str(f): round(v, 4) for f, v in worst.items()}
    result["max_difference_serving_vs_training_features"] = round(mismatch, 8)
    return result


def replay_scores(booster, folders: list[Path]) -> list[dict]:
    """The pipeline's own view: scores at alert time on the raw recording, with no labels, so
    the wrapper that runs each test is still inside the tree."""
    summary = []
    for folder in folders:
        result = run_session(folder, scorer=lambda events: score_module.score_with(booster, events))
        values = [a["risk_score"] for a in result.alerts if a["risk_score"] is not None]
        summary.append({
            "session": folder.name, "label": result.session.get("label"),
            "alerts": len(result.alerts), "scored": len(values),
            "score_min": round(min(values), 4) if values else None,
            "score_max": round(max(values), 4) if values else None,
        })
    return summary


def run(batches_spec: list[tuple[int, Path, Path]], save_to: Path | None) -> dict:
    batches = {n: load_batch(n, sessions, labels) for n, sessions, labels in batches_spec}
    folders = {n: session_folders(sessions) for n, sessions, _ in batches_spec}
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
        "balance": balance_table(batches),
        "folds": [],
    }
    for test in numbers:
        train_numbers = [n for n in numbers if n != test]
        trained = training_trees(batches, train_numbers)
        booster, info = model_module.train([t.row for t in trained])
        ordinary, held_out = evaluation_trees(batches[test])
        fold = {
            "train_batches": train_numbers, "test_batch": test, "train": info,
            "test": evaluate_group(booster, ordinary),
            "held_out_techniques": evaluate_group(booster, held_out),
            "partial_tree_scores": prefix_scores(booster, ordinary + held_out),
            "replay_alert_time_scores": replay_scores(booster, folders[test]),
        }
        report["folds"].append(fold)

    booster, info = model_module.train([t.row for t in all_training])
    report["final_model"] = {
        "trained_on_batches": numbers, **info,
        "note": "Trained on every training-pool tree of the labelled batches. It has no held-out "
                "evaluation of its own: the fold results above are the evidence, and they are preliminary.",
    }
    if save_to is not None:
        path = model_module.save(booster, save_to, {
            "status": report["status"], "trained_on_batches": numbers, **info,
            "trained_sessions": sorted({t.row["session_id"] for t in all_training}),
            "held_out_techniques_excluded": list(HELD_OUT_TECHNIQUES),
        })
        score_module.reset_model()
        report["final_model"]["saved_to"] = str(path)
    return report


def text_report(report: dict) -> str:
    lines = [report["status"], "", "Class balance (usable trees: start observed, harness left out):"]
    for row in report["balance"]:
        lines.append(f"  batch {row['batch']} {row['group']:9} positives {row['positive_trees']:3}  "
                     f"negatives {row['negative_trees']:4}  dropped (no start event) {row['unobserved_start_dropped']}")
    for fold in report["folds"]:
        lines += ["", f"Train on batches {fold['train_batches']}, test on batch {fold['test_batch']} "
                      f"({fold['train']['n_positive']} positive / {fold['train']['n_negative']} negative training trees)"]
        for name in ("test", "held_out_techniques"):
            group = fold[name]
            if not group["trees"]:
                lines.append(f"  {name}: no trees")
                continue
            lines.append(f"  {name}: {group['positives']} positive, {group['negatives']} negative trees")
            for c in group["by_threshold"]:
                fmt = lambda r: "n/a" if r["value"] is None else f"{r['value']:.2f} {r['ci95']} of {r['of']}"  # noqa: E731
                lines.append(f"    at {c['threshold']}: TP {c['tp']} FP {c['fp']} FN {c['fn']} TN {c['tn']}  "
                             f"precision {fmt(c['precision'])}  recall {fmt(c['recall'])}  FPR {fmt(c['false_positive_rate'])}")
            for p in group["positive_scores"]:
                lines.append(f"    positive {p['technique']}: score {p['score']} ({p['n_events']} events)")
            tops = ", ".join(str(n["score"]) for n in group["top_negative_scores"])
            lines.append(f"    highest negative scores: {tops}")
        partial = fold["partial_tree_scores"]
        lines.append(f"  score as a tree grows ({partial['fractions']} of its events):")
        for p in partial["positives"]:
            lines.append(f"    {p['technique']}: {list(p['scores'].values())}")
        lines.append(f"    worst negative: {partial['worst_negative_by_fraction']}")
        lines.append(f"    scoring path vs training path differ by at most "
                     f"{partial['max_difference_serving_vs_training_features']}")
        lines.append("  pipeline replay, score when the alert fires (raw recording, wrapper still in the tree):")
        for r in fold["replay_alert_time_scores"]:
            if r["alerts"]:
                lines.append(f"    {r['session'][16:]:34} {str(r['label'])[:4]} alerts {r['alerts']:2} scored {r['scored']:2} "
                             f"range {r['score_min']}..{r['score_max']}")
    lines += ["", report["final_model"]["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and evaluate the triage model, split by batch.")
    parser.add_argument("--batch", nargs=3, action="append", metavar=("NUMBER", "SESSIONS", "LABELS"), required=True,
                        help="a batch number, its session folder, and its labels folder. Repeat per batch")
    parser.add_argument("--out", type=Path, required=True, help="where report.json and report.txt go (not inside an input)")
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
        report = run(spec, None if args.no_save else score_module.MODEL_DIR)
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
