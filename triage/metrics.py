"""Precision, recall and false-positive rate with their uncertainty. Never accuracy alone.

With a handful of positive trees every rate is very uncertain, so each comes with a Wilson
95% interval. Plain Python: no scikit-learn needed.
"""

import math


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    if total == 0:
        return None
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return (round(max(0.0, centre - spread), 3), round(min(1.0, centre + spread), 3))


def rate(successes: int, total: int) -> dict:
    return {"value": round(successes / total, 3) if total else None, "of": total, "ci95": wilson(successes, total)}


def confusion(scores: list[float], positives: list[bool], threshold: float) -> dict:
    tp = sum(1 for s, y in zip(scores, positives) if y and s >= threshold)
    fn = sum(1 for s, y in zip(scores, positives) if y and s < threshold)
    fp = sum(1 for s, y in zip(scores, positives) if not y and s >= threshold)
    tn = sum(1 for s, y in zip(scores, positives) if not y and s < threshold)
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": rate(tp, tp + fp),      # of everything flagged, how much was an attack
        "recall": rate(tp, tp + fn),         # of the attacks, how many were flagged
        "false_positive_rate": rate(fp, fp + tn),
    }
