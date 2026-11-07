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
    return {"k": successes, "value": round(successes / total, 3) if total else None, "of": total,
            "ci95": wilson(successes, total)}


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


def percent(value: float) -> str:
    text = f"{value * 100:.1f}".rstrip("0").rstrip(".")
    return f"{text}%"


def show(successes: int, total: int) -> str:
    """A rate with its count and its interval, so small samples are visible: '9 of 15 (60%,
    95% CI 36% to 80%)'. With nothing to count it says so instead of a rate."""
    if total == 0:
        return "0 of 0 (no cases)"
    low, high = wilson(successes, total)
    return f"{successes} of {total} ({percent(successes / total)}, 95% CI {percent(low)} to {percent(high)})"


def pool(confusions: list[dict]) -> dict:
    """Sum per-batch counts, then compute the rates on the sums. These are counts from
    different models (one per held-out batch), so they are not one model's result."""
    tp, fn, fp, tn = (sum(c[k] for c in confusions) for k in ("tp", "fn", "fp", "tn"))
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "precision": rate(tp, tp + fp), "recall": rate(tp, tp + fn), "false_positive_rate": rate(fp, fp + tn)}
