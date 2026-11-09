"""score_process: the XGBoost risk score of a process tree (ROADMAP.md Section 2, step 3.5).

*** STUB ***  There is no model yet, so this always returns None. None means "not scored",
which is not the same as 0.0: the policy engine treats it as never matching a risk
threshold, and the dashboard shows "Not scored". Do not turn this into a number until a
model trained on our own recordings (split by session) replaces it.

The pipeline already calls it with the events of the alert's process tree, so replacing
this function is the only change needed. One thing to fix then: a replay has no labels,
so the tree includes the wrapper that runs each test, which training excluded.
"""

IS_STUB = True


def score_process(events: list[dict]) -> float | None:
    """STUB. Returns None (not scored) for every process tree."""
    return None
