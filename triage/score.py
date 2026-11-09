"""score_process: the XGBoost risk score of a process tree (ROADMAP.md Section 2, step 3.5).

Returns a number from 0 to 1, or None for "not scored". None is NOT 0.0: the policy engine
never matches a risk threshold on None, and the dashboard shows "Not scored". It is
returned when:
- there is no model in triage/models/, or it is damaged, or its feature list is not the
  current one (triage/model.py checks the SHA-256 and the features);
- the events are not one single process tree whose start was observed. Training used only
  such trees, so a tree that began before recording has no honest score;
- anything about the events is malformed.

The score is the model's raw output. Class weights make it uncalibrated: it ranks trees,
and is not a probability. See triage/README.md for what it was trained and tested on.

SCOPE: the scorer is label-free. At runtime it sees only this:
- the events of ONE process tree, as the pipeline passes them: the alerting process, its
  descendants, and its ancestors up to (not including) the first one whose start was never
  seen. Only events up to the moment of the alert. The agent's events only, no FIM events;
- from them, counts, rates, zones touched and signing (triage/features.py). A path or key
  is read only to answer "which zone is this", and that answer leaves as a number.
It never sees, reads or opens: labels, labels.csv, session.json, start_utc, the harness
that runs a test (it cannot know which process that is), a process name, a path, a command
line, a file, the network, or the model's own past scores. A test blocks every file read
while scoring, and another checks that labels cannot change a score.

What that means: training used labels to choose positives and negatives, to leave the
harness out and to drop events before start_utc. None of that exists at runtime, so a
replayed recording is scored with the wrapper still inside the tree and with the sensor's
start-up events. triage/README.md says how far that moves the scores.
"""

import logging
from functools import lru_cache
from pathlib import Path

from triage import model as model_module
from triage.features import tree_feature_row

log = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent / "models"  # gitignored: models are not committed


@lru_cache(maxsize=1)
def _loaded(directory: Path):
    return model_module.load(directory)


def reset_model() -> None:
    """Forget the loaded model (after MODEL_DIR changes, or a new model is saved)."""
    _loaded.cache_clear()


def loaded_model():
    return _loaded(MODEL_DIR)


def is_stub() -> bool:
    """True while there is no usable model, so every score is None."""
    return loaded_model() is None


def model_info(used: bool) -> dict:
    """What a run states about the model: whether its score was allowed to count, and which
    model file it is (SHA-256, checked when the model was loaded)."""
    loaded = loaded_model()
    info = {"used": bool(used and loaded is not None), "loaded": loaded is not None,
            "sha256": loaded.meta["model_sha256"] if loaded else None}
    if loaded:
        info["status"] = loaded.meta.get("status")
        info["trained_on_batches"] = loaded.meta.get("trained_on_batches")
    return info


def no_score(events: list[dict]) -> None:
    """The scorer a pipeline run uses unless --use-model is given: never a score."""
    return None


def score_with(booster, events: list[dict]) -> float | None:
    try:
        features = tree_feature_row(events)
        if features is None:
            return None
        value = model_module.predict_vector(booster, features)
    except (KeyError, TypeError, ValueError) as error:
        log.warning("tree not scored: %s", type(error).__name__)
        return None
    return value if 0.0 <= value <= 1.0 else None


def score_process(events: list[dict]) -> float | None:
    """Score one process tree from its events. None means not scored."""
    loaded = loaded_model()
    if loaded is None:
        return None
    return score_with(loaded.booster, events)
