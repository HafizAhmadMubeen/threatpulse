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

Known gap: the pipeline passes the tree as it is when an alert fires, and in a replay that
tree includes the wrapper that runs each test, which training left out.
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
