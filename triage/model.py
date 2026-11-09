"""The behavioural triage model: XGBoost on per-process-tree features (PHASES.md steps 3.4, 3.5).

4th generation (AI/ML). The model only ever sees the columns in MODEL_FEATURES: counts,
rates, zones touched, signing. Never a name, path or command line (CLAUDE.md "ML rules").

Hyperparameters are fixed here, in advance. Nothing is tuned on the test or the held-out
data. With only a few positive trees any tuning would just fit the test set; tuning waits
for leave-one-batch-out over many batches.

The model is saved as XGBoost's JSON format, never pickle: loading a pickle can run code.
A sidecar file records the feature order, what it was trained on, and the SHA-256 of the
model file. That catches a damaged or mismatched file. It is not a signature: whoever can
write the model folder can write both files.
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import xgboost as xgb

from triage.features import FEATURE_COLUMNS, METADATA_COLUMNS

log = logging.getLogger(__name__)

# n_fim_changes_linked is left out: a tree's own events (what score_process receives) hold
# no FIM events, so at scoring time it would always be 0 while training saw real values.
# FIM changes are handled by the policy's persistence rule, whatever the score is.
NOT_MODELLED = ("n_fim_changes_linked",)
MODEL_FEATURES = [c for c in FEATURE_COLUMNS if c not in NOT_MODELLED]
assert not set(MODEL_FEATURES) & set(METADATA_COLUMNS)

PARAMS = {
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "tree_method": "hist",
    "max_depth": 3,
    "eta": 0.1,
    "min_child_weight": 1,
    "subsample": 1.0,
    "colsample_bytree": 1.0,
    "reg_lambda": 1.0,
    "nthread": 1,
    "seed": 0,
}
ROUNDS = 60
MODEL_FILE = "behaviour_model.json"
META_FILE = "behaviour_model.meta.json"


def matrix(rows: list[dict]) -> np.ndarray:
    return np.array([[float(row[name]) for name in MODEL_FEATURES] for row in rows], dtype=np.float32)


def train(rows: list[dict]) -> tuple[xgb.Booster, dict]:
    """Class weights: positives count `negatives / positives` times as much, because
    malicious trees are rare. That makes scores uncalibrated: they are not probabilities,
    so a threshold such as 0.80 must be re-checked, not assumed."""
    labels = np.array([1.0 if row["label"] == "malicious" else 0.0 for row in rows], dtype=np.float32)
    positives, negatives = int(labels.sum()), int(len(labels) - labels.sum())
    if positives == 0 or negatives == 0:
        raise ValueError(f"cannot train with {positives} positive and {negatives} negative trees")
    weight = negatives / positives
    params = {**PARAMS, "scale_pos_weight": weight}
    booster = xgb.train(params, xgb.DMatrix(matrix(rows), label=labels, feature_names=MODEL_FEATURES), ROUNDS)
    info = {"n_positive": positives, "n_negative": negatives, "scale_pos_weight": round(weight, 4),
            "params": params, "rounds": ROUNDS}
    return booster, info


def predict(booster: xgb.Booster, rows: list[dict]) -> list[float]:
    if not rows:
        return []
    data = xgb.DMatrix(matrix(rows), feature_names=MODEL_FEATURES)
    return [float(v) for v in booster.predict(data)]


def predict_vector(booster: xgb.Booster, features: dict) -> float:
    return predict(booster, [features])[0]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(booster: xgb.Booster, directory: Path, details: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    model_path = directory / MODEL_FILE
    booster.save_model(str(model_path))
    meta = {"format": 1, "features": MODEL_FEATURES, "xgboost": xgb.__version__,
            "model_sha256": sha256_of(model_path), **details}
    (directory / META_FILE).write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    return model_path


@dataclass(frozen=True)
class LoadedModel:
    booster: xgb.Booster
    meta: dict


def load(directory: Path) -> LoadedModel | None:
    """The saved model, or None for ANY problem (missing, damaged, wrong features). A bad
    model must never turn into a score, so the caller gets "not scored"."""
    model_path, meta_path = directory / MODEL_FILE, directory / META_FILE
    if not (model_path.is_file() and meta_path.is_file()):
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(meta, dict) or meta.get("format") != 1:
            raise ValueError("unknown model format")
        if meta.get("features") != MODEL_FEATURES:
            raise ValueError("the model's features are not the current MODEL_FEATURES")
        if meta.get("model_sha256") != sha256_of(model_path):
            raise ValueError("the model file does not match its recorded SHA-256")
        booster = xgb.Booster()
        booster.load_model(str(model_path))
        return LoadedModel(booster, meta)
    except (OSError, ValueError, xgb.core.XGBoostError) as error:
        log.warning("model in %s not used: %s", directory, error)
        return None
