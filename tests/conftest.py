"""Keeps tests independent of whatever model happens to be in triage/models/ on this machine."""

import pytest

from triage import score


@pytest.fixture(autouse=True)
def no_local_model(tmp_path_factory, monkeypatch):
    monkeypatch.setattr(score, "MODEL_DIR", tmp_path_factory.mktemp("no-model"))
    score.reset_model()
    yield
    score.reset_model()
