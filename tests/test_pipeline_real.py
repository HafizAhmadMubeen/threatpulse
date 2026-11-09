"""The pipeline on the real batch 1 recordings. Skipped when the export is not mounted.

Run on their own: uv run pytest tests/test_pipeline_real.py -v. A skip proves nothing, so
read the skip count. Nothing from the recordings is written into the repository: outputs go
to pytest's temporary folder, and the recordings are only read.
"""

import hashlib
import json
from pathlib import Path

import pytest

from backend.pipeline import output, run_session
from contracts.validate_samples import load_validators

EXPORT = Path("/mnt/e/threatpulse-data/vm-export/batch-01")
EDGE_SESSION = EXPORT / "20261106T132018-benign-run1"
PERSISTENCE_SESSION = EXPORT / "20261106T133533-T1547.001-1-run1"

pytestmark = [
    pytest.mark.attack_data,
    pytest.mark.skipif(not EDGE_SESSION.is_dir(), reason="the batch 1 export is not mounted"),
]


def digest(folder: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        hasher.update(path.name.encode() + path.read_bytes())
    return hasher.hexdigest()


def test_edge_rewriting_its_run_value_is_never_restored_and_the_export_is_untouched(tmp_path):
    before = digest(EDGE_SESSION)
    result = run_session(EDGE_SESSION)
    assert digest(EDGE_SESSION) == before
    assert len(result.alerts) == len(result.decisions) == 3
    assert {(a["action"], a["status"]) for d in result.decisions for a in d["actions"]} == {("alert_only", "executed")}
    assert all(a["risk_score"] is None for a in result.alerts)
    summary = output.write_session(result, EDGE_SESSION, tmp_path, None)
    assert summary["notes"]["microsoft_root"].startswith("0 of")


def test_a_run_key_that_stays_is_planned_for_restore_and_the_cleanup_is_not(tmp_path):
    result = run_session(PERSISTENCE_SESSION)
    validators = load_validators()
    assert all(validators["decision"].is_valid(d) for d in result.decisions)
    planned = [d for d in result.decisions if any(a["action"] == "restore" and a["status"] == "pending" for a in d["actions"])]
    undone = [d for d in result.decisions if d["attributes"]["fim_state"] == "matches_baseline"]
    assert planned and undone
