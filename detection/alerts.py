"""Builds Alerts (PLANNING.md Section 5.2) and checks each one against the schema."""

import itertools
import threading
from datetime import datetime, timezone
from functools import lru_cache

from jsonschema import Draft202012Validator

from contracts.validate_samples import load_validators

# Same scheme as event IDs: the run start keeps IDs unique across runs. That matters,
# because the backend keys analyst reviews on these IDs, so a reused ID would hand a new
# decision an old approval.
RUN_START = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
_counter = itertools.count(1)
_counter_lock = threading.Lock()

# scan_file has a path and no process. The pipeline fills these in when it has one.
NO_PROCESS = {
    "pid": 0,
    "image": "unknown",
    "signed": False,
    "signer": None,
    "trusted_path": False,
    "ancestors": [],
}


def next_alert_id() -> str:
    with _counter_lock:
        return f"a-{RUN_START}-{next(_counter):06d}"


def now() -> str:
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


@lru_cache(maxsize=1)
def alert_validator() -> Draft202012Validator:
    return load_validators()["alert"]


def checked(alert: dict) -> dict:
    """A failure here is a bug in this code, so it's raised and not skipped."""
    errors = [error.message for error in alert_validator().iter_errors(alert)]
    if errors:
        raise ValueError(f"invalid alert {alert['alert_id']}: {errors}")
    return alert


def file_scan_alert(
    layer: str,
    rule_id: str,
    technique_ids: list[str],
    path: str,
    sha256: str,
    static_analysis: dict,
) -> dict:
    """risk_score stays null: it's the ML score of a process tree, and there is no process."""
    return checked(
        {
            "alert_id": next_alert_id(),
            "ts": now(),
            "layer": layer,
            "rule_id": rule_id,
            "technique_ids": technique_ids,
            "risk_score": None,
            "event_type": "file_scan",
            "static_analysis": static_analysis,
            "subject": dict(NO_PROCESS, ancestors=[]),
            "object": {
                "zone": "none",
                "path": path,
                "registry_key": None,
                "access": [],
                "file_sha256": sha256,
            },
            "evidence_event_ids": [],
        }
    )
