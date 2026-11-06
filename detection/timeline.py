"""Reading and ordering events. Shared by the rule engine and the feature extractor.

Events come from two agents and aren't in time order, so everything that keeps state must
sort first. The order matches agent/tools/label_session.py, so a labelled session and a
replayed one agree: in the same millisecond a start comes first and a stop comes last.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def parse_ts(text: object) -> datetime:
    """Raises ValueError for anything that isn't a timezone-aware ISO time."""
    if not isinstance(text, str):
        raise ValueError("ts is not a string")
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("ts has no timezone")
    return moment.astimezone(timezone.utc)


def format_ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def order_key(event: dict) -> tuple[str, int]:
    kind = event.get("event_type")
    rank = 0 if kind == "process_start" else 2 if kind == "process_stop" else 1
    ts = event.get("ts")
    return (ts if isinstance(ts, str) else "", rank)


def read_jsonl(path: Path) -> tuple[list[dict], int]:
    """Returns the objects and how many lines were unreadable. A partly written last line
    is normal while an agent is still running."""
    events, skipped = [], 0
    if not path.is_file():
        return events, skipped
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(item, dict):
            events.append(item)
        else:
            skipped += 1
    if skipped:
        log.warning("%s: %d unreadable line(s) skipped", path.name, skipped)
    return events, skipped
