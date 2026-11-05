"""Local JSON store for analyst reviews.

Reviews are kept apart from the data directory, so the samples and the pipeline's
output are never edited. They are layered over the decisions when read.
"""

import json
import os
import threading
from pathlib import Path


def empty_store() -> dict:
    return {"decisions": {}, "fim_changes": {}}


class ReviewStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()  # held across check-then-write, so a review can't happen twice
        self._state = self._read()

    def _read(self) -> dict:
        if not self.path.is_file():
            return empty_store()
        return {**empty_store(), **json.loads(self.path.read_text(encoding="utf-8"))}

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as output:
            json.dump(self._state, output, indent=2, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.path)  # a crash leaves the old file or the new one, never half

    def decision_reviews(self, decision_id: str) -> dict[str, dict]:
        """Maps an action name to its review."""
        return self._state["decisions"].get(decision_id, {})

    def add_decision_review(self, decision_id: str, action: str, review: dict) -> None:
        with self.lock:
            self._state["decisions"].setdefault(decision_id, {})[action] = review
            self._write()

    def fim_review(self, event_id: str) -> dict | None:
        return self._state["fim_changes"].get(event_id)

    def add_fim_review(self, event_id: str, review: dict) -> None:
        with self.lock:
            self._state["fim_changes"][event_id] = review
            self._write()
