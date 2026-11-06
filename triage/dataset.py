"""The training and evaluation sets (PHASES.md step 3.4), built from exported batches.

Rules, all from CLAUDE.md "ML rules" and PLANNING.md:
- Features come from triage.features with the harness left out and events before each
  session's start_utc dropped (sensor start and warm-up).
- Only trees whose start was observed are used. Without that, "no start event" would be
  learned as benign.
- Split by whole batch, never by event or by session inside a batch.
- Held-out techniques are used for evaluation only: never for training or tuning. A whole
  held-out SESSION is kept out of training, background trees included.
- Positives are trees with test-part malicious events. Everything else is negative: benign
  sessions, and the background trees of attack sessions.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from triage.features import SessionError, extract_session_trees

log = logging.getLogger(__name__)

HELD_OUT_TECHNIQUES = ("T1053.005", "T1685", "T1218.011")
HELD_OUT_POOL = "held-out"


class DatasetError(ValueError):
    pass


@dataclass
class Tree:
    row: dict
    events: list[dict]

    @property
    def positive(self) -> bool:
        return self.row["label"] == "malicious"

    @property
    def held_out(self) -> bool:
        return self.row["pool"] == HELD_OUT_POOL

    @property
    def usable(self) -> bool:
        return self.row["observed_start"] == 1 and self.row["harness_excluded"] == 1


def session_folders(sessions_dir: Path) -> list[Path]:
    folders = sorted(p for p in sessions_dir.iterdir() if (p / "events.jsonl").is_file())
    if not folders:
        raise DatasetError(f"{sessions_dir}: no session folders")
    return folders


def check_pool(tree: Tree) -> None:
    """The pool and the technique list must agree, so a held-out technique can't end up in
    training because a session was filed under the wrong pool (or the reverse)."""
    technique = tree.row["technique"]
    if tree.positive and (technique in HELD_OUT_TECHNIQUES) != tree.held_out:
        raise DatasetError(
            f"{tree.row['session_id']}: technique {technique!r} and pool {tree.row['pool']!r} disagree "
            f"about whether it is held out ({HELD_OUT_TECHNIQUES})"
        )


def load_batch(number: int, sessions_dir: Path, labels_dir: Path) -> list[Tree]:
    trees: list[Tree] = []
    for folder in session_folders(sessions_dir):
        try:
            pairs = extract_session_trees(folder, labels_dir, from_start=True)
        except SessionError as error:
            raise DatasetError(str(error)) from error
        for row, events in pairs:
            if row["batch"] != number:
                raise DatasetError(f"{folder.name}: session.json says batch {row['batch']}, expected {number}")
            if row["harness_excluded"] != 1:
                raise DatasetError(f"{folder.name}: labels have no part column, so the harness was not left out")
            tree = Tree(row, events if row["observed_start"] == 1 else [])  # events only for usable trees
            check_pool(tree)
            trees.append(tree)
    return trees


def training_trees(batches: dict[int, list[Tree]], numbers: list[int]) -> list[Tree]:
    return [t for n in numbers for t in batches[n] if t.usable and not t.held_out]


def evaluation_trees(batch: list[Tree]) -> tuple[list[Tree], list[Tree]]:
    """(ordinary test trees, held-out technique trees) of one batch."""
    usable = [t for t in batch if t.usable]
    return [t for t in usable if not t.held_out], [t for t in usable if t.held_out]


def balance_table(batches: dict[int, list[Tree]]) -> list[dict]:
    """Rows per batch, pool group and class, before and after the filters."""
    table = []
    for number, trees in sorted(batches.items()):
        for group, members in (("training", [t for t in trees if not t.held_out]),
                               ("held-out", [t for t in trees if t.held_out])):
            table.append({
                "batch": number, "group": group,
                "positive_trees": sum(t.positive and t.usable for t in members),
                "negative_trees": sum((not t.positive) and t.usable for t in members),
                "unobserved_start_dropped": sum(not t.usable for t in members),
            })
    return table
