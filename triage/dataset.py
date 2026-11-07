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
from dataclasses import dataclass, field
from pathlib import Path

from detection.timeline import parse_ts
from triage.features import SessionError, extract_session_trees, order_key, tree_feature_row

log = logging.getLogger(__name__)

HELD_OUT_TECHNIQUES = ("T1053.005", "T1685", "T1218.011")
HELD_OUT_POOL = "held-out"
# Documented limitation: LSA protection blocks the dump, so the test part has almost nothing
# to see (2 events). It is reported on its own and never counts toward the model's recall.
LIMITATION_TECHNIQUES = ("T1003.001",)


# A snapshot is a tree as it looked part-way through: its events up to this fraction of the
# tree's own time span. Fixed in advance. A partial snapshot with fewer events than the
# minimum has nothing to say yet (a lone process start looks the same for every program),
# so it is not used. The complete tree always is.
SNAPSHOT_FRACTIONS = (0.1, 0.25, 0.5, 0.75, 1.0)
MIN_SNAPSHOT_EVENTS = 2


class DatasetError(ValueError):
    pass


@dataclass
class Tree:
    row: dict
    events: list[dict]
    snapshot_cache: list | None = field(default=None, repr=False, compare=False)

    @property
    def positive(self) -> bool:
        return self.row["label"] == "malicious"

    @property
    def limited(self) -> bool:
        """An attack tree of a technique with a documented limitation (T1003.001)."""
        return self.positive and self.row["technique"] in LIMITATION_TECHNIQUES

    @property
    def held_out(self) -> bool:
        return self.row["pool"] == HELD_OUT_POOL

    @property
    def usable(self) -> bool:
        return self.row["observed_start"] == 1 and self.row["harness_excluded"] == 1


def all_session_folders(sessions_dir: Path) -> list[Path]:
    return sorted(p for p in sessions_dir.iterdir() if (p / "events.jsonl").is_file())


def unlabelled_sessions(sessions_dir: Path, labels_dir: Path) -> list[str]:
    """Sessions with no labels.csv in the labels folder. Used only when a batch holds
    sessions that were decided out (batch 3's first attempt), and always reported by name."""
    return [p.name for p in all_session_folders(sessions_dir) if not (labels_dir / p.name / "labels.csv").is_file()]


def session_folders(sessions_dir: Path, labels_dir: Path | None = None, only_labelled: bool = False) -> list[Path]:
    """Every session folder. With `only_labelled`, only those the labels folder covers: a
    session without labels is then left out on purpose, and a missing labels.csv is no error.
    Without it (the default) a session without labels stops the run."""
    folders = all_session_folders(sessions_dir)
    if only_labelled:
        if labels_dir is None:
            raise DatasetError("only_labelled needs a labels folder")
        folders = [p for p in folders if (labels_dir / p.name / "labels.csv").is_file()]
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


def load_batch(number: int, sessions_dir: Path, labels_dir: Path, only_labelled: bool = False) -> list[Tree]:
    trees: list[Tree] = []
    for folder in session_folders(sessions_dir, labels_dir, only_labelled):
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


def training_trees(batches: dict[int, list[Tree]], numbers: list[int], exclude_limited: bool = False) -> list[Tree]:
    """The trees a model trains on. `exclude_limited` leaves out the documented-limitation attack
    trees (T1003.001). Their benign neighbours in the same sessions always stay."""
    return [t for n in numbers for t in batches[n]
            if t.usable and not t.held_out and not (exclude_limited and t.limited)]


def evaluation_trees(batch: list[Tree]) -> tuple[list[Tree], list[Tree]]:
    """(ordinary test trees, held-out technique trees) of one batch. The documented-limitation
    attack trees are in neither: see limited_trees. Their benign neighbours stay negatives."""
    usable = [t for t in batch if t.usable and not t.limited]
    return [t for t in usable if not t.held_out], [t for t in usable if t.held_out]


def limited_trees(batch: list[Tree]) -> list[Tree]:
    return [t for t in batch if t.usable and t.limited]


def balance_table(batches: dict[int, list[Tree]]) -> list[dict]:
    """Rows per batch, pool group and class, before and after the filters."""
    table = []
    for number, trees in sorted(batches.items()):
        for group, members in (("training", [t for t in trees if not t.held_out]),
                               ("held-out", [t for t in trees if t.held_out])):
            table.append({
                "batch": number, "group": group,
                "positive_trees": sum(t.positive and t.usable and not t.limited for t in members),
                "documented_limitation_trees": sum(t.limited and t.usable for t in members),
                "negative_trees": sum((not t.positive) and t.usable for t in members),
                "unobserved_start_dropped": sum(not t.usable for t in members),
            })
    return table


def snapshot_rows(tree: Tree) -> list[tuple[float, dict]]:
    """(fraction, row) for each distinct snapshot of one tree, features from the same code
    that score_process runs. The row keeps the tree's metadata and label: a snapshot of an
    attack tree is still an attack tree, and a snapshot of a benign tree is still benign.

    Cuts are by time, because that is how a tree grows while an alert waits for its
    verdict. Two cuts that keep the same events are one snapshot (the later fraction is
    kept). Built from the tree's own events: no label and no harness is read here."""
    if tree.snapshot_cache is not None:
        return tree.snapshot_cache
    ordered = sorted(tree.events, key=order_key)
    if not ordered:
        return []
    times = [parse_ts(e["ts"]).timestamp() for e in ordered]
    first, last = times[0], times[-1]
    found: dict[int, float] = {}
    for fraction in SNAPSHOT_FRACTIONS:
        cut = first + (last - first) * fraction
        count = sum(1 for t in times if t <= cut + 1e-9)
        # The whole tree is always a snapshot, so no complete-tree row is lost. A partial
        # one needs enough events to say something.
        if count >= MIN_SNAPSHOT_EVENTS or fraction == 1.0:
            found[count] = fraction
    rows = []
    for count, fraction in sorted(found.items()):
        features = tree_feature_row(ordered[:count])
        if features is not None:
            rows.append((fraction, {**tree.row, **features, "n_events": count}))
    tree.snapshot_cache = rows
    return rows


def snapshot_training_rows(trees: list[Tree]) -> list[dict]:
    return [row for tree in trees for _, row in snapshot_rows(tree)]
