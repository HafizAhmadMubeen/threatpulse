"""The streaming extractor must give exactly the rows of the in-memory one, and the same events
in each tree. It is what makes a million-event session possible, so any difference is a bug."""

import csv
import json
from pathlib import Path

import pytest

from tests.event_builder import POWERSHELL, P, Recording, stamp
from tests.test_features import attack_recording, labels_for, write_session
from triage import dataset, features
from triage.features import (SessionError, compact, expand, extract_session_trees,
                             extract_session_trees_in_memory, iter_session_trees, tree_feature_row)


def make(tmp_path: Path, recording: Recording, *, labels="part", start=0.8, shuffle=False, harness_pids=()) -> tuple[Path, Path]:
    """A session folder and a labels folder. labels: 'part' (v2+), 'old' (no part column), None."""
    folder = write_session(tmp_path / "sess" / "s1", recording, labels=False, session_id="s1", batch=1,
                           pool="training-technique", technique="T1486", start_utc=stamp(start), end_utc=stamp(60))
    if shuffle:
        lines = (folder / "events.jsonl").read_text(encoding="utf-8").splitlines()[::-1]
        (folder / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    labels_dir = tmp_path / "labels"
    if labels:
        rows = labels_for(recording)
        by_id = {e["event_id"]: e for e in recording.events}
        for row in rows:
            event = by_id[row["event_id"]]
            if labels == "part":
                row["part"] = ("harness" if event["pid"] in harness_pids else
                               "test" if row["label"] == "malicious" else "background" if row["label"] == "benign" else "")
        (labels_dir / "s1").mkdir(parents=True)
        with (labels_dir / "s1" / "labels.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return folder, labels_dir


def both(folder: Path, labels_dir: Path | None, from_start: bool):
    return (extract_session_trees_in_memory(folder, labels_dir, from_start),
            extract_session_trees(folder, labels_dir, from_start))


def assert_same(old, new):
    assert [row for row, _ in old] == [row for row, _ in new]  # every column of every row, in order
    for (row, old_events), (_, new_events) in zip(old, new):
        if not row["observed_start"]:
            assert new_events == []  # only trees with an observed start keep events
            continue
        assert [e["event_id"] for e in new_events] == [e["event_id"] for e in old_events]
        assert tree_feature_row(new_events) == tree_feature_row(old_events)
        snapshots = lambda events: dataset.snapshot_rows(dataset.Tree(row, events))  # noqa: E731
        assert snapshots(new_events) == snapshots(old_events)


@pytest.mark.parametrize("labels", ["part", "old", None])
@pytest.mark.parametrize("from_start", [False, True])
@pytest.mark.parametrize("shuffle", [False, True])
def test_the_rows_and_trees_are_the_in_memory_ones(tmp_path, labels, from_start, shuffle):
    folder, labels_dir = make(tmp_path, attack_recording(), labels=labels, shuffle=shuffle)
    old, new = both(folder, labels_dir if labels else None, from_start)
    assert old and any(row["observed_start"] for row, _ in old)
    assert_same(old, new)


def test_the_harness_is_left_out_the_same_way(tmp_path):
    folder, labels_dir = make(tmp_path, attack_recording(), harness_pids=(200,))  # the test's launcher
    old, new = both(folder, labels_dir, True)
    assert_same(old, new)
    assert all(row["harness_excluded"] == 1 for row, _ in new)
    roots = {row["root_pid"] for row, _ in new}
    assert 200 not in roots and 201 in roots  # the child became the root, as before


def test_events_with_the_same_millisecond_and_a_reused_pid_come_out_the_same(tmp_path):
    recording = Recording()
    app = P(900, 1, "C:\\Windows\\notepad.exe", "notepad.exe")
    recording.start(app, 2.0)
    recording.add(app, "file_write", 3.0, path="C:\\Users\\lab\\AppData\\a.tmp")
    recording.stop(app, 3.0)
    again = P(900, 1, "C:\\Windows\\notepad.exe", "notepad.exe")   # the pid is reused
    recording.start(again, 3.0)
    recording.add(again, "file_delete", 4.0, path="C:\\Users\\lab\\Documents\\x\\a.txt")
    recording.stop(again, 5.0)
    folder, labels_dir = make(tmp_path, recording, shuffle=True)
    old, new = both(folder, labels_dir, True)
    assert len(new) >= 2
    assert_same(old, new)


def test_the_errors_are_the_same(tmp_path):
    folder, labels_dir = make(tmp_path, attack_recording())
    # Unknown part value.
    path = labels_dir / "s1" / "labels.csv"
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    first_test = next(row for row in rows if row["part"] == "test")
    first_test["part"] = "surprise"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for extract in (extract_session_trees_in_memory, extract_session_trees):
        with pytest.raises(SessionError, match="unknown part values"):
            extract(folder, labels_dir, True)
    # No labels at the given place.
    for extract in (extract_session_trees_in_memory, extract_session_trees):
        with pytest.raises(SessionError, match="no labels"):
            extract(folder, tmp_path / "nowhere", True)
    # Nothing at or after start_utc.
    folder2, labels2 = make(tmp_path / "late", attack_recording(), start=500)
    for extract in (extract_session_trees_in_memory, extract_session_trees):
        with pytest.raises(SessionError, match="no events at or after start_utc"):
            extract(folder2, labels2, True)
    # Every event is the harness.
    only_harness = Recording()
    wrapper = P(200, 100, POWERSHELL, "powershell.exe -File wrapper.ps1")
    only_harness.start(wrapper, 1.0)
    only_harness.add(wrapper, "file_write", 1.5, path="C:\\Temp\\w.tmp")
    only_harness.stop(wrapper, 2.0)
    folder3, labels3 = make(tmp_path / "allharness", only_harness, harness_pids=(200,))
    for extract in (extract_session_trees_in_memory, extract_session_trees):
        with pytest.raises(SessionError, match="harness"):
            extract(folder3, labels3, True)


def test_a_session_without_a_start_time_says_so_only_after_checking_there_are_events(tmp_path):
    folder, labels_dir = make(tmp_path, attack_recording())
    info = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    info.pop("start_utc")
    (folder / "session.json").write_text(json.dumps(info), encoding="utf-8")
    for extract in (extract_session_trees_in_memory, extract_session_trees):
        with pytest.raises(SessionError, match="no start_utc"):
            extract(folder, labels_dir, True)


def test_extract_session_returns_the_same_rows_without_holding_the_events(tmp_path):
    folder, labels_dir = make(tmp_path, attack_recording())
    assert features.extract_session(folder, labels_dir, True) == [row for row, _ in extract_session_trees_in_memory(folder, labels_dir, True)]


def test_the_trees_come_one_at_a_time(tmp_path):
    folder, labels_dir = make(tmp_path, attack_recording())
    generator = iter_session_trees(folder, labels_dir, True)
    first = next(generator)
    assert isinstance(first, tuple) and isinstance(first[0], dict)
    assert [row["tree_id"] for row, _ in [first, *generator]] == [row["tree_id"] for row, _ in extract_session_trees(folder, labels_dir, True)]


def test_labels_are_kept_as_small_codes_not_as_rows_of_text(tmp_path):
    folder, labels_dir = make(tmp_path, attack_recording())
    codes, table, has_part = features.read_label_codes(labels_dir / "s1" / "labels.csv")
    assert has_part and len(codes) == len(attack_recording().events)
    assert all(isinstance(n, int) for n in codes.values()) and 1 < len(table) <= 6  # a few distinct triples
    assert {t[1] for t in table} <= features.PARTS


def test_compact_and_expand_keep_exactly_what_the_features_read():
    for event in attack_recording().events:
        slim = expand(compact(event))
        assert slim["event_id"] == event["event_id"] and slim["ts"] == event["ts"]
        assert slim["process"] == {"signed": event["process"]["signed"]}
        assert slim["target"]["path"] == event["target"]["path"] and slim["target"]["dest_ip"] == event["target"]["dest_ip"]


def big_recording(writes: int) -> Recording:
    """One observed process that writes a lot (a Windows Update session is 92% file writes), plus a few small ones."""
    recording = Recording()
    worker = P(700, 100, POWERSHELL, "powershell.exe -File update.ps1")
    recording.start(worker, 1.0)
    for i in range(writes):
        recording.add(worker, "file_write", 2.0 + i * 0.001, path=f"C:\\Windows\\SoftwareDistribution\\Download\\part{i % 977}.tmp")
    recording.stop(worker, 2.0 + writes * 0.001 + 1)
    for pid in (710, 711, 712):
        small = P(pid, 100, "C:\\Windows\\notepad.exe", "notepad.exe")
        recording.start(small, 3.0)
        recording.add(small, "file_write", 3.5, path="C:\\Users\\lab\\AppData\\x.tmp")
        recording.stop(small, 4.0)
    return recording


def peak_bytes(call) -> int:
    import tracemalloc
    tracemalloc.start()
    try:
        call()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_streaming_holds_less_memory_than_reading_everything(tmp_path):
    folder, labels_dir = make(tmp_path, big_recording(2_000))  # tracemalloc makes this slow, so it is small
    # Rows only, like a real run: no tree keeps its events once they are used. Measured at about 0.43
    # of the in-memory peak at 2,000 and at 4,000 writes; the real figure for a session of a million
    # events is in triage/README.md.
    streaming = peak_bytes(lambda: [row for row, _ in iter_session_trees(folder, labels_dir, True)])
    in_memory = peak_bytes(lambda: [row for row, _ in extract_session_trees_in_memory(folder, labels_dir, True)])
    assert streaming < 0.6 * in_memory, (streaming, in_memory)
    # And the answer is the same.
    assert [r for r, _ in iter_session_trees(folder, labels_dir, True)] == \
        [r for r, _ in extract_session_trees_in_memory(folder, labels_dir, True)]


def test_one_huge_tree_is_handled_in_snapshots_without_the_whole_batch_in_memory(tmp_path):
    folder, labels_dir = make(tmp_path, big_recording(3_000))
    trees = dataset.load_batch(1, folder.parent, labels_dir, keep_events=False)
    huge = max(trees, key=lambda t: t.row["n_events"])
    assert huge.row["n_events"] >= 3_000 and huge.events == [] and huge.events_dropped
    snaps = dataset.snapshot_rows(huge)
    assert snaps and snaps[-1][0] == 1.0 and snaps[-1][1]["n_events"] == huge.row["n_events"]
    assert snaps[-1][1]["n_file_write"] == huge.row["n_file_write"]
