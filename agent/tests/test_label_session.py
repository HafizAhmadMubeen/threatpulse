"""Tests for label_session.py and the list of tests that may be recorded."""

import csv
import json
from pathlib import Path

import pytest

import label_session
from label_session import LabelError

CONFIG = Path(__file__).resolve().parents[1] / "config" / "recording_tests.json"
ROOT = 1000
counter = 0


def event(ts_second, event_type, pid, ppid=500, source="etw"):
    global counter
    counter += 1
    return {
        "event_id": f"e-20261106T101500-{counter:06d}",
        "ts": f"2026-11-06T10:00:{ts_second:02d}.000Z",
        "source": source,
        "event_type": event_type,
        "pid": pid,
        "ppid": ppid,
    }


def attack_session(**changes):
    session = {
        "session_id": "s1",
        "label": "malicious",
        "split": "train",
        "technique": "T1547.001",
        "network": "host-only",
        "root_pid": ROOT,
        "start_utc": "2026-11-06T10:00:01.000Z",
        "end_utc": "2026-11-06T10:00:30.000Z",
    }
    return session | changes


def write_session(folder, session, events, fim=()):
    (folder / "session.json").write_text(json.dumps(session), encoding="utf-8-sig")
    (folder / "events.jsonl").write_text("".join(json.dumps(item) + "\n" for item in events))
    (folder / "fim.jsonl").write_text("".join(json.dumps(item) + "\n" for item in fim))


def labels_by_id(folder):
    return {row["event_id"]: row["label"] for row in label_session.label_session(folder)}


def test_root_and_descendants_are_malicious(tmp_path):
    root = event(2, "process_start", ROOT)
    child = event(3, "process_start", 1001, ppid=ROOT)
    grandchild = event(4, "process_start", 1002, ppid=1001)
    write = event(5, "registry_set", 1002)
    write_session(tmp_path, attack_session(), [root, child, grandchild, write])
    assert set(labels_by_id(tmp_path).values()) == {"malicious"}


def test_unrelated_processes_are_benign(tmp_path):
    root = event(2, "process_start", ROOT)
    other = event(3, "file_write", 2000)
    write_session(tmp_path, attack_session(), [root, other])
    assert labels_by_id(tmp_path)[other["event_id"]] == "benign"


def test_a_descendant_outlives_the_root(tmp_path):
    root = event(2, "process_start", ROOT)
    child = event(3, "process_start", 1001, ppid=ROOT)
    root_stop = event(4, "process_stop", ROOT)
    late_write = event(5, "file_write", 1001)
    write_session(tmp_path, attack_session(), [root, child, root_stop, late_write])
    assert labels_by_id(tmp_path)[late_write["event_id"]] == "malicious"


def test_a_reused_pid_is_not_mislabelled(tmp_path):
    root = event(2, "process_start", ROOT)
    child = event(3, "process_start", 1001, ppid=ROOT)
    child_stop = event(4, "process_stop", 1001)
    reused = event(5, "process_start", 1001, ppid=2000)
    write = event(6, "file_write", 1001)
    write_session(tmp_path, attack_session(), [root, child, child_stop, reused, write])
    labels = labels_by_id(tmp_path)
    assert labels[reused["event_id"]] == "benign"
    assert labels[write["event_id"]] == "benign"


def test_a_child_of_a_reused_parent_pid_is_benign(tmp_path):
    root = event(2, "process_start", ROOT)
    root_stop = event(3, "process_stop", ROOT)
    child = event(4, "process_start", 3000, ppid=ROOT)
    write_session(tmp_path, attack_session(), [root, root_stop, child])
    assert labels_by_id(tmp_path)[child["event_id"]] == "benign"


def test_cleanup_is_not_labelled_as_the_attack(tmp_path):
    root = event(2, "process_start", ROOT)
    root_stop = event(3, "process_stop", ROOT)
    cleanup = event(31, "process_start", 4000, ppid=900)
    cleanup_write = event(32, "registry_set", 4000)
    write_session(tmp_path, attack_session(), [root, root_stop, cleanup, cleanup_write])
    labels = labels_by_id(tmp_path)
    assert labels[cleanup_write["event_id"]] == "benign"


def test_the_root_pid_outside_the_window_is_not_the_root(tmp_path):
    early = event(0, "process_start", ROOT)
    write_session(tmp_path, attack_session(), [early])
    with pytest.raises(LabelError):
        label_session.label_session(tmp_path)


def test_sysmon_events_follow_the_tree(tmp_path):
    root = event(2, "process_start", ROOT)
    access = event(3, "process_access", ROOT, source="sysmon")
    write_session(tmp_path, attack_session(), [root, access])
    assert labels_by_id(tmp_path)[access["event_id"]] == "malicious"


def test_fim_events_get_none(tmp_path):
    root = event(2, "process_start", ROOT)
    change = event(3, "fim_change", 0, ppid=0, source="fim")
    write_session(tmp_path, attack_session(), [root], [change])
    assert labels_by_id(tmp_path)[change["event_id"]] == "none"


def test_events_are_sorted_before_labelling(tmp_path):
    late_sysmon = event(3, "process_access", ROOT, source="sysmon")
    root = event(2, "process_start", ROOT)
    write_session(tmp_path, attack_session(), [late_sysmon, root])
    assert labels_by_id(tmp_path)[late_sysmon["event_id"]] == "malicious"


def test_a_start_in_the_same_millisecond_comes_first(tmp_path):
    write = event(2, "file_write", ROOT)
    root = event(2, "process_start", ROOT)
    write_session(tmp_path, attack_session(), [write, root])
    assert labels_by_id(tmp_path)[write["event_id"]] == "malicious"


def test_a_missing_root_is_an_error(tmp_path):
    write_session(tmp_path, attack_session(), [event(2, "file_write", 2000)])
    with pytest.raises(LabelError):
        label_session.label_session(tmp_path)


def test_benign_session_labels_everything_benign(tmp_path):
    session = attack_session(label="benign", technique=None, root_pid=None)
    items = [event(2, "process_start", 1), event(3, "file_write", 1)]
    write_session(tmp_path, session, items, [event(4, "fim_change", 0, ppid=0, source="fim")])
    assert set(labels_by_id(tmp_path).values()) == {"benign"}


def test_rows_carry_the_network_mode_and_split(tmp_path):
    write_session(tmp_path, attack_session(network="nat", split="held-out"), [event(2, "process_start", ROOT)])
    row = label_session.label_session(tmp_path)[0]
    assert (row["network"], row["split"], row["technique"]) == ("nat", "held-out", "T1547.001")


def test_main_writes_labels_csv(tmp_path, monkeypatch):
    write_session(tmp_path, attack_session(), [event(2, "process_start", ROOT)])
    monkeypatch.setattr("sys.argv", ["label_session.py", str(tmp_path)])
    assert label_session.main() == 0
    with (tmp_path / "labels.csv").open(encoding="utf-8") as file:
        assert next(csv.DictReader(file))["label"] == "malicious"


def config():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_recording_plan_matches_the_decided_numbers():
    tests = config()["tests"]
    assert sum(test["runs"] for test in tests if test["split"] == "train") == 30
    assert sum(test["runs"] for test in tests if test["split"] == "held-out") == 9
    assert (config()["benign"]["sessions"], config()["benign"]["nat_sessions"]) == (15, 5)


def test_the_tests_that_remove_sysmon_are_not_allowed():
    numbers = {test["number"] for test in config()["tests"] if test["technique"] == "T1685"}
    assert numbers == {51}


def test_only_t1105_needs_nat():
    assert {test["id"] for test in config()["tests"] if test["network"] == "nat"} == {"T1105-29"}


def test_atomic_tests_have_numbers_and_scripts_have_files():
    tools = CONFIG.parents[1] / "tools"
    for test in config()["tests"]:
        if test["kind"] == "atomic":
            assert isinstance(test["number"], int)
        else:
            assert (tools / test["script"]).exists()
