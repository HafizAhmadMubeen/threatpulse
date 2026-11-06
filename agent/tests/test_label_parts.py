"""Tests for the part column (test, harness, background) and the label_session outputs."""

import csv

import pytest

import label_session
from label_session import LabelError
from test_label_session import ROOT, attack_session, event, load_plan, write_session

ATOMIC = "edb5039ae07216bf322fdba07b6f686d7c088a03"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
SYSTEM32 = "C:\\Windows\\System32\\"


def atomic_session(**changes):
    return attack_session(atomic_commit=ATOMIC, **changes)


def parts_by_id(folder):
    return {row["event_id"]: (row["label"], row["part"]) for row in label_session.label_session(folder)}


def wrapped_run():
    """The wrapper, its three helpers, a command shell that runs the test, and what that starts."""
    return {
        "root": event(2, "process_start", ROOT, image=POWERSHELL),
        "root_write": event(2, "file_write", ROOT),
        "conhost": event(3, "process_start", 1001, ppid=ROOT, image=SYSTEM32 + "conhost.exe"),
        "hostname": event(3, "process_start", 1002, ppid=ROOT, image=SYSTEM32 + "HOSTNAME.EXE"),
        "whoami": event(3, "process_start", 1003, ppid=ROOT, image=SYSTEM32 + "whoami.exe"),
        "helper_child": event(4, "process_start", 1004, ppid=1002, image=SYSTEM32 + "other.exe"),
        "shell": event(5, "process_start", 1005, ppid=ROOT, image=SYSTEM32 + "cmd.exe"),
        "shell_write": event(5, "file_write", 1005),
        "tool": event(6, "process_start", 1006, ppid=1005, image=SYSTEM32 + "reg.exe"),
        "tool_set": event(6, "registry_set", 1006),
        "shell_conhost": event(6, "process_start", 1007, ppid=1005, image=SYSTEM32 + "conhost.exe"),
    }


def test_the_wrapper_is_harness_and_the_test_process_is_test(tmp_path):
    run = wrapped_run()
    write_session(tmp_path, atomic_session(), list(run.values()))
    parts = parts_by_id(tmp_path)
    for name in ("root", "root_write", "conhost", "hostname", "whoami", "helper_child"):
        assert parts[run[name]["event_id"]] == ("malicious", "harness"), name
    for name in ("shell", "shell_write", "tool", "tool_set", "shell_conhost"):
        assert parts[run[name]["event_id"]] == ("malicious", "test"), name


def test_a_conhost_below_the_test_belongs_to_the_test(tmp_path):
    run = wrapped_run()
    write_session(tmp_path, atomic_session(), list(run.values()))
    assert parts_by_id(tmp_path)[run["shell_conhost"]["event_id"]] == ("malicious", "test")


def test_our_own_script_is_all_test(tmp_path):
    items = [
        event(2, "process_start", ROOT, image=POWERSHELL),
        event(3, "file_write", ROOT),
        event(3, "process_start", 1001, ppid=ROOT, image=SYSTEM32 + "conhost.exe"),
    ]
    write_session(tmp_path, attack_session(), items)
    assert {part for _, part in parts_by_id(tmp_path).values()} == {"test"}


def test_a_wrapper_with_no_test_process_is_an_error(tmp_path):
    items = [
        event(2, "process_start", ROOT, image=POWERSHELL),
        event(3, "process_start", 1002, ppid=ROOT, image=SYSTEM32 + "HOSTNAME.EXE"),
    ]
    write_session(tmp_path, atomic_session(), items)
    with pytest.raises(LabelError, match="only to the wrapper"):
        label_session.label_session(tmp_path)


def test_other_processes_and_fim_are_background(tmp_path):
    run = wrapped_run()
    other = event(3, "file_write", 2000)
    change = event(4, "fim_change", 0, ppid=0, source="fim")
    write_session(tmp_path, atomic_session(), [*run.values(), other], [change])
    parts = parts_by_id(tmp_path)
    assert parts[other["event_id"]] == ("benign", "background")
    assert parts[change["event_id"]] == ("none", "background")


def test_a_benign_session_is_all_background(tmp_path):
    session = attack_session(label="benign", technique=None, root_pid=None)
    write_session(tmp_path, session, [event(2, "process_start", 1), event(3, "file_write", 1)])
    assert set(parts_by_id(tmp_path).values()) == {("benign", "background")}


def test_the_wrapper_events_stay_malicious_in_label(tmp_path):
    """label is the tree label, which is why training has to use part."""
    run = wrapped_run()
    write_session(tmp_path, atomic_session(), list(run.values()))
    assert {label for label, _ in parts_by_id(tmp_path).values()} == {"malicious"}


def test_warmup_seconds_defaults_to_zero_and_is_carried(tmp_path):
    write_session(tmp_path, attack_session(), [event(2, "process_start", ROOT)])
    assert label_session.label_session(tmp_path)[0]["warmup_seconds"] == 0

    write_session(tmp_path, attack_session(warmup_seconds=60), [event(2, "process_start", ROOT)])
    assert label_session.label_session(tmp_path)[0]["warmup_seconds"] == 60


def test_the_csv_has_the_documented_columns(tmp_path, monkeypatch):
    write_session(tmp_path, attack_session(), [event(2, "process_start", ROOT)])
    monkeypatch.setattr("sys.argv", ["label_session.py", str(tmp_path)])
    assert label_session.main() == 0
    with (tmp_path / "labels.csv").open(encoding="utf-8") as file:
        assert next(csv.reader(file)) == [
            "event_id", "label", "part", "technique", "pool", "session_id", "network", "warmup_seconds"
        ]


def test_out_leaves_the_session_folder_alone(tmp_path, monkeypatch):
    session = tmp_path / "exported" / "s1"
    session.mkdir(parents=True)
    write_session(session, attack_session(), [event(2, "process_start", ROOT)])
    out = tmp_path / "labels-v2"
    monkeypatch.setattr("sys.argv", ["label_session.py", str(session), "--out", str(out)])
    assert label_session.main() == 0
    assert (out / "labels.csv").exists()
    assert not (session / "labels.csv").exists()


def test_out_never_overwrites(tmp_path, monkeypatch, capsys):
    session = tmp_path / "s1"
    session.mkdir()
    write_session(session, attack_session(), [event(2, "process_start", ROOT)])
    out = tmp_path / "labels-v2"
    out.mkdir()
    (out / "labels.csv").write_text("keep me")
    monkeypatch.setattr("sys.argv", ["label_session.py", str(session), "--out", str(out)])
    assert label_session.main() == 1
    assert (out / "labels.csv").read_text() == "keep me"
    assert "not overwritten" in capsys.readouterr().err


def test_batch_labels_each_session_into_its_own_folder(tmp_path, monkeypatch):
    batch = tmp_path / "batch-01"
    for name in ("s1", "s2"):
        (batch / name).mkdir(parents=True)
        write_session(batch / name, attack_session(session_id=name), [event(2, "process_start", ROOT)])
    (batch / "not-a-session").mkdir()
    out = tmp_path / "batch-01-labels-v2"
    monkeypatch.setattr("sys.argv", ["label_session.py", "--batch", str(batch), "--out", str(out)])
    assert label_session.main() == 0
    assert sorted(path.name for path in out.iterdir()) == ["s1", "s2"]
    assert not list(batch.rglob("labels.csv"))


def test_batch_needs_out(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["label_session.py", "--batch", str(tmp_path)])
    with pytest.raises(SystemExit) as stopped:
        label_session.main()
    assert stopped.value.code == 2


def test_the_plan_has_one_extra_run_at_the_end_of_batch_5():
    batch = load_plan()["batches"][4]
    extras = [session for session in batch["sessions"] if session.get("extra")]
    assert [(s["test_id"], s["run"]) for s in extras] == [("T1547.001-2", 6)]
    assert batch["sessions"][-1] == extras[0]


# The -Cleanup process is started by the recording script, which also started the test's
# root, so both have the same parent. record_session.ps1 runs it after the end time.
RECORDER = 500
CLEANUP_ROOT = 4000
AFTER_END = 40  # seconds; the test ends at 30


def cleanup_run(pid=CLEANUP_ROOT, cmdline="powershell -File x.ps1 -Cleanup", ppid=RECORDER):
    root = event(AFTER_END, "process_start", pid, ppid=ppid, image=POWERSHELL)
    root["process"]["cmdline"] = cmdline
    return {
        "root": root,
        "delete": event(AFTER_END + 1, "file_delete", pid),
        "child": event(AFTER_END + 1, "process_start", 4001, ppid=pid, image=SYSTEM32 + "conhost.exe"),
        "child_write": event(AFTER_END + 2, "file_write", 4001),
    }


def test_the_cleanup_tree_of_our_own_script_is_harness(tmp_path):
    test_root = event(2, "process_start", ROOT, ppid=RECORDER, image=POWERSHELL)
    test_write = event(3, "file_write", ROOT)
    cleanup = cleanup_run()
    write_session(tmp_path, attack_session(), [test_root, test_write, *cleanup.values()])
    parts = parts_by_id(tmp_path)
    assert parts[test_write["event_id"]] == ("malicious", "test")
    for name, item in cleanup.items():
        assert parts[item["event_id"]] == ("malicious", "harness"), name


def test_the_cleanup_tree_of_an_atomic_test_is_harness(tmp_path):
    run = wrapped_run()
    run["root"]["ppid"] = RECORDER
    cleanup = cleanup_run()
    write_session(tmp_path, atomic_session(), [*run.values(), *cleanup.values()])
    parts = parts_by_id(tmp_path)
    assert {parts[item["event_id"]] for item in cleanup.values()} == {("malicious", "harness")}
    assert parts[run["shell_write"]["event_id"]] == ("malicious", "test")


def test_a_recorded_cleanup_pid_picks_the_cleanup(tmp_path):
    test_root = event(2, "process_start", ROOT, ppid=RECORDER, image=POWERSHELL)
    test_write = event(3, "file_write", ROOT)
    cleanup = cleanup_run(cmdline=None)
    other = cleanup_run(pid=4500)  # another PowerShell from the recording script, not the cleanup
    other_list = list(other.values())
    session = attack_session(cleanup_root_pid=CLEANUP_ROOT)
    write_session(tmp_path, session, [test_root, test_write, *cleanup.values(), *other_list])
    parts = parts_by_id(tmp_path)
    assert parts[cleanup["delete"]["event_id"]] == ("malicious", "harness")
    assert parts[other["root"]["event_id"]] == ("benign", "background")


def test_a_powershell_after_the_end_without_the_cleanup_flag_is_background(tmp_path):
    test_root = event(2, "process_start", ROOT, ppid=RECORDER, image=POWERSHELL)
    test_write = event(3, "file_write", ROOT)
    cleanup = cleanup_run(cmdline="powershell -File something_else.ps1")
    write_session(tmp_path, attack_session(), [test_root, test_write, *cleanup.values()])
    assert parts_by_id(tmp_path)[cleanup["delete"]["event_id"]] == ("benign", "background")


def test_a_sibling_started_before_the_end_is_not_the_cleanup(tmp_path):
    test_root = event(2, "process_start", ROOT, ppid=RECORDER, image=POWERSHELL)
    test_write = event(3, "file_write", ROOT)
    early = event(10, "process_start", 4100, ppid=RECORDER, image=POWERSHELL)
    early["process"]["cmdline"] = "powershell -Cleanup"
    early_write = event(11, "file_write", 4100)
    write_session(tmp_path, attack_session(), [test_root, test_write, early, early_write])
    assert parts_by_id(tmp_path)[early_write["event_id"]] == ("benign", "background")


def test_a_session_without_cleanup_still_labels(tmp_path):
    test_root = event(2, "process_start", ROOT, ppid=RECORDER, image=POWERSHELL)
    write_session(tmp_path, attack_session(), [test_root, event(3, "file_write", ROOT)])
    assert {part for _, part in parts_by_id(tmp_path).values()} == {"test"}
