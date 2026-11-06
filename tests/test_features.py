"""Feature extraction tests. The sessions are built here, because contracts/samples has no
session.json or labels.csv."""

import copy
import csv
import json
from pathlib import Path

import pytest

from tests.event_builder import CMD, DOCS, POWERSHELL, RUN_KEY, P, Recording
from triage import features
from triage.features import COLUMNS, FEATURE_COLUMNS, METADATA_COLUMNS, SessionError, extract_session

FORBIDDEN_WORDS = {"name", "path", "cmd", "cmdline", "image", "ext", "extension", "trusted", "rule", "user", "hash"}
NOT_FEATURES = {"session_id", "tree_id", "pool", "batch", "label", "technique", "network", "activity"}

# Columns that count only ETW events. Sysmon events must never change them.
ETW_ONLY = [
    "n_file_create", "n_file_write", "n_file_rename", "n_file_delete", "n_registry_set",
    "n_network_connect", "rate_file_create", "rate_file_write", "rate_file_rename",
    "rate_file_delete", "rate_registry_set", "peak_file_ops_10s", "peak_destructive_ops_30s",
    "n_distinct_dest_ips", "n_distinct_dest_ports", "n_document_file_events",
    "n_document_deletes", "n_persistence_registry_sets", "n_startup_folder_events",
    "n_hosts_file_events",
]


def attack_recording(names: dict | None = None) -> Recording:
    """An 'already running' launcher, a tree under it that deletes documents, writes a Run key
    and reads LSASS, and a separate benign process. `names` renames everything a feature must ignore."""
    n = names or {}
    image = lambda default: n.get("image", default)  # noqa: E731
    leaf = n.get("leaf", "dummy")
    ext = n.get("ext", ".locked")
    ip = n.get("ip", "192.0.2.10")
    value = n.get("value", "Test")

    recording = Recording()
    running = P(100, 50, image(POWERSHELL), n.get("cmd", "powershell.exe -File x.ps1"))
    root = P(200, 100, image(POWERSHELL), n.get("cmd", "powershell.exe -File t.ps1"))
    child = P(201, 200, image(CMD), n.get("cmd", "cmd.exe /c a"))
    grandchild = P(202, 201, image("C:\\Users\\lab\\x.exe"), n.get("cmd", "x.exe"), signed=False)
    benign = P(300, 100, image("C:\\Windows\\notepad.exe"), n.get("cmd", "notepad.exe"))

    recording.add(running, "file_write", 0.5, path="C:\\Temp\\background.tmp")
    recording.start(root, 1.0)
    recording.start(child, 1.5)
    recording.start(grandchild, 2.0)
    for index in range(25):
        recording.add(grandchild, "file_write", 3 + index * 0.2, path=f"{DOCS}\\{leaf}{index}{ext}")
        recording.add(grandchild, "file_delete", 3.1 + index * 0.2, path=f"{DOCS}\\{leaf}{index}.txt")
    recording.add(grandchild, "file_create", 9.0, path=f"C:\\Temp\\{leaf}.tmp")
    recording.add(grandchild, "registry_set", 10.0, registry_key=RUN_KEY.replace("Test", value))
    recording.add(grandchild, "network_connect", 11.0, dest_ip=ip, dest_port=443)
    recording.add(grandchild, "network_connect", 11.5, dest_ip=ip, dest_port=80)
    recording.add(child, "process_access", 12.0, source="sysmon", path="C:\\Windows\\System32\\lsass.exe",
                  pid=712, access_rights=["vm_read", "query_information"])
    recording.fim(15.0, registry_key=RUN_KEY.replace("Test", value))
    recording.stop(grandchild, 20.0)

    recording.start(benign, 5.0)
    recording.add(benign, "file_write", 6.0, path="C:\\Users\\lab\\AppData\\x.tmp")
    recording.stop(benign, 30.0)
    return recording


def labels_for(recording: Recording) -> list[dict]:
    malicious_pids = {200, 201, 202}
    rows = []
    for event in recording.events:
        bad = event["pid"] in malicious_pids
        rows.append({
            "event_id": event["event_id"],
            "label": "none" if event["source"] == "fim" else "malicious" if bad else "benign",
            "technique": "T1486" if bad else "",
            "pool": "training-technique",
            "session_id": "s-1",
            "network": "host-only",
        })
    return rows


def write_session(folder: Path, recording: Recording, labels: bool = True, **session) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    agent = [e for e in recording.events if e["source"] != "fim"]
    fim = [e for e in recording.events if e["source"] == "fim"]
    (folder / "events.jsonl").write_text("\n".join(json.dumps(e) for e in agent) + "\n", encoding="utf-8")
    (folder / "fim.jsonl").write_text("\n".join(json.dumps(e) for e in fim) + "\n", encoding="utf-8")
    info = {"session_id": "s-1", "pool": "training-technique", "batch": 3, "network": "host-only",
            "label": "malicious", "technique": "T1486", **session}
    (folder / "session.json").write_text(json.dumps(info), encoding="utf-8-sig")
    if labels:
        rows = labels_for(recording)
        with (folder / "labels.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return folder


def by_root(rows: list[dict]) -> dict[int, dict]:
    return {int(row["root_pid"]): row for row in rows}


@pytest.fixture
def rows(tmp_path):
    return extract_session(write_session(tmp_path / "s", attack_recording()))


# Trees


def test_one_row_per_process_tree(rows):
    assert sorted(by_root(rows)) == [100, 200, 300]
    assert len({row["tree_id"] for row in rows}) == 3


def test_a_root_is_a_process_whose_parent_was_never_seen_starting(rows):
    trees = by_root(rows)
    assert trees[200]["observed_start"] == 1
    assert trees[300]["observed_start"] == 1  # its parent, pid 100, has no start event
    assert trees[100]["observed_start"] == 0  # running before recording began


def test_the_tree_is_built_from_parents_and_not_from_the_label(rows):
    tree = by_root(rows)[200]
    assert tree["n_processes"] == 3
    assert tree["n_children_of_root"] == 1
    assert tree["max_depth"] == 2
    assert by_root(rows)[300]["n_processes"] == 1


def test_the_trees_do_not_depend_on_the_recorded_root_pid(tmp_path):
    """root_pid in session.json is the labeller's input. If trees used it, attack and benign
    trees would differ by construction."""
    a = extract_session(write_session(tmp_path / "a", attack_recording(), root_pid=200))
    b = extract_session(write_session(tmp_path / "b", attack_recording(), root_pid=201))
    assert feature_values(a) == feature_values(b)
    assert [r["root_pid"] for r in a] == [r["root_pid"] for r in b]


def test_labels_come_from_the_events(rows):
    trees = by_root(rows)
    assert trees[200]["label"] == "malicious"
    assert trees[200]["technique"] == "T1486"
    assert int(trees[200]["n_malicious_events"]) > 0
    assert trees[300]["label"] == "benign"
    assert trees[100]["label"] == "benign"


def test_a_session_with_no_labels_says_so(tmp_path):
    rows = extract_session(write_session(tmp_path / "s", attack_recording(), labels=False))
    assert {row["label"] for row in rows} == {"unlabelled"}


def test_metadata_comes_from_session_json(rows):
    for row in rows:
        assert (row["session_id"], row["pool"], row["batch"], row["network"]) == ("s-1", "training-technique", 3, "host-only")


def test_a_reused_pid_is_a_separate_tree(tmp_path):
    recording = Recording()
    first, second = P(500, 1, "C:\\a.exe"), P(500, 1, "C:\\b.exe")
    recording.start(first, 1.0)
    recording.stop(first, 2.0)
    recording.start(second, 5.0)
    recording.add(second, "file_write", 6.0, path="C:\\Temp\\x")
    rows = extract_session(write_session(tmp_path / "s", recording, labels=False))
    assert len(rows) == 2
    assert [int(r["n_file_write"]) for r in rows] == [0, 1]


# Features


def test_activity_counts_and_rates(rows):
    tree = by_root(rows)[200]
    assert tree["n_file_write"] == 25
    assert tree["n_file_delete"] == 25
    assert tree["n_file_create"] == 1
    assert tree["n_registry_set"] == 1
    assert tree["n_network_connect"] == 2
    assert tree["rate_file_delete"] == pytest.approx(25 / 19.0, abs=0.01)
    assert tree["duration_s"] == pytest.approx(19.0, abs=0.01)


def test_bursts(rows):
    tree = by_root(rows)[200]
    assert tree["peak_destructive_ops_30s"] == 25
    assert tree["peak_file_ops_10s"] >= 25


def test_zones_touched(rows):
    tree = by_root(rows)[200]
    assert tree["n_document_file_events"] == 50
    assert tree["n_document_deletes"] == 25
    assert tree["n_persistence_registry_sets"] == 1
    assert tree["n_zones_touched"] == 4  # documents, persistence, network, lsass
    benign = by_root(rows)[300]
    assert benign["n_zones_touched"] == 0 and benign["n_document_file_events"] == 0


def test_network_shape_is_counts_only(rows):
    tree = by_root(rows)[200]
    assert (tree["n_distinct_dest_ips"], tree["n_distinct_dest_ports"]) == (1, 2)


def test_sysmon_signals(rows):
    tree = by_root(rows)[200]
    assert tree["sysmon_lsass_access"] == 1
    assert tree["sysmon_lsass_vm_read"] == 1
    assert by_root(rows)[300]["sysmon_lsass_access"] == 0


def test_signing(rows):
    tree = by_root(rows)[200]
    assert tree["n_unsigned_processes"] == 1
    assert tree["signed_fraction"] == pytest.approx(2 / 3, abs=0.001)
    assert tree["root_signed"] == 1


def test_a_fim_change_is_linked_to_the_tree_that_wrote_the_item(rows):
    assert by_root(rows)[200]["n_fim_changes_linked"] == 1
    assert by_root(rows)[300]["n_fim_changes_linked"] == 0


def test_a_fim_change_is_not_linked_to_a_write_that_came_after_it(tmp_path):
    recording = Recording()
    writer = P(200, 1, "C:\\a.exe")
    recording.fim(1.0, registry_key=RUN_KEY)
    recording.add(writer, "registry_set", 5.0, registry_key=RUN_KEY)
    rows = extract_session(write_session(tmp_path / "s", recording, labels=False))
    assert [r["n_fim_changes_linked"] for r in rows] == [0]


def test_a_fim_change_long_after_a_write_is_not_linked(tmp_path):
    recording = Recording()
    recording.add(P(200, 1, "C:\\a.exe"), "registry_set", 1.0, registry_key=RUN_KEY)
    recording.fim(1.0 + features.FIM_LINK_SECONDS + 1, registry_key=RUN_KEY)
    rows = extract_session(write_session(tmp_path / "s", recording, labels=False))
    assert [r["n_fim_changes_linked"] for r in rows] == [0]


def test_a_fim_change_links_to_one_tree_only(tmp_path):
    recording = Recording()
    for pid, when in ((200, 1.0), (201, 2.0)):
        recording.add(P(pid, 1, "C:\\a.exe"), "registry_set", when, registry_key=RUN_KEY)
    recording.fim(3.0, registry_key=RUN_KEY)
    rows = extract_session(write_session(tmp_path / "s", recording, labels=False))
    assert sorted(int(r["n_fim_changes_linked"]) for r in rows) == [0, 1]
    assert by_root(rows)[201]["n_fim_changes_linked"] == 1  # the latest writer


def test_the_same_key_written_as_hku_links_to_hkcu(tmp_path):
    recording = Recording()
    recording.add(P(200, 1, "C:\\a.exe"), "registry_set", 1.0,
                  registry_key="HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test")
    recording.fim(2.0, registry_key=RUN_KEY)
    assert extract_session(write_session(tmp_path / "s", recording, labels=False))[0]["n_fim_changes_linked"] == 1


# No names, no paths, no command lines, no double counting


def feature_values(rows: list[dict]) -> list[dict]:
    return [{name: row[name] for name in FEATURE_COLUMNS} for row in rows]


def test_renaming_everything_changes_no_feature(tmp_path):
    original = extract_session(write_session(tmp_path / "a", attack_recording()))
    renamed = extract_session(write_session(tmp_path / "b", attack_recording({
        "image": "C:\\Q\\zzz_unrelated.exe",
        "cmd": "totally different command line --with --flags",
        "leaf": "qqq", "ext": ".xyz", "ip": "198.51.100.77", "value": "Other",
    })))
    assert feature_values(renamed) == feature_values(original)


def test_the_process_name_of_a_known_tool_gets_no_special_treatment(tmp_path):
    plain = attack_recording()
    for event in plain.events:
        if event["pid"] == 202:
            event["process"]["image"] = "C:\\Tools\\mimikatz.exe"
            event["process"]["cmdline"] = "mimikatz.exe sekurlsa::logonpasswords"
    base = extract_session(write_session(tmp_path / "a", attack_recording()))
    assert feature_values(extract_session(write_session(tmp_path / "b", plain))) == feature_values(base)


def test_sysmon_duplicates_do_not_change_etw_counts(tmp_path):
    original = attack_recording()
    doubled = copy.deepcopy(original)
    extra = []
    for event in original.events:
        if event["source"] == "etw" and event["event_type"] in ("registry_set", "network_connect", "file_create"):
            copy_ = copy.deepcopy(event)
            copy_["source"] = "sysmon"
            copy_["event_id"] = event["event_id"].replace("-0000", "-1000")
            extra.append(copy_)
    doubled.events += extra
    a = extract_session(write_session(tmp_path / "a", original, labels=False))
    b = extract_session(write_session(tmp_path / "b", doubled, labels=False))
    for before, after in zip(a, b):
        assert {c: before[c] for c in ETW_ONLY} == {c: after[c] for c in ETW_ONLY}
    assert by_root(b)[200]["sysmon_network_connects"] == 2
    assert by_root(b)[200]["sysmon_persistence_registry_sets"] == 1


def test_removing_sysmon_events_changes_only_sysmon_signals(tmp_path):
    full = attack_recording()
    bare = copy.deepcopy(full)
    bare.events = [e for e in bare.events if e["source"] != "sysmon"]
    a = by_root(extract_session(write_session(tmp_path / "a", full, labels=False)))[200]
    b = by_root(extract_session(write_session(tmp_path / "b", bare, labels=False)))[200]
    assert {c: a[c] for c in ETW_ONLY} == {c: b[c] for c in ETW_ONLY}
    assert b["sysmon_lsass_access"] == 0 and a["sysmon_lsass_access"] == 1


def test_events_out_of_order_give_the_same_rows(tmp_path):
    ordered = attack_recording()
    shuffled = copy.deepcopy(ordered)
    shuffled.events.reverse()
    a = extract_session(write_session(tmp_path / "a", ordered))
    b = extract_session(write_session(tmp_path / "b", shuffled))
    assert a == b


# The columns themselves


def test_no_feature_column_names_a_name_a_path_or_a_command():
    for column in FEATURE_COLUMNS:
        assert not FORBIDDEN_WORDS & set(column.split("_")), column


def test_metadata_is_never_a_feature():
    assert not NOT_FEATURES & set(FEATURE_COLUMNS)
    assert NOT_FEATURES <= set(METADATA_COLUMNS) | {"label"}
    assert "network" in METADATA_COLUMNS and "network" not in FEATURE_COLUMNS


def test_every_feature_is_a_number(rows):
    for row in rows:
        for column in FEATURE_COLUMNS:
            assert isinstance(row[column], (int, float)) and not isinstance(row[column], bool), column
            assert row[column] >= 0


def test_every_row_has_every_column(rows):
    assert all(list(row) == COLUMNS for row in rows)
    assert len(set(COLUMNS)) == len(COLUMNS)


def test_a_feature_with_text_in_it_would_be_caught(rows):
    row = dict(rows[0], n_file_write="C:\\Users\\lab\\x.txt")
    with pytest.raises(AssertionError):
        assert isinstance(row["n_file_write"], (int, float))


# Reading sessions


@pytest.mark.parametrize("missing", ["session_id", "pool", "batch", "network"])
def test_session_json_must_have_what_the_split_needs(tmp_path, missing):
    folder = write_session(tmp_path / "s", attack_recording())
    info = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    del info[missing]
    (folder / "session.json").write_text(json.dumps(info), encoding="utf-8")
    with pytest.raises(SessionError, match=missing):
        extract_session(folder)


def test_a_missing_session_json_is_an_error(tmp_path):
    folder = write_session(tmp_path / "s", attack_recording())
    (folder / "session.json").unlink()
    with pytest.raises(SessionError, match="session.json"):
        extract_session(folder)


def test_a_session_with_no_events_is_an_error(tmp_path):
    folder = write_session(tmp_path / "s", attack_recording())
    for name in ("events.jsonl", "fim.jsonl"):
        (folder / name).write_text("", encoding="utf-8")
    with pytest.raises(SessionError, match="no usable events"):
        extract_session(folder)


def test_bad_lines_and_invalid_events_are_skipped(tmp_path):
    folder = write_session(tmp_path / "s", attack_recording())
    with (folder / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("not json\n")
        stream.write('{"event_id": "x"}\n')
        stream.write('{"event_id": "e-20261105T093000-000999", "ts": "partly writ')
    assert len(extract_session(folder)) == 3


def test_fim_jsonl_is_optional(tmp_path):
    folder = write_session(tmp_path / "s", attack_recording())
    (folder / "fim.jsonl").unlink()
    assert by_root(extract_session(folder))[200]["n_fim_changes_linked"] == 0


def test_a_bom_in_session_json_is_fine(tmp_path):
    """PowerShell's Set-Content -Encoding UTF8 writes one."""
    folder = write_session(tmp_path / "s", attack_recording())
    assert (folder / "session.json").read_bytes().startswith(b"\xef\xbb\xbf")
    assert extract_session(folder)


def test_the_command_line_writes_a_csv(tmp_path, capsys):
    folder = write_session(tmp_path / "s", attack_recording())
    out = tmp_path / "features.csv"
    assert features.main([str(folder), "--out", str(out)]) == 0
    with out.open(encoding="utf-8", newline="") as stream:
        table = list(csv.DictReader(stream))
    assert list(table[0]) == COLUMNS
    assert len(table) == 3
    assert "3 trees" in capsys.readouterr().out


def test_the_command_line_stops_on_a_bad_session(tmp_path, capsys):
    assert features.main([str(tmp_path), "--out", str(tmp_path / "f.csv")]) == 1
    assert not (tmp_path / "f.csv").exists()
    assert "error:" in capsys.readouterr().err


def test_several_sessions_go_into_one_file(tmp_path):
    a = write_session(tmp_path / "a", attack_recording(), session_id="s-a")
    b = write_session(tmp_path / "b", attack_recording(), session_id="s-b")
    out = tmp_path / "features.csv"
    features.main([str(a), str(b), "--out", str(out)])
    with out.open(encoding="utf-8", newline="") as stream:
        assert {row["session_id"] for row in csv.DictReader(stream)} == {"s-a", "s-b"}


def test_peak_in_window():
    assert features.peak_in_window([], 10) == 0
    assert features.peak_in_window([1, 2, 3, 20, 21], 5) == 3
    assert features.peak_in_window([0, 10, 20], 10) == 2
    assert features.peak_in_window([0, 10.1, 20.2], 10) == 1


def test_features_import_nothing_that_can_reach_the_network_or_a_model():
    source = Path(features.__file__).read_text(encoding="utf-8")
    for word in ("urllib", "requests", "httpx", "socket", "xgboost", "backend.rag", "openai"):
        assert word not in source
