"""Tests for the parts of FIM that need no Windows APIs."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from baseline import (
    UNREADABLE,
    Change,
    Item,
    compare,
    create_baseline,
    encode_registry_data,
    hash_file,
    load_baseline,
    scan_folder,
)
from events import FIRST_COUNTER, MAX_VALUE_CHARS, EventWriter, build_event, rotate_existing
from monitor import Monitor, run
from targets import REGISTRY_TARGETS, FolderTarget, folder_targets

SCHEMA = Path(__file__).resolve().parents[2] / "contracts" / "schemas" / "event.schema.json"
VALIDATOR = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
NOW = datetime(2026, 11, 6, 10, 15, 0, 123456, tzinfo=timezone.utc)
RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test"


def registry(value: str) -> Item:
    return Item("registry", value, 1)


class FakeSource:
    """Plays back a list of (notified, snapshot) steps."""

    def __init__(self, first, steps):
        self.current = first
        self.steps = list(steps)

    def scan(self):
        return self.current

    def wait(self, timeout_seconds):
        notified, self.current = self.steps.pop(0)
        return notified


def play(baseline, first, steps):
    seen = []
    monitor = Monitor(baseline, seen.append)
    source = FakeSource(first, steps)
    run(monitor, source, lambda: not source.steps)
    return seen, monitor.stats


def play_all(baseline, first, steps):
    """Like play(), but the last step is also processed."""
    return play(baseline, first, [*steps, (False, steps[-1][1] if steps else first)])


def test_compare_finds_each_kind():
    old = {"a": registry("1"), "b": registry("2")}
    new = {"a": registry("9"), "c": registry("3")}
    assert compare(old, new) == [
        Change("a", "registry", "modified", "1", "9"),
        Change("b", "registry", "removed", "2", None),
        Change("c", "registry", "added", None, "3"),
    ]


def test_compare_finds_a_type_change_with_the_same_text():
    assert compare({"a": Item("registry", "1", 1)}, {"a": Item("registry", "1", 4)})


def test_no_change_gives_nothing():
    state = {"a": registry("1")}
    assert compare(state, dict(state)) == []


def test_change_while_stopped_is_reported_at_start():
    seen, _ = play({}, {RUN_KEY: registry("x")}, [])
    assert [change.change_kind for change in seen] == ["added"]


def test_a_change_that_stays_is_reported_once():
    state = {RUN_KEY: registry("x")}
    seen, stats = play_all({}, {}, [(True, state), (False, state), (False, state)])
    assert len(seen) == 1
    assert stats.full_compares >= 2


def test_add_then_remove_gives_two_events():
    seen, _ = play_all({}, {}, [(True, {RUN_KEY: registry("x")}), (True, {})])
    assert [change.change_kind for change in seen] == ["added", "removed"]


def test_a_later_change_compares_with_last_seen_not_the_baseline():
    seen, _ = play_all(
        {RUN_KEY: registry("base")},
        {RUN_KEY: registry("first")},
        [(True, {RUN_KEY: registry("second")})],
    )
    assert [(change.old_value, change.new_value) for change in seen] == [
        ("base", "first"),
        ("first", "second"),
    ]


def test_notification_with_no_change_is_counted():
    state = {RUN_KEY: registry("x")}
    seen, stats = play_all(state, state, [(True, state)])
    assert seen == []
    assert stats.notifications == 1
    assert stats.notifications_no_change == 1


def test_timeout_finds_what_no_notification_reported():
    seen, stats = play_all({}, {}, [(False, {RUN_KEY: registry("x")})])
    assert len(seen) == 1
    assert stats.notifications == 0


def test_encode_registry_data():
    assert encode_registry_data("C:\\a.exe") == "C:\\a.exe"
    assert encode_registry_data(1) == "1"
    assert encode_registry_data(b"\x01\xff") == "01ff"
    assert encode_registry_data(["a", "b"]) == "a\nb"
    assert encode_registry_data(None) == ""


def test_hash_file_reports_unreadable(tmp_path):
    assert hash_file(tmp_path / "missing") == UNREADABLE


def test_scan_folder_only_file_and_no_subfolders(tmp_path):
    (tmp_path / "hosts").write_text("a")
    (tmp_path / "services").write_text("b")
    (tmp_path / "sub").mkdir()
    assert [Path(name).name for name in scan_folder(FolderTarget(str(tmp_path), "hosts"))] == ["hosts"]
    assert len(scan_folder(FolderTarget(str(tmp_path)))) == 2


def test_scan_folder_missing_is_empty(tmp_path):
    assert scan_folder(FolderTarget(str(tmp_path / "missing"))) == {}


def test_baseline_round_trip_keeps_a_file_copy(tmp_path):
    source = tmp_path / "hosts"
    source.write_text("content")
    digest = hash_file(source)
    snapshot = {str(source): Item("file", digest), RUN_KEY: registry("x")}
    folder = tmp_path / "fim"

    create_baseline(folder, snapshot)

    assert load_baseline(folder) == snapshot
    assert (folder / "files" / digest).read_text() == "content"


def test_baseline_is_never_replaced(tmp_path):
    create_baseline(tmp_path, {RUN_KEY: registry("x")})
    with pytest.raises(FileExistsError):
        create_baseline(tmp_path, {})
    assert RUN_KEY in load_baseline(tmp_path)


@pytest.mark.parametrize("kind,old,new", [("added", None, "x"), ("modified", "a", "b"), ("removed", "a", None)])
def test_registry_event_matches_the_schema(kind, old, new):
    event = build_event(Change(RUN_KEY, "registry", kind, old, new), "e-20261106T101500-900000000", "lab", NOW)
    assert list(VALIDATOR.iter_errors(event)) == []
    assert event["target"]["registry_key"] == RUN_KEY
    assert event["target"]["path"] is None
    assert event["ts"] == "2026-11-06T10:15:00.123Z"


def test_file_event_matches_the_schema_and_claims_no_writer():
    change = Change("C:\\hosts", "file", "modified", "a" * 64, "b" * 64)
    event = build_event(change, "e-20261106T101500-900000000", "lab", NOW)
    assert list(VALIDATOR.iter_errors(event)) == []
    assert event["target"]["path"] == "C:\\hosts"
    assert (event["pid"], event["process"]["image"], event["process"]["signed"]) == (0, "unknown", False)


def test_long_values_are_cut():
    change = Change(RUN_KEY, "registry", "added", None, "x" * (MAX_VALUE_CHARS + 5))
    event = build_event(change, "e-20261106T101500-900000000", "lab", NOW)
    assert len(event["target"]["change"]["new_value"]) == MAX_VALUE_CHARS


def test_schema_rules_for_change():
    event = build_event(Change(RUN_KEY, "registry", "added", None, "x"), "e-20261106T101500-900000000", "lab", NOW)

    missing = json.loads(json.dumps(event))
    del missing["target"]["change"]
    assert list(VALIDATOR.iter_errors(missing))

    wrong_kind = json.loads(json.dumps(event))
    wrong_kind["target"]["change"]["kind"] = "renamed"
    assert list(VALIDATOR.iter_errors(wrong_kind))

    on_other_event = json.loads(json.dumps(event))
    on_other_event["event_type"] = "registry_set"
    assert list(VALIDATOR.iter_errors(on_other_event))


def test_writer_counts_from_the_high_range_and_rotates(tmp_path):
    out = tmp_path / "logs" / "fim.jsonl"
    change = Change(RUN_KEY, "registry", "added", None, "x")

    first = EventWriter(out, clock=lambda: NOW)
    first.write(change)
    first.write(change)
    first.close()
    ids = [json.loads(line)["event_id"] for line in out.read_text().splitlines()]
    assert ids == [f"e-20261106T101500-{FIRST_COUNTER}", f"e-20261106T101500-{FIRST_COUNTER + 1}"]

    EventWriter(out, clock=lambda: NOW).close()
    assert (out.parent / "fim-20261106T101500.jsonl").exists()
    assert out.read_text() == ""


def test_rotation_never_overwrites(tmp_path):
    out = tmp_path / "fim.jsonl"
    (tmp_path / "fim-20261106T101500.jsonl").write_text("older")
    out.write_text("newer")
    rotate_existing(out, NOW)
    assert (tmp_path / "fim-20261106T101500.jsonl").read_text() == "older"
    assert (tmp_path / "fim-20261106T101500-1.jsonl").read_text() == "newer"


def test_targets_cover_the_persistence_zone():
    names = {target.name for target in REGISTRY_TARGETS}
    assert len(names) == 8
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" in names
    assert "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" in names


def test_folder_targets():
    environ = {"APPDATA": "C:\\U\\R", "PROGRAMDATA": "C:\\PD", "SYSTEMROOT": "C:\\W"}
    user, machine, hosts = folder_targets(environ)
    assert user.path == "C:\\U\\R\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    assert machine.path.startswith("C:\\PD\\")
    assert (hosts.path, hosts.only_file) == ("C:\\W\\System32\\drivers\\etc", "hosts")
