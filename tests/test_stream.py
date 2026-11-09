"""Streaming a session in sorted order must equal reading it all and sorting."""

import json
from pathlib import Path

import pytest

from detection.stream import SHIFT, SortedEvents
from detection.timeline import read_jsonl
from detection.behaviour import sort_events
from contracts.validate_samples import load_validators
from tests.event_builder import P, Recording
from tests.test_features import attack_recording

VALID = load_validators()["event"].is_valid


def write(folder: Path, recording: Recording, shuffle: bool = False) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    agent = [e for e in recording.events if e["source"] != "fim"]
    fim = [e for e in recording.events if e["source"] == "fim"]
    if shuffle:  # the agents write out of time order
        agent = agent[::-1]
    (folder / "events.jsonl").write_text("\n".join(json.dumps(e) for e in agent) + "\n", encoding="utf-8")
    (folder / "fim.jsonl").write_text("\n".join(json.dumps(e) for e in fim) + "\n", encoding="utf-8")
    return [folder / "events.jsonl", folder / "fim.jsonl"]


def old_way(paths: list[Path]) -> list[dict]:
    events = []
    for path in paths:
        read, _ = read_jsonl(path)
        events += [e for e in read if VALID(e)]
    return sort_events(events)


@pytest.mark.parametrize("shuffle", [False, True])
def test_the_order_is_exactly_the_old_sorted_order(tmp_path, shuffle):
    paths = write(tmp_path, attack_recording(), shuffle)
    stream = SortedEvents(paths, VALID)
    assert [e["event_id"] for e in stream] == [e["event_id"] for e in old_way(paths)]
    assert len(stream) == stream.valid == len(old_way(paths))


def test_ties_keep_file_and_line_order_and_a_start_comes_before_a_stop(tmp_path):
    recording = Recording()
    app = P(900, 1, "C:\\Windows\\notepad.exe")
    for kind in ("process_stop", "file_write", "process_start", "file_write"):  # all in the same millisecond
        recording.add(app, kind, 5.0, path="C:\\a.txt" if kind == "file_write" else None)
    recording.fim(5.0, registry_key="HKCU\\Software\\X")
    paths = write(tmp_path, recording)
    got = [(e["event_type"], e["event_id"]) for e in SortedEvents(paths, VALID)]
    assert got == [(e["event_type"], e["event_id"]) for e in old_way(paths)]
    # A start first, a stop last, and in between the events keep file order: events.jsonl, then fim.jsonl.
    assert [kind for kind, _ in got] == ["process_start", "file_write", "file_write", "fim_change", "process_stop"]


def test_unreadable_and_invalid_lines_are_counted_like_read_jsonl(tmp_path):
    paths = write(tmp_path, attack_recording())
    with paths[0].open("a", encoding="utf-8") as stream:
        stream.write("{not json\n\n[1, 2]\n")                       # unreadable, blank, not an object
        stream.write(json.dumps({"event_id": "x"}) + "\n")           # an object the schema rejects
    stream = SortedEvents(paths, VALID)
    assert stream.unreadable == 2 and stream.skipped_invalid == 1
    assert [e["event_id"] for e in stream] == [e["event_id"] for e in old_way(paths)]


def test_not_before_keeps_only_events_at_or_after_that_time(tmp_path):
    from detection.timeline import parse_ts
    paths = write(tmp_path, attack_recording())
    begin = parse_ts(old_way(paths)[10]["ts"]).timestamp()
    kept = [e for e in old_way(paths) if parse_ts(e["ts"]).timestamp() >= begin]
    stream = SortedEvents(paths, VALID, not_before=begin)
    assert [e["event_id"] for e in stream] == [e["event_id"] for e in kept]
    assert stream.valid > len(stream)  # the early ones were valid, just not wanted


def test_it_can_be_iterated_twice_and_a_missing_file_is_no_error(tmp_path):
    paths = write(tmp_path, attack_recording())
    stream = SortedEvents([paths[0], tmp_path / "absent.jsonl", paths[1]], VALID)
    first = [e["event_id"] for e in stream]
    assert first == [e["event_id"] for e in stream] and first == [e["event_id"] for e in old_way(paths)]


def test_a_position_orders_like_reading_file_zero_then_file_one():
    assert (0 << SHIFT | 10**9) < (1 << SHIFT | 0)


def test_non_utf8_bytes_do_not_stop_it(tmp_path):
    paths = write(tmp_path, attack_recording())
    paths[0].write_bytes(paths[0].read_bytes() + b'{"event_id": "\xff\xfe"}\n')
    stream = SortedEvents(paths, VALID)
    assert stream.parsed >= stream.valid
    assert [e["event_id"] for e in stream] == [e["event_id"] for e in old_way(paths)]
