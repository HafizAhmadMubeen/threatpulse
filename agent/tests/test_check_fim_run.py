"""Tests that check_fim_run.py passes a good run and catches broken ones."""

import copy

from check_fim_run import full_checks, key_checks, writer_check

KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
VALUE = f"{KEY}\\ThreatPulseFimTest"
HOSTS = "C:\\Windows\\System32\\drivers\\etc\\hosts"
STARTUP = "C:\\Users\\lab\\Startup\\threatpulse-fim-test.txt"


def fim(kind, ts="2026-11-06T10:00:01.000Z", key=None, path=None, old=None, new=None):
    return {
        "ts": ts,
        "pid": 0,
        "process": {"image": "unknown"},
        "target": {"registry_key": key, "path": path, "change": {"kind": kind, "old_value": old, "new_value": new}},
    }


def good_run():
    return [
        fim("added", key=VALUE, new="notepad"),
        fim("modified", key=VALUE, old="notepad", new="notepad /changed"),
        fim("removed", key=VALUE, old="notepad /changed"),
        fim("modified", path=HOSTS, old="aaa", new="bbb"),
        fim("modified", ts="2026-11-06T10:00:09.000Z", path=HOSTS, old="bbb", new="aaa"),
        fim("added", path=STARTUP, new="ccc"),
        fim("modified", path=STARTUP, old="ccc", new="ddd"),
        fim("removed", path=STARTUP, old="ddd"),
    ]


def sysmon_events(ts="2026-11-06T10:00:00.500Z"):
    return [{"ts": ts, "source": "sysmon", "event_type": "registry_set", "target": {"registry_key": VALUE}}]


def failures(events, agent_events=None):
    results = [*key_checks(events, [KEY]), writer_check(events)]
    results += full_checks(events, [KEY], sysmon_events() if agent_events is None else agent_events)
    return [label for label, passed, _ in results if not passed]


def test_good_run_passes():
    assert failures(good_run()) == []


def test_a_repeated_event_fails():
    events = good_run() + [fim("added", key=VALUE, new="notepad")]
    assert any("added and removed once" in label for label in failures(events))


def test_a_missing_removal_fails():
    events = [event for event in good_run() if not (event["target"]["registry_key"] and event["target"]["change"]["kind"] == "removed")]
    assert any("added and removed once" in label for label in failures(events))


def test_hosts_not_restored_fails():
    events = copy.deepcopy(good_run())
    events[4]["target"]["change"]["new_value"] = "other"
    assert any("hosts" in label for label in failures(events))


def test_a_claimed_writer_fails():
    events = copy.deepcopy(good_run())
    events[0]["pid"] = 1234
    assert "no event claims a writer" in failures(events)


def test_a_slow_change_fails():
    assert any("seconds of Sysmon" in label for label in failures(good_run(), sysmon_events("2026-11-06T09:59:00.000Z")))


def test_no_sysmon_event_fails():
    assert any("seconds of Sysmon" in label for label in failures(good_run(), []))
