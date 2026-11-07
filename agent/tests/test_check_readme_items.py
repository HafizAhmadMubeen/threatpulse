"""Tests that check_readme_items.py passes a good run and catches broken ones."""

from check_readme_items import run_checks

CMD = "C:\\WINDOWS\\system32\\cmd.exe"
DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MsMpEng.exe"
AGENT = "C:\\ThreatPulseLab\\threatpulse\\agent\\build\\Release\\threatpulse_agent.exe"


def event(event_type, image, source="etw", signed=True, signer="Microsoft Windows", sha256="a" * 64):
    return {
        "source": source,
        "event_type": event_type,
        "process": {"image": image, "signed": signed, "signer": signer, "sha256": sha256},
    }


def good_run():
    return [
        event("process_start", CMD),
        event("network_connect", DEFENDER, source="sysmon", signer="Microsoft Windows Publisher"),
        event("process_stop", DEFENDER),
    ]


def failures(events):
    return [label for label, passed, _ in run_checks(events) if not passed]


def test_good_run_passes():
    assert failures(good_run()) == []


def test_no_cmd_start_fails():
    assert any("cmd.exe" in label for label in failures(good_run()[1:]))


def test_unsigned_cmd_fails():
    assert any("cmd.exe" in label for label in failures([event("process_start", CMD, signed=False)]))


def test_wrong_signer_fails():
    assert any("cmd.exe" in label for label in failures([event("process_start", CMD, signer="Someone")]))


def test_missing_hash_fails():
    assert any("cmd.exe" in label for label in failures([event("process_start", CMD, sha256=None)]))


def test_32_bit_cmd_is_not_counted():
    assert any("cmd.exe" in label for label in failures([event("process_start", "C:\\Windows\\SysWOW64\\cmd.exe")]))


def test_agent_as_process_fails():
    assert "no event has the agent as its process" in failures(good_run() + [event("file_write", AGENT)])


def test_agent_as_a_target_passes():
    access = event("process_access", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", source="sysmon")
    access["target"] = {"path": AGENT}
    assert failures(good_run() + [access]) == []


def test_defender_file_event_fails():
    assert any("got through" in label for label in failures(good_run() + [event("file_write", DEFENDER)]))


def test_sysmon_file_event_fails():
    assert any("got through" in label for label in failures(good_run() + [event("registry_set", "C:\\Windows\\Sysmon64.exe")]))


def test_defender_network_events_are_allowed():
    assert failures(good_run() + [event("network_connect", DEFENDER)]) == []
