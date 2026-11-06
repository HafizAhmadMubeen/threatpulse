"""execute() and undo(): statuses, the VM guard, approvals, never-suspend, firewall and kill.

Every test uses FakeApi, so nothing here touches the machine running the tests. An
autouse fixture makes that checkable: starting a program from Python fails the test.
"""

import copy
import os
import subprocess

import pytest

from policy import ExecuteError, execute, undo
from policy.actions_windows import Layout, Refused
from tests.fake_windows_api import LAB, FakeApi
from tests.test_policy import make_alert, run

LAYOUT = Layout(LAB)
NOW = "2026-11-07T12:00:00.000Z"
EVIL = "C:\\Users\\lab\\Desktop\\encrypt.exe"
SVCHOST = "C:\\Windows\\System32\\svchost.exe"
AGENT = "C:\\ThreatPulseLab\\threatpulse\\agent\\build\\Release\\threatpulse_agent.exe"


@pytest.fixture(autouse=True)
def nothing_starts_a_program(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to start a program")
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, "system", refuse)


def go(decision, alert, api, **kwargs):
    return execute(decision, alert, api=api, layout=LAYOUT, now=lambda: NOW, **kwargs)


def action(decision, name):
    return next(a for a in decision["actions"] if a["action"] == name)


def suspend_case(pid=6120, image=EVIL, **alert_kwargs):
    api = FakeApi()
    api.start(pid, image)
    alert = make_alert(zone="documents", risk=0.9, pid=pid, image=image, signed=False, signer=None, **alert_kwargs)
    return api, alert, run(alert)


def approve(decision, name, by="analyst"):
    action(decision, name).update(status="approved", reviewed_by=by, reviewed_at=NOW)


# ---- the VM guard -----------------------------------------------------------------


def test_with_the_real_api_on_this_machine_nothing_runs():
    """The default api is the real one. Here it must refuse, and not raise."""
    _, alert, decision = suspend_case()
    result = execute(decision, alert, now=lambda: NOW)  # real WindowsApi, default layout
    suspend = action(result, "suspend")
    assert suspend["status"] == "skipped" and suspend["executed_at"] is None
    assert suspend["reason"].startswith("not in lab VM")


def test_not_windows_skips_every_automatic_action():
    api, alert, decision = suspend_case()
    api.windows = False
    result = go(decision, alert, api)
    assert action(result, "suspend")["reason"] == "not in lab VM: this is not Windows"
    assert api.suspended == set() and api.calls == []


def test_missing_marker_skips_with_the_marker_path():
    api, alert, decision = suspend_case()
    api.lab = False
    result = go(decision, alert, api)
    assert action(result, "suspend")["reason"] == f"not in lab VM: {LAB}\\LAB_VM is missing"
    assert api.suspended == set() and api.calls == []


def test_outside_the_vm_an_approved_request_stays_approved():
    api, alert, decision = suspend_case()
    api.lab = False
    decision = run(make_alert(zone="documents", pid=6120, risk=0.97, image=EVIL, signed=False, signer=None),
                   {"suspended_pids": [6120]})
    approve(decision, "request_kill")
    result = go(decision, make_alert(zone="documents", pid=6120, risk=0.97, image=EVIL, signed=False, signer=None), api)
    assert action(result, "request_kill")["status"] == "approved"
    assert any("not in lab VM" in n for n in result["attributes"]["enforcement_notes"])
    assert api.terminated == []


# ---- the contract of execute ------------------------------------------------------


def test_the_input_decision_is_not_changed():
    api, alert, decision = suspend_case()
    before = copy.deepcopy(decision)
    go(decision, alert, api)
    assert decision == before


def test_a_malformed_decision_or_a_mismatched_alert_is_a_bug_and_raises():
    api, alert, decision = suspend_case()
    broken = copy.deepcopy(decision)
    del broken["ts"]
    with pytest.raises(ExecuteError, match="decision"):
        go(broken, alert, api)
    other = make_alert(zone="documents", risk=0.9, pid=6120, image=EVIL, number=2, signed=False, signer=None)
    with pytest.raises(ExecuteError, match="not a-"):
        go(decision, other, api)


def test_a_pending_suspend_runs_and_is_journaled():
    api, alert, decision = suspend_case()
    result = go(decision, alert, api)
    suspend = action(result, "suspend")
    assert (suspend["status"], suspend["executed_at"]) == ("executed", NOW)
    assert suspend["target"] == {"pid": 6120, "image": EVIL}
    assert api.suspended == {(6120, 1000 + 6120)}
    assert api.journal_states(LAYOUT) == [(f"{decision['decision_id']}#0", "started"),
                                          (f"{decision['decision_id']}#0", "done")]


def test_running_execute_again_acts_once():
    api, alert, decision = suspend_case()
    once = go(decision, alert, api)
    calls = list(api.calls)
    twice = go(once, alert, api)
    assert twice == once and api.calls == calls


def test_an_unexpected_error_fails_that_action_and_the_rest_still_run():
    api, alert, decision = suspend_case()
    image2 = "C:\\Users\\lab\\Desktop\\beacon.exe"
    api.start(7000, image2)
    api.put(image2, b"MZ")
    second = copy.deepcopy(action(decision, "suspend"))
    second.update(action="block_network", target={"pid": 7000, "image": image2})
    decision["actions"].insert(0, second)
    api.fail_on.add("firewall_add")  # the first action fails inside the api
    result = go(decision, alert, api)
    assert action(result, "block_network")["status"] == "failed"
    assert action(result, "block_network")["executed_at"] == NOW
    assert "firewall_add failed" in action(result, "block_network")["reason"]
    assert action(result, "suspend")["status"] == "executed"

    class Broken(FakeApi):
        def process_info(self, pid):
            raise RuntimeError("boom")
    api2 = Broken()
    _, alert2, decision2 = suspend_case()
    out = go(decision2, alert2, api2)
    assert action(out, "suspend")["status"] == "failed"
    assert "unexpected RuntimeError: boom" in action(out, "suspend")["reason"]


# ---- suspend and its checks -------------------------------------------------------


def test_suspend_of_an_exited_process_is_skipped():
    api, alert, decision = suspend_case()
    del api.processes[6120]
    suspend = action(go(decision, alert, api), "suspend")
    assert (suspend["status"], suspend["reason"], suspend["executed_at"]) == ("skipped", "process already exited", None)


def test_a_reused_pid_is_not_suspended():
    api, alert, decision = suspend_case()
    api.start(6120, "C:\\Users\\lab\\Desktop\\other.exe")
    suspend = action(go(decision, alert, api), "suspend")
    assert suspend["status"] == "skipped" and "now runs" in suspend["reason"]
    assert api.suspended == set()


def test_an_unreadable_live_path_is_refused():
    api, alert, decision = suspend_case()
    api.processes[6120] = type(api.processes[6120])(None, 1)
    assert "can't be read" in action(go(decision, alert, api), "suspend")["reason"]


def test_the_system_process_is_never_suspended():
    api, alert, decision = suspend_case()
    decision["actions"][0]["target"] = {"pid": 4, "image": "System"}
    api.start(4, "System")
    suspend = action(go(decision, alert, api), "suspend")
    assert suspend["status"] == "skipped" and "system process" in suspend["reason"]
    assert api.suspended == set()


def test_the_enforcement_process_itself_is_never_suspended():
    api, alert, decision = suspend_case()
    api.own = 6120
    assert "enforcement process itself" in action(go(decision, alert, api), "suspend")["reason"]


@pytest.mark.parametrize("answer,suspended", [(True, False), (None, False), (False, True)])
def test_never_suspend_is_rechecked_against_the_live_file(answer, suspended):
    """The alert said the file was not Microsoft's (so decide planned a suspend). The
    live check decides: a Microsoft-rooted svchost, or a check that can't be done, protects
    it. A file at that path whose signature is not Microsoft's does not."""
    api = FakeApi()
    api.start(6120, SVCHOST, microsoft_root=answer)
    alert = make_alert(zone="documents", risk=0.9, pid=6120, image=SVCHOST, microsoft_root=False)
    decision = run(alert)
    assert action(decision, "suspend")["status"] == "pending"  # stale alert data
    suspend = action(go(decision, alert, api), "suspend")
    assert (suspend["status"] == "executed") is suspended
    if not suspended:
        assert suspend["status"] == "skipped" and "never-suspend list" in suspend["reason"]
        assert api.suspended == set()


def test_a_same_named_program_elsewhere_is_not_on_the_list_and_needs_no_signature_check():
    api = FakeApi()
    desktop = "C:\\Users\\lab\\Desktop\\svchost.exe"
    api.start(6120, desktop)
    alert = make_alert(zone="documents", risk=0.9, pid=6120, image=desktop, signed=False, signer=None)
    suspend = action(go(run(alert), alert, api), "suspend")
    assert suspend["status"] == "executed" and api.verifier_calls == []


def test_our_own_agent_is_protected_whatever_the_signature_check_says():
    api = FakeApi()
    api.start(6120, AGENT, microsoft_root=False)
    alert = make_alert(zone="documents", risk=0.9, pid=6120, image=AGENT, microsoft_root=False)
    decision = run(alert)
    assert action(go(decision, alert, api), "suspend")["status"] == "skipped"
    assert api.suspended == set()


def test_a_second_suspend_of_the_same_process_does_not_stack():
    api, alert, decision = suspend_case()
    go(decision, alert, api)
    again = copy.deepcopy(decision)
    again["decision_id"] = decision["decision_id"][:-6] + "000099"
    out = go(again, alert, api)
    assert "already suspended" in action(out, "suspend")["reason"]


# ---- block_network ----------------------------------------------------------------


def block_case(image=EVIL, pid=6120):
    api = FakeApi()
    api.start(pid, image)
    api.put(image, b"MZ")
    alert = make_alert(event_type="network_connect", zone="network", risk=0.9, pid=pid, image=image,
                       signed=False, signer=None)
    return api, alert, run(alert)


def test_block_network_adds_a_rule_for_the_program_and_undo_removes_it():
    api, alert, decision = block_case()
    result = go(decision, alert, api)
    assert action(result, "block_network")["status"] == "executed"
    name = f"ThreatPulse-Block-{decision['decision_id']}-0"
    assert api.rules == {name: EVIL}
    rows = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert [(r["action"], r["result"]) for r in rows] == [("block_network", "undone")]
    assert api.rules == {}


def test_block_network_still_works_when_the_process_has_already_exited():
    api, alert, decision = block_case()
    del api.processes[6120]
    assert action(go(decision, alert, api), "block_network")["status"] == "executed"


def test_block_network_refuses_a_missing_program_and_an_unsafe_path():
    api, alert, decision = block_case()
    del api.files[EVIL.lower()]
    assert "does not exist" in action(go(decision, alert, api), "block_network")["reason"]
    api2, alert2, decision2 = block_case()
    decision2["actions"][0]["target"]["image"] = 'C:\\x" dir=in action=allow "y.exe'
    api2.processes.clear()
    assert "not an absolute program path" in action(go(decision2, alert2, api2), "block_network")["reason"]


def test_block_network_fails_if_the_rule_is_not_there_afterwards():
    api, alert, decision = block_case()
    api.fail_on.add("firewall_add_silently_nothing")
    block = action(go(decision, alert, api), "block_network")
    assert block["status"] == "failed" and "not found after adding" in block["reason"]


def test_block_network_never_touches_a_critical_program():
    api = FakeApi()
    api.start(6120, SVCHOST, microsoft_root=True)
    api.put(SVCHOST, b"MZ")
    alert = make_alert(event_type="network_connect", zone="network", risk=0.9, pid=6120, image=SVCHOST,
                       microsoft_root=False)
    block = action(go(run(alert), alert, api), "block_network")
    assert block["status"] == "skipped" and api.rules == {}


# ---- request_kill: approval, and a very hard gate ---------------------------------


def kill_case():
    api = FakeApi()
    api.start(6120, EVIL)
    alert = make_alert(zone="documents", pid=6120, risk=0.97, image=EVIL, signed=False, signer=None)
    return api, alert, run(alert, {"suspended_pids": [6120]})


def test_a_kill_waits_for_approval_and_is_never_run_unapproved_or_rejected():
    api, alert, decision = kill_case()
    first = go(decision, alert, api)
    assert action(first, "suspend")["status"] == "executed"
    assert action(first, "request_kill")["status"] == "awaiting_approval"
    assert api.terminated == []
    action(first, "request_kill").update(status="rejected", reviewed_by="analyst", reviewed_at=NOW)
    assert go(first, alert, api) == first and api.terminated == []


def test_an_approved_kill_runs_once_the_process_was_suspended_by_us():
    api, alert, decision = kill_case()
    first = go(decision, alert, api)
    approve(first, "request_kill")
    done = go(first, alert, api)
    kill = action(done, "request_kill")
    assert (kill["status"], kill["executed_at"]) == ("executed", NOW)
    assert (kill["reviewed_by"], kill["reviewed_at"]) == ("analyst", NOW)
    assert api.terminated == [6120]
    assert go(done, alert, api) == done


def test_an_approved_kill_of_a_process_we_did_not_suspend_is_refused():
    api, alert, decision = kill_case()
    decision["actions"] = [a for a in decision["actions"] if a["action"] != "suspend"]  # it was suspended by someone else
    approve(decision, "request_kill")
    kill = action(go(decision, alert, api), "request_kill")
    assert kill["status"] == "failed" and "not one that ThreatPulse suspended" in kill["reason"]
    assert api.terminated == []


def test_a_kill_has_no_undo_and_undo_says_so():
    api, alert, decision = kill_case()
    first = go(decision, alert, api)
    approve(first, "request_kill")
    go(first, alert, api)
    rows = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    by_action = {r["action"]: r for r in rows}
    assert by_action["request_kill"]["result"] == "skipped"
    assert "can't be undone" in by_action["request_kill"]["detail"]


# ---- undo -------------------------------------------------------------------------


def test_undo_resumes_a_suspended_process_once():
    api, alert, decision = suspend_case()
    go(decision, alert, api)
    rows = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert [(r["action"], r["result"], r["detail"]) for r in rows] == [("suspend", "undone", "resumed")]
    assert api.suspended == set()
    assert undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW) == []


def test_undo_never_resumes_a_different_process_that_got_the_pid():
    api, alert, decision = suspend_case()
    go(decision, alert, api)
    api.processes[6120] = type(api.processes[6120])(EVIL, 424242)
    (row,) = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "undone" and "another process" in row["detail"]
    assert api.suspended == {(6120, 1000 + 6120)}


def test_undo_refuses_outside_the_vm():
    api, alert, decision = suspend_case()
    go(decision, alert, api)
    api.lab = False
    with pytest.raises(Refused, match="not in lab VM"):
        undo(api=api, layout=LAYOUT)
    assert api.suspended


def test_a_failed_undo_is_reported_and_stays_active():
    api, alert, decision = suspend_case()
    go(decision, alert, api)
    api.fail_on.add("resume")
    (row,) = undo(api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "failed"
    api.fail_on.clear()
    (again,) = undo(api=api, layout=LAYOUT, now=lambda: NOW)
    assert again["result"] == "undone"
