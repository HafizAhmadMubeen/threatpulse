"""The FIM evidence session: its entry in recording_tests.json, its wrapper script, and the
pool that keeps it out of model training and evaluation (PLANNING.md Section 8.1)."""

import csv
import json
import re
from pathlib import Path

import label_session
import make_batch_plan
from test_label_session import ROOT, attack_session, event, write_session

AGENT = Path(__file__).resolve().parents[1]
TOOLS = AGENT / "tools"
CONFIG = AGENT / "config" / "recording_tests.json"
PLAN = TOOLS / "batch_plan.json"
WRAPPER = TOOLS / "vm_fim_session.ps1"
FIM_TEST = TOOLS / "vm_test_fim.ps1"
KNOWN_POOLS = {"training-technique", "held-out", "fim-test-only"}
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def config():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def entry():
    return next(test for test in config()["tests"] if test["id"] == "fim-test")


# ---- the entry and the pool -------------------------------------------------------


def test_the_entry_runs_the_wrapper_once_on_host_only():
    test = entry()
    assert (test["kind"], test["script"], test["runs"], test["network"]) == ("script", "vm_fim_session.ps1", 1, "host-only")
    assert test["technique"] is None and "number" not in test and "extra_runs" not in test
    assert (TOOLS / test["script"]).is_file()


def test_the_pool_is_fim_test_only_and_is_listed_as_excluded_from_ml():
    assert entry()["pool"] == "fim-test-only"
    assert config()["excluded_from_ml_pools"] == ["fim-test-only"]
    assert {test["pool"] for test in config()["tests"]} <= KNOWN_POOLS
    ordinary = [test for test in config()["tests"] if test["pool"] in ("training-technique", "held-out")]
    assert all(test["pool"] not in config()["excluded_from_ml_pools"] for test in ordinary)


def test_the_session_is_not_part_of_the_batch_plan_and_the_plan_is_unchanged():
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    assert all(session["test_id"] != "fim-test" for batch in plan["batches"] for session in batch["sessions"])
    assert sum(len(batch["sessions"]) for batch in plan["batches"]) == 55
    # The generator still gives the committed plan byte for byte, so adding the entry moved nothing.
    assert make_batch_plan.render(make_batch_plan.build_plan(config()["tests"])) == PLAN.read_text(encoding="utf-8")


# ---- the wrapper ------------------------------------------------------------------


def test_the_wrapper_has_a_cleanup_switch_the_vm_guard_and_runs_the_unchanged_test():
    text = WRAPPER.read_text(encoding="utf-8")
    assert "[switch]$Cleanup" in text
    assert "C:\\ThreatPulseLab\\LAB_VM" in text and "Is64BitProcess" in text
    assert "vm_test_fim.ps1" in text and "-HoldSeconds $HoldSeconds" in text


def test_the_cleanup_removes_exactly_what_the_fim_test_creates():
    wrapper, fim_test = WRAPPER.read_text(encoding="utf-8"), FIM_TEST.read_text(encoding="utf-8")
    value = re.search(r"\$valueName = '([^']+)'", fim_test).group(1)
    startup = re.search(r"Startup\\([^'\"]+)'", fim_test).group(1)
    assert f"$valueName = '{value}'" in wrapper
    assert f"Startup\\{startup}'" in wrapper
    assert "# ThreatPulse FIM test" in fim_test and "# ThreatPulse FIM test" in wrapper

    def keys(text):
        return {found.replace(":", "") for found in re.findall(r'"(HK(?:CU|LM):?\\[^"]+)"', text)}
    run_keys = {key for key in keys(fim_test) if not key.endswith("RunOnceEx")}
    assert len(run_keys) == 6 and run_keys <= keys(wrapper)
    assert {key for key in keys(wrapper) if key.endswith(r"RunOnceEx\0001\Depend")} == {
        r"HKLM\SOFTWARE\$root\RunOnceEx\0001\Depend",
        r"HKLM\SOFTWARE\WOW6432Node\$root\RunOnceEx\0001\Depend",
    }


# ---- what the labeller does with it -----------------------------------------------


def test_the_session_is_labelled_with_its_pool_and_its_cleanup_is_harness(tmp_path):
    cleanup_pid = 4000
    items = [
        event(2, "process_start", ROOT, image=POWERSHELL),
        event(3, "process_start", 1001, ppid=ROOT, image="C:\\Windows\\System32\\reg.exe"),
        event(3, "registry_set", 1001),
        event(4, "file_write", ROOT),
        event(31, "process_start", cleanup_pid, image=POWERSHELL),
        event(31, "file_write", cleanup_pid),
        event(35, "file_write", 2000),
    ]
    fim_changes = [event(3, "fim_change", 0, source="fim"), event(5, "fim_change", 0, source="fim")]
    session = attack_session(pool="fim-test-only", technique=None, cleanup_root_pid=cleanup_pid)
    write_session(tmp_path, session, items, fim=fim_changes)

    rows = label_session.label_session(tmp_path)
    by_id = {row["event_id"]: row for row in rows}
    assert {row["pool"] for row in rows} == {"fim-test-only"}
    assert (by_id[items[0]["event_id"]]["label"], by_id[items[0]["event_id"]]["part"]) == ("malicious", "test")
    assert by_id[items[2]["event_id"]]["part"] == "test"
    assert by_id[items[5]["event_id"]]["part"] == "harness"
    assert (by_id[items[6]["event_id"]]["label"], by_id[items[6]["event_id"]]["part"]) == ("benign", "background")
    for change in fim_changes:
        assert (by_id[change["event_id"]]["label"], by_id[change["event_id"]]["part"]) == ("none", "background")

    out = tmp_path / "labels.csv"
    label_session.write_labels(rows, out, overwrite=False)
    with out.open(encoding="utf-8") as file:
        written = list(csv.DictReader(file))
    assert {row["technique"] for row in written if row["label"] == "malicious"} == {""}
