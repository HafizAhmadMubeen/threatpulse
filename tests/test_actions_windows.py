"""The restore, delete and Controlled Folder Access actions, the real WindowsApi on a
machine that is not Windows, and the parts that must stay in step with FIM."""

import importlib.util
import inspect
import json
import subprocess
import sys
from pathlib import Path

import pytest

from policy import actions_windows as win
from policy import execute, undo
from policy.actions_windows import Layout, WindowsApi
from policy import enable_controlled_folder_access
from tests.fake_windows_api import ENV, LAB, FakeApi, digest, key
from tests.test_executor import EVIL, LAYOUT, NOW, action, approve, go, nothing_starts_a_program  # noqa: F401
from tests.test_policy import FIM, make_alert, run

ROOT = Path(__file__).resolve().parent.parent
RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
ITEM = RUN + "\\AtomicTest"
SETTLED = {"fim": {"differs_from_baseline": True, "settled_seconds": 3}}
STARTUP = ENV["APPDATA"] + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
HOSTS = "C:\\Windows\\System32\\drivers\\etc\\hosts"


def registry_case(baseline_items, current=None, item=ITEM):
    api = FakeApi()
    api.write_baseline(LAYOUT, baseline_items)
    if current is not None:
        api.set_reg("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "AtomicTest", *current)
    alert = make_alert(**{**FIM, "key": item})
    return api, alert, run(alert, SETTLED)


def read(api, name="AtomicTest"):
    return api.get_reg("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name)


def manifest_of(api, decision, index=0):
    path = f"{LAYOUT.quarantine}\\{decision['decision_id']}-{index}\\manifest.json"
    return json.loads(api.files[key(path)])


# ---- restore: registry ------------------------------------------------------------


def test_a_modified_value_goes_back_to_the_baseline_and_undo_brings_the_attackers_value_back():
    api, alert, decision = registry_case(
        {ITEM: {"kind": "registry", "value": "C:\\good.exe", "reg_type": 1}}, ("C:\\evil.exe", 1))
    result = go(decision, alert, api)
    restore = action(result, "restore")
    assert (restore["status"], restore["executed_at"]) == ("executed", NOW)
    assert read(api).data == "C:\\good.exe"
    saved = manifest_of(api, decision)
    assert saved["before"] == {"reg_type": 1, "kind": "str", "value": "C:\\evil.exe"}
    (row,) = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "undone"
    assert read(api).data == "C:\\evil.exe"


def test_an_added_value_is_saved_then_removed_and_undo_adds_it_back():
    api, alert, decision = registry_case({}, ("C:\\evil.exe", 2))
    go(decision, alert, api)
    assert read(api) is None
    assert manifest_of(api, decision)["before"] == {"reg_type": 2, "kind": "str", "value": "C:\\evil.exe"}
    undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert read(api).data == "C:\\evil.exe" and read(api).reg_type == 2


def test_a_value_the_attacker_removed_is_written_back_and_undo_removes_it_again():
    api, alert, decision = registry_case({ITEM: {"kind": "registry", "value": "C:\\good.exe", "reg_type": 1}})
    go(decision, alert, api)
    assert read(api).data == "C:\\good.exe"
    assert manifest_of(api, decision)["before"] is None
    undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert read(api) is None


@pytest.mark.parametrize("data,reg_type", [
    ("%SystemRoot%\\x.exe", win.REG_EXPAND_SZ),
    (7, win.REG_DWORD),
    (2 ** 40, win.REG_QWORD),
    (b"\x00\xff\x10", win.REG_BINARY),
    (b"", win.REG_BINARY),
    (["one", "two"], win.REG_MULTI_SZ),
])
def test_every_registry_type_round_trips_through_the_baseline_text(data, reg_type):
    baseline = {ITEM: {"kind": "registry", "value": win.encode_value(data), "reg_type": reg_type}}
    api, alert, decision = registry_case(baseline, ("changed", 1))
    go(decision, alert, api)
    restored = read(api)
    assert (restored.data, restored.reg_type) == (data, reg_type)
    undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert read(api).data == "changed"


def test_a_value_that_already_matches_is_not_touched():
    api, alert, decision = registry_case(
        {ITEM: {"kind": "registry", "value": "C:\\good.exe", "reg_type": 1}}, ("C:\\good.exe", 1))
    restore = action(go(decision, alert, api), "restore")
    assert restore["status"] == "skipped" and "already matches" in restore["reason"]
    assert ("reg_write",) not in api.calls


def test_something_outside_the_persistence_zone_is_never_restored():
    outside = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"
    api = FakeApi()
    api.write_baseline(LAYOUT, {})
    api.set_reg("HKLM", "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 1, 4)
    alert = make_alert(**{**FIM, "key": outside})
    restore = action(go(run(alert, SETTLED), alert, api), "restore")
    assert restore["status"] == "skipped" and "not in the persistence zone" in restore["reason"]
    assert api.calls == []


def test_runonceex_values_in_numbered_subkeys_are_found():
    assert win.split_registry_item(
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend\\1") == \
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend", "1")
    assert win.split_registry_item(RUN + "\\(Default)") == ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "")
    for outside in (RUN, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceX\\a",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Runner\\a", "HKU\\S-1-5-21\\x\\Run\\a"):
        assert win.split_registry_item(outside) is None


def test_without_a_baseline_nothing_is_restored_and_the_failure_is_recorded():
    api = FakeApi()
    alert = make_alert(**{**FIM, "key": ITEM})
    restore = action(go(run(alert, SETTLED), alert, api), "restore")
    assert restore["status"] == "failed" and "no FIM baseline" in restore["reason"]


def test_a_registry_write_that_does_not_stick_is_a_failure_and_stays_undoable():
    api, alert, decision = registry_case(
        {ITEM: {"kind": "registry", "value": "C:\\good.exe", "reg_type": 1}}, ("C:\\evil.exe", 1))
    api.fail_on.add("reg_write")
    restore = action(go(decision, alert, api), "restore")
    assert restore["status"] == "failed" and restore["executed_at"] == NOW
    assert api.journal_states(LAYOUT)[-1] == (f"{decision['decision_id']}#0", "failed")
    api.fail_on.clear()
    (row,) = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "undone" and read(api).data == "C:\\evil.exe"


# ---- restore: files ---------------------------------------------------------------


def file_case(path, baseline_content=None, current=None):
    api = FakeApi()
    items = {}
    if baseline_content is not None:
        sha = api.put(f"{LAYOUT.stored_files}\\{digest(baseline_content)}", baseline_content)
        items[path] = {"kind": "file", "value": sha, "reg_type": None}
    api.write_baseline(LAYOUT, items)
    if current is not None:
        api.put(path, current)
    alert = make_alert(**{**FIM, "key": None, "path": path})
    return api, alert, run(alert, SETTLED)


def test_a_changed_hosts_file_is_restored_from_the_stored_copy_and_undo_puts_the_change_back():
    api, alert, decision = file_case(HOSTS, b"127.0.0.1 localhost\n", b"127.0.0.1 localhost\n6.6.6.6 bank.example\n")
    assert action(go(decision, alert, api), "restore")["status"] == "executed"
    assert api.files[key(HOSTS)] == b"127.0.0.1 localhost\n"
    saved = manifest_of(api, decision)
    assert saved["before"]["sha256"] == digest(b"127.0.0.1 localhost\n6.6.6.6 bank.example\n")
    undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert api.files[key(HOSTS)] == b"127.0.0.1 localhost\n6.6.6.6 bank.example\n"


def test_a_new_startup_file_is_quarantined_not_erased_and_undo_returns_it():
    path = STARTUP + "\\evil.lnk"
    api, alert, decision = file_case(path, None, b"LNK payload")
    assert action(go(decision, alert, api), "restore")["status"] == "executed"
    assert key(path) not in api.files
    quarantined = manifest_of(api, decision)["before"]["stored"]
    assert api.files[key(quarantined)] == b"LNK payload"
    undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert api.files[key(path)] == b"LNK payload"


def test_a_corrupt_baseline_copy_is_never_written_over_the_file():
    api, alert, decision = file_case(HOSTS, b"good\n", b"tampered\n")
    api.files[key(f"{LAYOUT.stored_files}\\{digest(b'good' + chr(10).encode())}")] = b"corrupt"
    restore = action(go(decision, alert, api), "restore")
    assert restore["status"] == "failed" and "does not match its hash" in restore["reason"]
    assert api.files[key(HOSTS)] == b"tampered\n"


def test_files_outside_the_startup_folders_and_hosts_are_never_restored():
    for path in ("C:\\Users\\lab\\Documents\\a.txt", "C:\\Windows\\System32\\drivers\\etc\\services",
                 STARTUP + "\\sub\\x.lnk", "C:\\Windows\\System32\\drivers\\etc\\..\\..\\config\\SAM"):
        api, alert, decision = file_case(path, None, b"x")
        restore = action(go(decision, alert, api), "restore")
        assert restore["status"] == "skipped" and "is not a startup-folder file" in restore["reason"], path
        assert api.files[key(path)] == b"x"


def test_a_restore_needs_the_persistence_zone():
    api, alert, decision = registry_case({}, ("x", 1))
    alert["object"]["zone"] = "none"
    assert "persistence zone" in action(go(decision, alert, api), "restore")["reason"]


# ---- request_delete: a move into quarantine ---------------------------------------


EICAR = "C:\\Users\\lab\\Downloads\\eicar.com"


def delete_case(content=b"EICAR-LIKE", sha=None):
    api = FakeApi()
    api.put(EICAR, content)
    alert = make_alert(layer="signature", rule_id="SIG-EICAR", event_type="file_scan", pid=0, path=EICAR)
    alert["object"]["file_sha256"] = sha or digest(b"EICAR-LIKE")
    decision = run(alert)
    return api, alert, decision


def test_a_delete_is_never_run_before_approval_and_then_moves_the_file_to_quarantine():
    api, alert, decision = delete_case()
    first = go(decision, alert, api)
    assert action(first, "request_delete")["status"] == "awaiting_approval" and key(EICAR) in api.files
    approve(first, "request_delete")
    done = go(first, alert, api)
    deleted = action(done, "request_delete")
    assert (deleted["status"], deleted["reviewed_by"]) == ("executed", "analyst")
    assert key(EICAR) not in api.files
    assert api.files[key(manifest_of(api, decision)["before"]["stored"])] == b"EICAR-LIKE"
    (row,) = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "undone" and api.files[key(EICAR)] == b"EICAR-LIKE"


def test_a_delete_refuses_a_file_that_changed_or_has_no_hash():
    api, alert, decision = delete_case(content=b"something else now")
    approve(decision, "request_delete")
    assert "changed since it was flagged" in action(go(decision, alert, api), "request_delete")["reason"]
    api2, alert2, decision2 = delete_case()
    alert2["object"]["file_sha256"] = None
    approve(decision2, "request_delete")
    out = action(go(decision2, alert2, api2), "request_delete")
    assert out["status"] == "failed" and "no file_sha256" in out["reason"]
    assert key(EICAR) in api2.files


@pytest.mark.parametrize("path", [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\svchost.exe",
    LAB + "\\fim\\baseline.json",
    LAB + "\\threatpulse\\agent\\build\\Release\\threatpulse_agent.exe",
    LAB + "\\LAB_VM",
])
def test_a_delete_never_touches_the_system_or_our_own_files(path):
    api = FakeApi()
    content = b"x"
    api.put(path, content)
    alert = make_alert(layer="signature", rule_id="SIG-X", event_type="file_scan", pid=0, path=path)
    alert["object"]["file_sha256"] = digest(content)
    decision = run(alert)
    approve(decision, "request_delete")
    out = action(go(decision, alert, api), "request_delete")
    assert out["status"] == "failed" and key(path) in api.files


def test_undo_of_a_delete_does_not_overwrite_a_file_that_is_back():
    api, alert, decision = delete_case()
    approve(decision, "request_delete")
    go(decision, alert, api)
    api.put(EICAR, b"a new file")
    (row,) = undo(decision["decision_id"], api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "failed" and api.files[key(EICAR)] == b"a new file"


# ---- Controlled Folder Access -----------------------------------------------------


def test_cfa_is_enabled_in_the_vm_and_undo_restores_the_previous_mode():
    api = FakeApi()
    previous = enable_controlled_folder_access(api=api, layout=LAYOUT, now=lambda: NOW)
    assert (previous, api.cfa) == ("Disabled", "Enabled")
    (row,) = undo("setup", api=api, layout=LAYOUT, now=lambda: NOW)
    assert row["result"] == "undone" and api.cfa == "Disabled"


def test_cfa_refuses_outside_the_vm_and_when_already_on():
    api = FakeApi(lab=False)
    with pytest.raises(win.Refused, match="not in lab VM"):
        enable_controlled_folder_access(api=api, layout=LAYOUT, now=lambda: NOW)
    assert api.calls == [] and api.cfa == "Disabled"
    api2 = FakeApi()
    api2.cfa = "Enabled"
    with pytest.raises(win.Refused, match="already enabled"):
        enable_controlled_folder_access(api=api2, layout=LAYOUT, now=lambda: NOW)


def test_execute_never_enables_cfa():
    api, alert, decision = registry_case({}, ("x", 1))
    go(decision, alert, api)
    assert api.cfa == "Disabled" and ("cfa_set",) not in api.calls


# ---- the real WindowsApi on a machine that is not Windows -------------------------


NEEDS_WINDOWS = [
    ("process_info", (1,)), ("suspend", (1, 1)), ("resume", (1, 1)), ("terminate", (1, 1)),
    ("microsoft_root", ("C:\\x.exe", "C:\\agent.exe")), ("firewall_exists", ("n",)),
    ("firewall_add", ("n", "C:\\x.exe")), ("firewall_remove", ("n",)),
    ("reg_read", ("HKCU", "Software", "x")), ("reg_write", ("HKCU", "Software", "x", "v", 1)),
    ("reg_delete", ("HKCU", "Software", "x")), ("cfa_get", ()), ("cfa_set", ("Enabled",)),
]


@pytest.mark.skipif(sys.platform == "win32", reason="this test is about not being Windows")
@pytest.mark.parametrize("method,arguments", NEEDS_WINDOWS, ids=[m for m, _ in NEEDS_WINDOWS])
def test_every_real_system_call_refuses_when_this_is_not_windows(method, arguments):
    with pytest.raises(win.NotWindows):
        getattr(WindowsApi(), method)(*arguments)


def test_the_fake_api_has_every_method_the_real_one_has():
    real = {n for n, f in inspect.getmembers(WindowsApi, inspect.isfunction) if not n.startswith("_")}
    fake = {n for n, f in inspect.getmembers(FakeApi, inspect.isfunction) if not n.startswith("_")}
    assert real <= fake, real - fake


def test_the_real_file_helpers_work_on_any_path(tmp_path):
    api, folder = WindowsApi(), str(tmp_path)
    assert api.sha256(folder + "/missing") is None
    api.write_text(folder + "/a.txt", "one\n")
    api.append_text(folder + "/a.txt", "two\n")
    assert api.read_text(folder + "/a.txt") == "one\ntwo\n"
    api.copy_file(folder + "/a.txt", folder + "/b.txt")
    assert api.sha256(folder + "/b.txt") == api.sha256(folder + "/a.txt") == digest(b"one\ntwo\n")
    api.move_file(folder + "/b.txt", folder + "/c.txt")
    assert not api.exists(folder + "/b.txt") and api.is_file(folder + "/c.txt")
    api.remove_file(folder + "/c.txt")
    assert not api.exists(folder + "/c.txt")
    assert not (tmp_path / "a.txt.tmp").exists()  # write_text leaves no partial file behind


def test_the_real_guard_on_this_machine_says_no():
    assert win.lab_guard(WindowsApi(), Layout()) == "not in lab VM: this is not Windows" or sys.platform == "win32"


# ---- staying in step with FIM -----------------------------------------------------


def load_fim(name):
    path = ROOT / "agent" / "fim"
    sys.path.insert(0, str(path))
    try:
        spec = importlib.util.spec_from_file_location(f"fim_under_test_{name}", path / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(path))
        sys.modules.pop("targets", None)


def test_registry_encoding_matches_the_fim_baseline():
    baseline = load_fim("baseline")
    for data in ("text", 5, b"\x01\xab", ["a", "b"], None, ""):
        assert win.encode_value(data) == baseline.encode_registry_data(data)


def test_the_restorable_registry_keys_are_exactly_the_ones_fim_watches():
    targets = load_fim("targets")
    fim = {(t.root, t.subkey, t.subtree) for t in targets.REGISTRY_TARGETS}
    assert set(win.PERSISTENCE_KEYS) == fim


def test_the_restorable_folders_are_exactly_the_ones_fim_watches():
    targets = load_fim("targets")
    environ = {**ENV, "SYSTEMROOT": "C:\\Windows"}
    for folder in targets.folder_targets(environ):
        probe = folder.path + "\\" + (folder.only_file or "x.lnk")
        assert win.file_in_scope(probe, environ), probe
        assert not win.file_in_scope(folder.path + "\\other\\y", environ)
