"""The orchestrator (PHASES.md step 3.9): sessions in, alerts, decisions and reports out."""

import ast
import hashlib
import json
import shutil
import socket
from pathlib import Path

import pytest

from backend.data import DataDirectory
from backend.pipeline import output, run, run_session
from backend.pipeline import __main__ as cli
from backend.pipeline.run import PipelineError
from contracts.validate_samples import load_validators
from tests.event_builder import DOCS, POWERSHELL, RUN_KEY, P, Recording
from tests.test_behaviour import EDGE, EDGE_KEY
from tests.test_features import write_session
from triage import score

ROOT = Path(__file__).resolve().parent.parent
VALIDATORS = load_validators()
REG = "C:\\Windows\\System32\\reg.exe"


def session(tmp_path: Path, recording: Recording, name: str = "s1", **info) -> Path:
    return write_session(tmp_path / name, recording, labels=False, session_id=name, **info)


def go(tmp_path, recording, **options):
    return run_session(session(tmp_path, recording), **options)


def pairs(result) -> list[tuple[str, str, str]]:
    return [(d["decision_id"][-6:], a["action"], a["status"]) for d in result.decisions for a in d["actions"]]


def decision_for(result, rule_id: str) -> dict:
    alert = next(a for a in result.alerts if a["rule_id"] == rule_id)
    return next(d for d in result.decisions if d["alert_id"] == alert["alert_id"])


def added(recording, seconds, key=RUN_KEY, value="calc.exe"):
    return recording.fim(seconds, kind="added", registry_key=key,
                         change={"kind": "added", "old_value": None, "new_value": value})


def removed(recording, seconds, key=RUN_KEY, value="calc.exe"):
    return recording.fim(seconds, kind="removed", registry_key=key,
                         change={"kind": "removed", "old_value": value, "new_value": None})


def modified(recording, seconds, old, new, key=RUN_KEY):
    return recording.fim(seconds, kind="modified", registry_key=key,
                         change={"kind": "modified", "old_value": old, "new_value": new})


def seconds_between(a: str, b: str) -> float:
    from detection.timeline import parse_ts
    return (parse_ts(b) - parse_ts(a)).total_seconds()


# ---- the FIM debounce, on the real shapes --------------------------------------------


def test_edge_rewriting_its_autolaunch_value_is_not_restored(tmp_path):
    """Batch 1: removed and re-added 140 ms apart. After the debounce the value is back at
    the baseline, so there is nothing to restore."""
    recording = Recording()
    edge = P(9608, 1392, EDGE)
    value = '"msedge.exe" --no-startup-window'
    recording.fim(6.054, kind="removed", registry_key=EDGE_KEY,
                  change={"kind": "removed", "old_value": value, "new_value": None})
    recording.add(edge, "registry_delete", 6.099, source="sysmon", registry_key=EDGE_KEY)
    recording.add(edge, "registry_set", 6.193, source="sysmon", registry_key=EDGE_KEY)
    recording.fim(6.195, kind="added", registry_key=EDGE_KEY,
                  change={"kind": "added", "old_value": None, "new_value": value})
    result = go(tmp_path, recording)
    assert len(result.alerts) == 3
    assert {(a, s) for _, a, s in pairs(result)} == {("alert_only", "executed")}
    assert all(d["attributes"]["fim_state"] == "matches_baseline" for d in result.decisions)
    assert all("P2-persistence-change" not in d["policy_rules"] for d in result.decisions)


def test_a_change_that_stays_is_planned_for_restore_after_the_debounce(tmp_path):
    recording = Recording()
    recording.add(P(900, 700, REG), "registry_set", 1.000, source="sysmon", registry_key=RUN_KEY)
    added(recording, 1.040)
    result = go(tmp_path, recording)
    for rule in ("R-T1547-001", "R-FIM-PERSISTENCE"):
        decision = decision_for(result, rule)
        assert [(a["action"], a["status"]) for a in decision["actions"]] == [("restore", "pending")]
        alert = next(a for a in result.alerts if a["alert_id"] == decision["alert_id"])
        assert seconds_between(alert["ts"], decision["ts"]) >= 2.0
        assert decision["actions"][0]["executed_at"] is None


def test_a_change_undone_inside_the_debounce_is_not_restored(tmp_path):
    recording = Recording()
    added(recording, 1.0)
    removed(recording, 2.0)  # gone again one second later
    result = go(tmp_path, recording)
    assert {(a, s) for _, a, s in pairs(result)} == {("alert_only", "executed")}
    first = result.decisions[0]
    assert seconds_between(result.alerts[0]["ts"], first["ts"]) >= 3.0  # it waited for the second change


def test_the_wait_is_extended_while_the_item_keeps_changing(tmp_path):
    recording = Recording()
    added(recording, 1.0, value="a.exe")
    modified(recording, 2.5, "a.exe", "b.exe")
    modified(recording, 4.0, "b.exe", "c.exe")
    result = go(tmp_path, recording)
    first = result.decisions[0]
    assert seconds_between(result.alerts[0]["ts"], first["ts"]) >= 5.0  # 4.0 + 2 - 1.0
    assert first["attributes"]["fim_state"] == "differs_settled"
    assert [(a["action"], a["status"]) for a in first["actions"]] == [("restore", "pending")]


def test_no_fim_history_means_restore_is_skipped_not_guessed(tmp_path):
    """Batch 1: FIM did not watch RunOnceEx, so only the rule saw the write."""
    recording = Recording()
    key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend\\1"
    recording.add(P(900, 700, REG), "registry_set", 1.0, source="sysmon", registry_key=key)
    result = go(tmp_path, recording)
    action = result.decisions[0]["actions"][0]
    assert (action["action"], action["status"]) == ("restore", "skipped")
    assert "unknown" in action["reason"]


def test_decisions_use_only_what_had_happened_by_then(tmp_path):
    """A change that happens long after the decision was due cannot change that decision."""
    recording = Recording()
    added(recording, 1.0)
    removed(recording, 60.0)
    first = go(tmp_path, recording).decisions[0]
    assert first["attributes"]["fim_state"] == "differs_settled"
    assert seconds_between("2026-11-05T09:30:01.000Z", first["ts"]) == pytest.approx(2.0, abs=0.01)


# ---- writer_tree: linking FIM changes to writers --------------------------------------


def scorer_of(value):
    return lambda events: value


def persistence(recording, writer_ts=1.0, fim_ts=1.0, key=RUN_KEY, fim_key=None, pid=900, ppid=700):
    reg = P(pid, ppid, REG)
    recording.start(P(ppid, 1, POWERSHELL), 0.1)
    recording.start(reg, 0.5)
    recording.add(reg, "registry_set", writer_ts, source="sysmon", registry_key=key)
    added(recording, fim_ts, key=fim_key or key)
    return reg


def test_a_fim_alert_is_linked_to_its_writer_and_the_writers_parents(tmp_path):
    recording = Recording()
    persistence(recording)
    result = go(tmp_path, recording, scorer=scorer_of(0.9))
    suspend = [a for a in decision_for(result, "R-FIM-PERSISTENCE")["actions"] if a["action"] == "suspend"]
    assert len(suspend) == 1 and suspend[0]["status"] == "pending"
    # the whole chain has one score here, so the lowest pid is the tie-break: the parent
    assert suspend[0]["target"] == {"pid": 700, "image": POWERSHELL}


def test_no_writer_found_means_no_suspend(tmp_path):
    recording = Recording()
    added(recording, 1.0)
    result = go(tmp_path, recording, scorer=scorer_of(0.9))
    assert "P2b-persistence-origin" not in decision_for(result, "R-FIM-PERSISTENCE")["policy_rules"]


def test_dead_writers_are_skipped(tmp_path):
    recording = Recording()
    reg = persistence(recording)
    recording.stop(reg, 1.2)
    recording.stop(P(700, 1, POWERSHELL), 1.3)
    result = go(tmp_path, recording, scorer=scorer_of(0.9))
    suspend = next(a for a in decision_for(result, "R-FIM-PERSISTENCE")["actions"] if a["action"] == "suspend")
    assert suspend["status"] == "skipped" and "exited" in suspend["reason"]


def test_keys_are_matched_ignoring_case_and_hku_is_hkcu(tmp_path):
    recording = Recording()
    persistence(recording, key=RUN_KEY.replace("Software", "SOFTWARE"),
                fim_key="HKU\\S-1-5-21-1-2-3-1001\\Software" + RUN_KEY.split("Software", 1)[1])
    result = go(tmp_path, recording, scorer=scorer_of(0.9))
    assert any(a["action"] == "suspend" for a in decision_for(result, "R-FIM-PERSISTENCE")["actions"])


@pytest.mark.parametrize("write_at,linked", [(1.4, True), (1.6, False), (0.0, True)])
def test_the_clock_skew_window_is_half_a_second(tmp_path, write_at, linked):
    """FIM's clock ran ahead of Sysmon's by 45 ms in the real recordings. The write may come
    up to 0.5 s after the change, and is still its writer."""
    recording = Recording()
    reg = P(900, 700, REG)
    recording.start(P(700, 1, POWERSHELL), 0.0)
    recording.add(reg, "registry_set", write_at, source="sysmon", registry_key=RUN_KEY)
    added(recording, 1.0)
    result = go(tmp_path, recording, scorer=scorer_of(0.9))
    fim_decision = decision_for(result, "R-FIM-PERSISTENCE")
    assert ("P2b-persistence-origin" in fim_decision["policy_rules"]) is linked


def test_a_reused_pid_is_a_new_process_with_its_own_parent(tmp_path):
    recording = Recording()
    recording.start(P(700, 1, POWERSHELL), 0.0)
    recording.start(P(701, 1, "C:\\Windows\\System32\\cmd.exe"), 0.0)
    first = P(900, 700, "C:\\Windows\\System32\\whoami.exe")
    recording.start(first, 0.1)
    recording.stop(first, 0.2)
    second = P(900, 701, REG)  # the same pid, a different program with a different parent
    recording.start(second, 0.5)
    recording.add(second, "registry_set", 1.0, source="sysmon", registry_key=RUN_KEY)
    added(recording, 1.0)
    result = go(tmp_path, recording, scorer=scorer_of(0.9))
    alert = next(a for a in result.alerts if a["rule_id"] == "R-T1547-001")
    assert alert["subject"]["image"] == REG
    suspend = next(a for a in decision_for(result, "R-FIM-PERSISTENCE")["actions"] if a["action"] == "suspend")
    # the chain is reg.exe (900) then its real parent cmd.exe (701), and the lowest pid wins
    assert suspend["status"] == "pending" and suspend["target"]["pid"] == 701


# ---- the stubs and the wiring ----------------------------------------------------------


def delete_session(tmp_path, count=12):
    recording = Recording()
    ransom = P(6120, 4724, POWERSHELL, "powershell.exe")
    for i in range(count):
        recording.add(ransom, "file_delete", 1.0 + i * 0.1, path=f"{DOCS}\\f{i}.txt")
    return recording


def test_without_a_model_the_scorer_says_not_scored():
    assert score.is_stub() is True  # tests/conftest.py points the scorer at an empty folder
    assert score.score_process([{"anything": 1}]) is None


def test_with_the_stub_nothing_has_a_risk_score_and_nothing_is_contained(tmp_path):
    result = go(tmp_path, delete_session(tmp_path))
    assert result.alerts and all(a["risk_score"] is None for a in result.alerts)
    assert {a for _, a, _ in pairs(result)} == {"alert_only"}
    assert result.reports == []  # a null score is not high-risk


def test_a_real_score_flows_through_to_a_pending_suspend_and_a_report(tmp_path):
    seen = []

    def scorer(events):
        seen.append(len(events))
        return 0.93

    result = go(tmp_path, delete_session(tmp_path), scorer=scorer)
    decision = decision_for(result, "R-T1486-001")
    assert [(a["action"], a["status"], a["automatic"]) for a in decision["actions"]] == [("suspend", "pending", True)]
    assert decision["actions"][0]["target"]["pid"] == 6120
    assert decision["actions"][0]["executed_at"] is None
    assert [r["alert_id"] for r in result.reports] == [decision["alert_id"]]
    assert seen and seen[0] >= 10  # it got the tree's events up to the alert, not nothing


def test_the_scorer_only_sees_events_up_to_the_alert(tmp_path):
    recording = delete_session(tmp_path)
    recording.add(P(6120, 4724, POWERSHELL), "file_delete", 500.0, path=f"{DOCS}\\late.txt")
    seen = []
    go(tmp_path, recording, scorer=lambda events: seen.append(max(e["ts"] for e in events)))
    assert seen and all(ts < "2026-11-05T09:30:30" for ts in seen)


@pytest.mark.parametrize("bad", [1.5, -0.1, "high", True])
def test_a_scorer_returning_nonsense_stops_the_run(tmp_path, bad):
    with pytest.raises(PipelineError):
        go(tmp_path, delete_session(tmp_path), scorer=scorer_of(bad))


def test_decide_runs_before_the_report_and_never_sees_it(tmp_path, monkeypatch):
    calls = []
    real_decide = run.decide

    def spy_decide(alert, context):
        calls.append(("decide", alert["alert_id"]))
        assert set(context) <= {"now", "suspended_pids", "fim", "writer_tree"}
        assert context["suspended_pids"] == []
        return real_decide(alert, context)

    def spy_reporter(alert, events):
        calls.append(("report", alert["alert_id"]))
        return run.report_stub.write_report(alert, events)

    monkeypatch.setattr(run, "decide", spy_decide)
    go(tmp_path, delete_session(tmp_path), scorer=scorer_of(0.95), reporter=spy_reporter)
    assert calls and calls[0][0] == "decide"
    for index, (kind, alert_id) in enumerate(calls):
        if kind == "report":
            assert ("decide", alert_id) in calls[:index]


def test_reports_are_stubs_with_no_network(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the pipeline must not open a network connection")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    result = go(tmp_path, delete_session(tmp_path), scorer=scorer_of(0.95))
    assert result.reports
    for report in result.reports:
        assert report["summary"].startswith("STUB report, no LLM call")
        assert VALIDATORS["report"].is_valid(report)
        assert not any("\x00" in line for line in report["timeline"])


def test_reports_only_for_high_risk_alerts(tmp_path):
    recording = Recording()
    recording.add(P(300, 1, POWERSHELL, "powershell.exe -enc AAAA"), "process_start", 1.0,)
    result = go(tmp_path, recording)
    assert any(a["rule_id"] == "R-T1059-001" for a in result.alerts)
    assert result.reports == []


def test_a_fim_change_in_a_protected_zone_is_confirmed_so_it_gets_a_report(tmp_path):
    recording = Recording()
    added(recording, 1.0)
    result = go(tmp_path, recording)
    assert [r["alert_id"] for r in result.reports] == [result.alerts[0]["alert_id"]]


# ---- signature alerts from a recording ---------------------------------------------------


def test_a_known_bad_process_hash_gives_a_signature_alert_and_a_delete_request(tmp_path, monkeypatch):
    sha = "ab" * 32
    monkeypatch.setattr(run.hashes, "lookup", lambda value: "EICAR" if value == sha else None)
    recording = Recording()
    bad = P(4280, 1, "C:\\Users\\lab\\Desktop\\eicar.com")
    for second in (1.0, 5.0):  # the same file started twice is one alert
        event = recording.start(bad, second)
        event["process"]["sha256"] = sha
    result = go(tmp_path, recording)
    alerts = [a for a in result.alerts if a["layer"] == "signature"]
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SIG-EICAR" and alerts[0]["subject"]["pid"] == 4280
    assert alerts[0]["object"]["path"] == bad.image and alerts[0]["object"]["file_sha256"] == sha
    decision = decision_for(result, "SIG-EICAR")
    assert [(a["action"], a["status"]) for a in decision["actions"]] == [("request_delete", "awaiting_approval")]
    assert len(result.reports) == 1  # a signature match is Confirmed


def test_scan_files_is_off_unless_asked_and_runs_scan_file_on_images_that_exist(tmp_path, monkeypatch):
    calls = []
    image = tmp_path / "tool.exe"
    image.write_bytes(b"MZ")

    def fake_scan(path):
        calls.append(path)
        from detection.alerts import file_scan_alert
        return [file_scan_alert("signature", "SIG-TEST", [], path, "cd" * 32, {"score": None, "reasons": ["x"]})]

    monkeypatch.setattr(run, "scan_file", fake_scan)
    recording = Recording()
    recording.start(P(300, 1, str(image)), 1.0)
    recording.start(P(301, 1, "C:\\does\\not\\exist.exe"), 2.0)
    assert go(tmp_path, recording).alerts == [] and calls == []
    result = run_session(tmp_path / "s1", scan_files=True)
    assert calls == [str(image)]
    assert [a["rule_id"] for a in result.alerts] == ["SIG-TEST"]
    assert result.alerts[0]["subject"]["pid"] == 300 and result.alerts[0]["evidence_event_ids"]


# ---- outputs ----------------------------------------------------------------------------


def full_recording():
    recording = delete_session(None)
    persistence(recording, pid=901, ppid=701)
    return recording


def test_ids_are_the_recordings_run_start_and_repeat_exactly(tmp_path):
    first = go(tmp_path, full_recording(), scorer=scorer_of(0.9))
    second = go(tmp_path, full_recording(), scorer=scorer_of(0.9))
    assert json.dumps([first.alerts, first.decisions, first.reports], sort_keys=True) == \
           json.dumps([second.alerts, second.decisions, second.reports], sort_keys=True)
    assert first.alerts and all(a["alert_id"].startswith("a-20261105T093000-") for a in first.alerts)


def test_every_output_validates_and_the_backend_serves_it(tmp_path):
    folder = session(tmp_path, full_recording())
    result = run_session(folder, scorer=scorer_of(0.9))
    out = tmp_path / "out"
    output.write_session(result, folder, out, None)
    served = DataDirectory(out / "s1").load()
    for kind, name in (("alert", "alerts.json"), ("decision", "decisions.json"), ("report", "reports.json")):
        items = json.loads((out / "s1" / name).read_text(encoding="utf-8"))
        assert items and all(VALIDATORS[kind].is_valid(i) for i in items)
    assert (out / "s1" / "pipeline_summary.json").is_file()
    assert served.skipped == {"events": 0, "alerts": 0, "decisions": 0, "reports": 0}
    assert len(served.alerts) == len(result.alerts) and len(served.decisions) == len(result.decisions)


def test_the_summary_labels_its_stubs_and_its_approximation(tmp_path):
    folder = session(tmp_path, full_recording())
    summary = output.write_session(run_session(folder), folder, tmp_path / "out", None)
    notes = summary["notes"]
    assert "NOT USED" in notes["scorer"] and "STUB" in notes["report_writer"]
    assert notes["fim_baseline"].startswith("APPROXIMATION")
    assert "empty" in notes["suspended_pids"]
    assert notes["microsoft_root"].startswith("0 of")  # recordings 1 to 11 have no such field


def test_labels_reach_the_summary_but_never_a_decision(tmp_path):
    without = tmp_path / "plain"
    with_labels = tmp_path / "labelled"
    for root, labels in ((without, False), (with_labels, True)):
        write_session(root, full_recording(), labels=labels, session_id="s1")
    a, b = run_session(without), run_session(with_labels)
    assert (a.alerts, a.decisions, a.reports) == (b.alerts, b.decisions, b.reports)
    summary = output.summarise(b, output.labels_for(with_labels, None), "x")
    assert "alerts_by_part" in summary


def test_two_recordings_merge_and_a_repeated_id_is_refused(tmp_path):
    first_folder = session(tmp_path, full_recording(), "one")
    other = full_recording()
    text = json.dumps(other.events).replace("20261105T093000", "20261105T101500").replace("20261105T092955", "20261105T101455")
    other.events = json.loads(text)
    second_folder = session(tmp_path, other, "two")
    results = [(run_session(first_folder), first_folder), (run_session(second_folder), second_folder)]
    merged = output.write_merged(results, tmp_path / "out")
    alerts = json.loads((merged / "alerts.json").read_text(encoding="utf-8"))
    assert len(alerts) == len(results[0][0].alerts) + len(results[1][0].alerts)
    assert len({a["alert_id"] for a in alerts}) == len(alerts)
    twin = session(tmp_path, full_recording(), "twin")
    with pytest.raises(output.OutputError):
        output.write_merged([results[0], (run_session(twin), twin)], tmp_path / "out2")


# ---- reading is read-only -----------------------------------------------------------------


def digest(folder: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        hasher.update(path.name.encode() + path.read_bytes())
    return hasher.hexdigest()


def test_the_input_folder_is_never_changed(tmp_path):
    folder = session(tmp_path / "in", full_recording())
    before = digest(tmp_path / "in")
    code = cli.main([str(tmp_path / "in"), "--out", str(tmp_path / "out")])
    assert code == 0 and digest(tmp_path / "in") == before
    assert folder.exists() and (tmp_path / "out" / "s1" / "alerts.json").is_file()


@pytest.mark.parametrize("where", ["in", "in/s1", "in/s1/sub"])
def test_out_inside_an_input_is_refused(tmp_path, where):
    session(tmp_path / "in", full_recording())
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path / "in"), "--out", str(tmp_path / where)])
    assert not (tmp_path / "in" / "alerts.json").exists()


def test_it_runs_end_to_end_on_the_sample_files(tmp_path):
    shutil.copytree(ROOT / "contracts" / "samples", tmp_path / "samples", ignore=shutil.ignore_patterns("invalid"))
    (tmp_path / "samples" / "alerts.json").unlink()
    code = cli.main([str(tmp_path / "samples"), "--out", str(tmp_path / "out")])
    assert code == 0
    alerts = json.loads((tmp_path / "out" / "samples" / "alerts.json").read_text(encoding="utf-8"))
    assert {a["rule_id"] for a in alerts} >= {"R-T1003-001", "R-T1105-001", "R-FIM-HOSTS"}


# ---- walls -----------------------------------------------------------------------------------


def imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
    return found


@pytest.mark.parametrize("name", ["app", "views", "data", "store", "__main__"])
def test_the_api_modules_never_import_policy_or_the_pipeline(name):
    for module in imports(ROOT / "backend" / f"{name}.py"):
        assert module.split(".")[0] != "policy"
        assert not module.startswith("backend.pipeline")


NETWORK = {"httpx", "requests", "urllib", "urllib3", "socket", "http", "aiohttp", "anthropic", "openai", "langchain"}


@pytest.mark.parametrize("path", sorted((ROOT / "backend" / "pipeline").glob("*.py")), ids=lambda p: p.name)
def test_the_pipeline_makes_no_network_calls(path):
    assert not {m.split(".")[0] for m in imports(path)} & NETWORK


def test_policy_still_never_imports_the_backend():
    for path in (ROOT / "policy").glob("*.py"):
        assert not any(m.split(".")[0] == "backend" for m in imports(path)), path.name
