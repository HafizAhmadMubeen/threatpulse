"""Policy engine tests (PHASES.md step 3.1): every rule, with near misses."""

import copy
import itertools
import json
import random
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from contracts.validate_samples import load_validators
from detection import zones
from policy import AlertError, ContextError, PolicyError, decide, load_policy
from policy import paths
from policy.loader import POLICY_FILE, parse_policy

POLICY = load_policy()
VALIDATORS = load_validators()
SAMPLES = Path(__file__).resolve().parent.parent / "contracts" / "samples"

SYSTEM32 = "C:\\Windows\\System32\\"
SVCHOST = SYSTEM32 + "svchost.exe"
POWERSHELL = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
DESKTOP_SVCHOST = "C:\\Users\\lab\\Desktop\\svchost.exe"
ENFORCING = replace(POLICY, lsass_mode="enforcing")


def make_alert(*, layer="rule", rule_id=None, event_type="file_delete", zone="none",
               risk=None, pid=4321, image=POWERSHELL, signed=True, signer="Microsoft Windows",
               microsoft_root=None, access=(), path=None, key=None, number=1) -> dict:
    rule_id = rule_id or {"ml": "ML-TRIAGE", "signature": "SIG-TEST", "heuristic": "HEUR-TEST"}.get(layer, "R-TEST-001")
    subject = {
        "pid": pid, "image": image, "signed": signed, "signer": signer,
        "trusted_path": zones.is_trusted_image(image), "ancestors": [],
    }
    if pid == 0:
        subject.update(image="unknown", signed=False, signer=None, trusted_path=False)
    if microsoft_root is not None:
        subject["microsoft_root"] = microsoft_root
    return {
        "alert_id": f"a-20261105T093000-{number:06d}",
        "ts": "2026-11-05T09:30:05.000Z",
        "layer": layer,
        "rule_id": rule_id,
        "technique_ids": ["T1486"],
        "risk_score": risk,
        "event_type": event_type,
        "subject": subject,
        "object": {"zone": zone, "path": path, "registry_key": key, "access": list(access), "file_sha256": None},
        "evidence_event_ids": [] if pid == 0 else ["e-20261105T093000-000001"],
    }


def run(alert, context=None, policy=POLICY) -> dict:
    """decide, plus the one check that matters for every case: the Decision is valid."""
    decision = decide(alert, context, policy)
    errors = [e.message for e in VALIDATORS["decision"].iter_errors(decision)]
    assert errors == [], errors
    return decision


def actions_of(decision) -> list[tuple[str, str]]:
    return [(a["action"], a["status"]) for a in decision["actions"]]


def only(decision) -> dict:
    assert len(decision["actions"]) == 1
    return decision["actions"][0]


# ---- default -----------------------------------------------------------------------


def test_default_is_alert_only_and_lists_no_rule():
    decision = run(make_alert(risk=0.2))
    assert decision["policy_rules"] == []
    assert actions_of(decision) == [("alert_only", "executed")]
    assert only(decision)["executed_at"] == decision["ts"]


def test_decision_ids_and_attributes_follow_the_alert():
    decision = run(make_alert(number=42, risk=0.4, zone="documents"))
    assert decision["decision_id"] == "d-20261105T093000-000042"
    assert decision["alert_id"] == "a-20261105T093000-000042"
    assert decision["ts"] == "2026-11-05T09:30:05.000Z"
    attributes = decision["attributes"]
    assert (attributes["zone"], attributes["signed"], attributes["risk_score"]) == ("documents", True, 0.4)


def test_now_in_the_context_sets_the_decision_time():
    decision = run(make_alert(), {"now": "2026-11-05T09:31:00.000Z"})
    assert decision["ts"] == "2026-11-05T09:31:00.000Z"


# ---- P3, P4: risk score thresholds --------------------------------------------------


@pytest.mark.parametrize("risk,fires", [(0.80, True), (0.9999, True), (0.7999, False), (0.0, False), (None, False)])
def test_p3_ransomware_threshold(risk, fires):
    decision = run(make_alert(zone="documents", risk=risk))
    assert ("P3-ransomware" in decision["policy_rules"]) is fires
    assert actions_of(decision) == ([("suspend", "pending")] if fires else [("alert_only", "executed")])


def test_p3_names_its_target():
    action = only(run(make_alert(zone="documents", risk=0.9, pid=6120)))
    assert action["target"] == {"pid": 6120, "image": POWERSHELL}
    assert action["automatic"] is True and action["executed_at"] is None


def test_p3_needs_the_documents_zone():
    assert run(make_alert(zone="none", risk=0.99))["policy_rules"] == []
    assert run(make_alert(zone="network", risk=0.99))["policy_rules"] == []


@pytest.mark.parametrize("event_type,risk,fires", [
    ("network_connect", 0.80, True), ("network_connect", 0.79, False),
    ("network_connect", None, False), ("file_write", 0.99, False),
])
def test_p4_exfil(event_type, risk, fires):
    decision = run(make_alert(event_type=event_type, zone="network", risk=risk))
    assert ("P4-exfil" in decision["policy_rules"]) is fires
    if fires:
        assert actions_of(decision) == [("block_network", "pending")]


def test_thresholds_come_from_the_yaml():
    stricter = replace(POLICY, thresholds={**POLICY.thresholds, "auto_contain": 0.95})
    alert = make_alert(zone="documents", risk=0.90)
    assert actions_of(run(alert, policy=POLICY)) == [("suspend", "pending")]
    assert actions_of(run(alert, policy=stricter)) == [("alert_only", "executed")]


def test_a_null_risk_score_never_matches_risk_score_gte():
    """Even a rule whose threshold is 0 must not match an alert that was never scored."""
    zero = replace(POLICY, thresholds={"alert": 0.0, "auto_contain": 0.0, "request_kill": 0.0})
    for zone, event_type in [("documents", "file_delete"), ("network", "network_connect"), ("persistence", "registry_set")]:
        decision = run(make_alert(zone=zone, event_type=event_type, risk=None), policy=zero)
        assert not set(decision["policy_rules"]) & {"P2b-persistence-origin", "P3-ransomware", "P4-exfil", "P5-kill-request"}
    suspended = run(make_alert(zone="documents", risk=None), {"suspended_pids": [4321]}, zero)
    assert "P5-kill-request" not in suspended["policy_rules"]
    assert run(make_alert(zone="documents", risk=0.0), policy=zero)["policy_rules"] == ["P3-ransomware"]


# ---- P1: LSASS ----------------------------------------------------------------------

LSASS = dict(event_type="process_access", zone="lsass", access=["vm_read"], risk=None,
             image="C:\\Users\\lab\\Desktop\\procdump.exe", signed=False, signer=None)


def test_p1_learning_mode_only_alerts():
    decision = run(make_alert(**LSASS))
    assert decision["policy_rules"] == ["P1-lsass-read"]
    assert actions_of(decision) == [("alert_only", "executed")]
    assert decision["attributes"]["lsass_mode"] == "learning"


def test_p1_enforcing_mode_suspends():
    decision = run(make_alert(**LSASS), policy=ENFORCING)
    assert decision["policy_rules"] == ["P1-lsass-read"]
    assert actions_of(decision) == [("suspend", "pending")]
    assert only(decision)["target"]["image"].endswith("procdump.exe")
    assert decision["attributes"]["lsass_mode"] == "enforcing"


def test_p1_does_not_need_a_risk_score():
    assert run(make_alert(**LSASS), policy=ENFORCING)["attributes"]["risk_score"] is None


@pytest.mark.parametrize("change", [
    {"access": ["query_limited_information"]}, {"access": []}, {"zone": "none"},
    {"event_type": "file_write"},
])
def test_p1_near_misses(change):
    decision = run(make_alert(**{**LSASS, **change}), policy=ENFORCING)
    assert "P1-lsass-read" not in decision["policy_rules"]


def test_p1_allowlist_needs_path_and_a_verified_microsoft_root():
    allow = replace(ENFORCING, lsass_allowlist=(
        next(e for e in POLICY.never_suspend if e.path == SYSTEM32 + "services.exe"),))
    reader = dict(LSASS, image=SYSTEM32 + "services.exe", signed=True, signer="Microsoft Windows")
    assert "P1-lsass-read" not in run(make_alert(**reader, microsoft_root=True), policy=allow)["policy_rules"]
    # unknown must NOT be trusted here: a wrong yes would hide an attack
    assert "P1-lsass-read" in run(make_alert(**reader), policy=allow)["policy_rules"]
    assert "P1-lsass-read" in run(make_alert(**reader, microsoft_root=False), policy=allow)["policy_rules"]
    other_path = dict(reader, image="C:\\Users\\lab\\Desktop\\services.exe")
    assert "P1-lsass-read" in run(make_alert(**other_path, microsoft_root=True), policy=allow)["policy_rules"]


def test_p1_signed_rundll32_is_not_trusted_just_for_being_signed():
    rundll = dict(LSASS, image=SYSTEM32 + "rundll32.exe", signed=True, signer="Microsoft Windows")
    decision = run(make_alert(**rundll, microsoft_root=True), policy=ENFORCING)
    assert actions_of(decision) == [("suspend", "pending")]


# ---- P2 and P2b: persistence --------------------------------------------------------

KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AtomicTest"
FIM = dict(layer="fim", rule_id="R-FIM-PERSISTENCE", event_type="fim_change", zone="persistence",
           pid=0, key=KEY, risk=None)


def fim(differs, settled):
    return {"fim": {"differs_from_baseline": differs, "settled_seconds": settled}}


@pytest.mark.parametrize("differs,settled,status,why", [
    (True, 2.0, "pending", None),
    (True, 30.0, "pending", None),
    (True, 1.99, "skipped", "settled"),
    (True, 0.14, "skipped", "settled"),
    (None, 30.0, "skipped", "unknown"),
])
def test_p2_restores_only_changes_that_still_differ_after_the_debounce(differs, settled, status, why):
    decision = run(make_alert(**FIM), fim(differs, settled))
    assert decision["policy_rules"] == ["P2-persistence-change"]
    action = only(decision)
    assert (action["action"], action["status"]) == ("restore", status)
    assert why is None or why in action["reason"]


def test_p2_skips_when_nothing_is_known_about_the_baseline():
    action = only(run(make_alert(**FIM)))
    assert (action["action"], action["status"]) == ("restore", "skipped")


def test_p2_edge_rewrite_that_is_back_at_the_baseline_is_not_restored():
    """Batch 1: Edge removed and re-added its autolaunch value 140 ms apart. After the
    debounce the value matches the baseline again, so there is nothing to restore."""
    decision = run(make_alert(**FIM), fim(False, 2.5))
    assert decision["policy_rules"] == []
    assert actions_of(decision) == [("alert_only", "executed")]
    assert decision["attributes"]["fim_state"] == "matches_baseline"
    assert decision["attributes"]["change_approved"] is True


def test_p2_debounce_comes_from_the_yaml():
    patient = replace(POLICY, fim_debounce_seconds=10.0)
    assert actions_of(run(make_alert(**FIM), fim(True, 5.0), patient)) == [("restore", "skipped")]
    assert actions_of(run(make_alert(**FIM), fim(True, 10.0), patient)) == [("restore", "pending")]


def test_p2_applies_to_a_behaviour_rule_alert_in_the_persistence_zone_too():
    alert = make_alert(layer="rule", rule_id="R-T1547-001", event_type="registry_set",
                       zone="persistence", key=KEY, risk=0.3, image=SYSTEM32 + "reg.exe")
    assert actions_of(run(alert, fim(True, 3))) == [("restore", "pending")]


def test_p2_is_not_for_other_zones():
    assert run(make_alert(zone="documents"), fim(True, 9))["policy_rules"] == []


TREE = [
    {"pid": 5332, "image": SYSTEM32 + "reg.exe", "alive": True, "risk_score": 0.91},
    {"pid": 5300, "image": POWERSHELL, "alive": True, "risk_score": 0.60},
]


def test_p2b_suspends_the_highest_risk_live_process_in_the_writers_tree():
    decision = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": TREE})
    assert decision["policy_rules"] == ["P2-persistence-change", "P2b-persistence-origin"]
    assert actions_of(decision) == [("restore", "pending"), ("suspend", "pending")]
    assert decision["actions"][1]["target"] == {"pid": 5332, "image": SYSTEM32 + "reg.exe"}


def test_p2b_skips_when_every_process_has_exited():
    gone = [{**c, "alive": False} for c in TREE]
    decision = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": gone})
    suspend = decision["actions"][1]
    assert (suspend["action"], suspend["status"]) == ("suspend", "skipped")
    assert "exited" in suspend["reason"]
    assert "target" not in suspend


def test_p2b_falls_to_the_next_live_process_when_the_best_one_has_exited():
    tree = [{**TREE[0], "alive": False}, {**TREE[1], "risk_score": 0.85}]
    suspend = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": tree})["actions"][1]
    assert suspend["target"]["pid"] == 5300


def test_p2b_does_not_fire_when_no_process_in_the_tree_scores_high_enough():
    weak = [{**c, "risk_score": 0.5} for c in TREE]
    decision = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": weak})
    assert decision["policy_rules"] == ["P2-persistence-change"]


def test_p2b_null_scores_in_the_tree_never_match():
    unscored = [{**c, "risk_score": None} for c in TREE]
    decision = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": unscored})
    assert "P2b-persistence-origin" not in decision["policy_rules"]


def test_p2b_without_a_writer_tree_never_fires():
    assert "P2b-persistence-origin" not in run(make_alert(**FIM), fim(True, 3))["policy_rules"]


def test_p2b_never_picks_a_never_suspend_process():
    tree = [{"pid": 700, "image": SVCHOST, "alive": True, "risk_score": 0.99, "microsoft_root": True},
            {"pid": 5332, "image": SYSTEM32 + "reg.exe", "alive": True, "risk_score": 0.90}]
    suspend = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": tree})["actions"][1]
    assert suspend["target"]["pid"] == 5332
    only_svchost = run(make_alert(**FIM), {**fim(True, 3), "writer_tree": tree[:1]})["actions"][1]
    assert only_svchost["status"] == "skipped" and "never-suspend" in only_svchost["reason"]


def test_p2b_uses_the_alerts_own_score_when_the_alert_has_a_process():
    alert = make_alert(layer="rule", rule_id="R-T1547-001", event_type="registry_set",
                       zone="persistence", key=KEY, risk=0.91, image=SYSTEM32 + "reg.exe", pid=5332)
    decision = run(alert, fim(True, 3))
    assert actions_of(decision) == [("restore", "pending"), ("suspend", "pending")]


# ---- P5: kill request ---------------------------------------------------------------


@pytest.mark.parametrize("risk,suspended,fires", [
    (0.95, True, True), (0.99, True, True), (0.9499, True, False),
    (0.99, False, False), (None, True, False),
])
def test_p5_kill_request(risk, suspended, fires):
    context = {"suspended_pids": [6120] if suspended else []}
    decision = run(make_alert(zone="documents", pid=6120, risk=risk), context)
    assert ("P5-kill-request" in decision["policy_rules"]) is fires
    if fires:
        kill = next(a for a in decision["actions"] if a["action"] == "request_kill")
        assert kill["automatic"] is False and kill["status"] == "awaiting_approval"
        assert kill["executed_at"] is None and kill["target"]["pid"] == 6120


def test_p5_another_process_being_suspended_does_not_count():
    assert "P5-kill-request" not in run(make_alert(pid=6120, risk=0.99), {"suspended_pids": [1]})["policy_rules"]


def test_p5_can_combine_with_p3():
    decision = run(make_alert(zone="documents", pid=6120, risk=0.97), {"suspended_pids": [6120]})
    assert decision["policy_rules"] == ["P3-ransomware", "P5-kill-request"]
    assert actions_of(decision) == [("suspend", "pending"), ("request_kill", "awaiting_approval")]
    assert decision["attributes"]["already_suspended"] is True


# ---- P6: delete request -------------------------------------------------------------


def test_p6_signature_match_requests_a_delete():
    alert = make_alert(layer="signature", rule_id="SIG-EICAR", event_type="file_scan", pid=0,
                       path="C:\\Users\\lab\\Downloads\\eicar.com")
    decision = run(alert)
    assert decision["policy_rules"] == ["P6-delete-request"]
    action = only(decision)
    assert (action["action"], action["automatic"], action["status"]) == ("request_delete", False, "awaiting_approval")
    assert action["executed_at"] is None


def test_p6_needs_a_file_path():
    decision = run(make_alert(layer="signature", rule_id="SIG-X", event_type="file_scan", pid=0))
    assert decision["policy_rules"] == ["P6-delete-request"]
    assert actions_of(decision) == [("alert_only", "executed")]
    assert "no file path" in decision["attributes"]["not_requested"][0]


@pytest.mark.parametrize("layer", ["heuristic", "rule", "fim", "ml"])
def test_p6_is_for_signature_alerts_only(layer):
    alert = make_alert(layer=layer, event_type="file_scan", pid=0, path="C:\\x\\y.exe", risk=None)
    assert "P6-delete-request" not in run(alert)["policy_rules"]


# ---- never suspend -------------------------------------------------------------------

GUARDED = [
    ("P3 suspend", dict(zone="documents", risk=0.99), "suspend"),
    ("P4 block", dict(event_type="network_connect", zone="network", risk=0.99), "block_network"),
]


@pytest.mark.parametrize("label,base,name", GUARDED)
def test_never_suspend_needs_the_exact_path_and_a_verified_microsoft_root(label, base, name):
    # the real file, verified: protected
    action = only(run(make_alert(**base, image=SVCHOST, microsoft_root=True)))
    assert (action["action"], action["status"]) == (name, "skipped")
    assert "never-suspend list" in action["reason"] and action["target"]["image"] == SVCHOST
    # same name on the Desktop: not protected, even with a Microsoft chain
    assert only(run(make_alert(**base, image=DESKTOP_SVCHOST, microsoft_root=True)))["status"] == "pending"
    # the signer text says Microsoft but the root check said no: not protected
    liar = only(run(make_alert(**base, image=SVCHOST, signer="Microsoft Windows", microsoft_root=False)))
    assert liar["status"] == "pending"


@pytest.mark.parametrize("label,base,name", GUARDED)
def test_never_suspend_unknown_root_on_a_protected_path_is_protected(label, base, name):
    action = only(run(make_alert(**base, image=SVCHOST)))
    assert action["status"] == "skipped"
    assert "microsoft_root unknown" in action["reason"]


def test_never_suspend_does_not_trust_the_signer_text():
    a = run(make_alert(zone="documents", risk=0.99, image=SVCHOST, signer="Microsoft Windows", microsoft_root=False))
    b = run(make_alert(zone="documents", risk=0.99, image=SVCHOST, signer="Evil Corp", microsoft_root=False))
    c = run(make_alert(zone="documents", risk=0.99, image=SVCHOST, signer="Evil Corp", microsoft_root=True))
    assert (a["actions"], b["actions"]) == (a["actions"], a["actions"])
    assert only(c)["status"] == "skipped"


@pytest.mark.parametrize("image", [
    "c:\\windows\\system32\\SVCHOST.EXE", "C:/Windows/System32/svchost.exe",
    "C:\\Windows\\System32\\.\\svchost.exe", "C:\\Windows\\Temp\\..\\System32\\svchost.exe",
    "\\\\?\\C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\svchost.exe.",
])
def test_never_suspend_sees_through_other_spellings_of_the_path(image):
    assert only(run(make_alert(zone="documents", risk=0.99, image=image, microsoft_root=True)))["status"] == "skipped"


@pytest.mark.parametrize("image", [
    "C:\\Windows\\System32\\svchost.exe.bak", "C:\\Windows\\System32\\x\\svchost.exe",
    "C:\\Windows\\System32\\svchost", "svchost.exe", "D:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\SYSTEM~1\\svchost.exe", "C:\\Windows\\System32\\..\\..\\..\\svchost.exe",
    "C:\\Windows\\System32\\svchost.exe\\..\\evil.exe",
])
def test_never_suspend_ignores_paths_that_only_look_alike(image):
    assert only(run(make_alert(zone="documents", risk=0.99, image=image, microsoft_root=True)))["status"] == "pending"


def test_never_suspend_system_process():
    system = run(make_alert(zone="documents", risk=0.99, pid=4, image="System", microsoft_root=True))
    assert only(system)["status"] == "skipped"
    # a user process that merely calls itself System, or a pid-4 look-alike path
    assert only(run(make_alert(zone="documents", risk=0.99, pid=999, image="System")))["status"] == "pending"
    assert only(run(make_alert(zone="documents", risk=0.99, pid=4, image="C:\\x\\evil.exe")))["status"] == "pending"


def test_never_suspend_defender_version_folder_wildcard():
    defender = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26010.5-0\\MsMpEng.exe"
    assert only(run(make_alert(zone="documents", risk=0.99, image=defender, microsoft_root=True)))["status"] == "skipped"
    too_deep = defender.replace("MsMpEng.exe", "x\\MsMpEng.exe")
    assert only(run(make_alert(zone="documents", risk=0.99, image=too_deep, microsoft_root=True)))["status"] == "pending"


def test_never_suspend_our_own_programs_match_by_exact_path_only():
    agent = "C:\\ThreatPulseLab\\threatpulse\\agent\\build\\Release\\threatpulse_agent.exe"
    for signed in (True, False):  # signature: none, so the signature is not asked about
        assert only(run(make_alert(zone="documents", risk=0.99, image=agent, signed=signed)))["status"] == "skipped"
    other = "C:\\ThreatPulseLab\\samples\\evil.exe"
    assert only(run(make_alert(zone="documents", risk=0.99, image=other)))["status"] == "pending"
    sibling = "C:\\ThreatPulseLab\\threatpulse\\agent\\build\\Release\\other.exe"
    assert only(run(make_alert(zone="documents", risk=0.99, image=sibling)))["status"] == "pending"


def test_never_suspend_does_not_list_the_whole_lab_tree():
    for entry in POLICY.never_suspend:
        assert not entry.path.lower().rstrip("\\").endswith("threatpulselab")
        assert entry.signature == "microsoft" or entry.path.lower().endswith(".exe")


def test_never_suspend_also_refuses_a_kill_request():
    decision = run(make_alert(zone="documents", pid=700, image=SVCHOST, risk=0.99, microsoft_root=True),
                   {"suspended_pids": [700]})
    assert "P5-kill-request" in decision["policy_rules"]
    assert [a["action"] for a in decision["actions"]] == ["suspend"]
    assert decision["actions"][0]["status"] == "skipped"
    assert any("request_kill" in note for note in decision["attributes"]["not_requested"])


def test_never_suspend_with_nothing_left_still_gives_an_alert():
    decision = run(make_alert(zone="none", pid=700, image=SVCHOST, risk=0.99, microsoft_root=True,
                              event_type="file_delete"), {"suspended_pids": [700]})
    assert decision["policy_rules"] == ["P5-kill-request"]
    assert actions_of(decision) == [("alert_only", "executed")]


# ---- paths ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "", 5, "relative\\a.exe", "C:", "C:\\", "\x00C:\\a", "C:\\..\\a", "C:\\PROGRA~1\\a.exe"])
def test_paths_that_cannot_be_trusted_do_not_normalise(value):
    assert paths.normalise(value) is None


def test_paths_compare_by_whole_segments():
    assert paths.matches("c:/windows/system32/svchost.exe", SVCHOST)
    assert not paths.matches("C:\\Windows\\System32\\svchost.exe2", SVCHOST)
    pattern = "C:\\A\\*\\b.exe"
    assert paths.matches("C:\\A\\1.2\\b.exe", pattern)
    assert not paths.matches("C:\\A\\b.exe", pattern)
    assert not paths.matches("C:\\A\\1\\2\\b.exe", pattern)


# ---- loading -------------------------------------------------------------------------


def policy_data() -> dict:
    return yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))


def test_the_shipped_policy_loads_and_has_the_planned_rules():
    assert [rule.id for rule in POLICY.rules] == [
        "P1-lsass-read", "P2-persistence-change", "P2b-persistence-origin",
        "P3-ransomware", "P4-exfil", "P5-kill-request", "P6-delete-request"]
    assert POLICY.thresholds == {"auto_contain": 0.80, "request_kill": 0.95, "alert": 0.50}
    assert POLICY.lsass_mode == "learning" and POLICY.default == ("alert_only",)
    assert POLICY.fim_debounce_seconds == 2.0


def test_trusted_dirs_stay_in_step_with_detection():
    assert tuple(POLICY.trusted_dirs) == zones.TRUSTED_DIRS


def mutate(change):
    data = policy_data()
    change(data)
    return data


BROKEN = {
    "unknown top-level key": lambda d: d.update(extra=1),
    "missing key": lambda d: d.pop("never_suspend"),
    "threshold above 1": lambda d: d["thresholds"].update(auto_contain=1.5),
    "threshold order": lambda d: d["thresholds"].update(request_kill=0.5),
    "threshold as text": lambda d: d["thresholds"].update(alert="0.5"),
    "bad lsass mode": lambda d: d.update(lsass_mode="paranoid"),
    "bad debounce": lambda d: d.update(fim_debounce_seconds=-1),
    "default changed": lambda d: d.update(default=["suspend"]),
    "unknown action": lambda d: d["rules"][0].update(actions=["format_disk"]),
    "no actions": lambda d: d["rules"][0].update(actions=[]),
    "unknown condition": lambda d: d["rules"][0]["when"].update(colour="red"),
    "empty condition": lambda d: d["rules"][0].update(when={}),
    "unknown zone": lambda d: d["rules"][0]["when"].update(zone="kernel"),
    "unknown threshold name": lambda d: d["rules"][3]["when"].update(risk_score_gte="sky_high"),
    "duplicate rule id": lambda d: d["rules"][1].update(id=d["rules"][0]["id"]),
    "bad rule id": lambda d: d["rules"][0].update(id="rule one"),
    "relative path": lambda d: d["never_suspend"].append({"path": "svchost.exe"}),
    "name only entry": lambda d: d["never_suspend"].append({"path": "C:\\"}),
    "wildcard in a file name": lambda d: d["never_suspend"].append({"path": "C:\\a\\*.exe"}),
    "wildcard as the file": lambda d: d["never_suspend"].append({"path": "C:\\a\\*"}),
    "bad signature kind": lambda d: d["never_suspend"].append({"path": "C:\\a\\b.exe", "signature": "trust-me"}),
    "system in the allowlist": lambda d: d["lsass_allowlist"].append({"system": True}),
    "short name path": lambda d: d["never_suspend"].append({"path": "C:\\PROGRA~1\\a.exe"}),
}


@pytest.mark.parametrize("name", BROKEN)
def test_a_wrong_policy_stops_loading(name):
    with pytest.raises(PolicyError):
        parse_policy(mutate(BROKEN[name]))


def test_a_missing_policy_file_stops_loading(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.yaml")


# ---- bad input -----------------------------------------------------------------------


def test_an_invalid_alert_is_rejected():
    broken = make_alert()
    del broken["subject"]
    with pytest.raises(AlertError):
        decide(broken)


@pytest.mark.parametrize("context", [
    {"now": "yesterday"}, {"suspended_pids": "4321"}, {"suspended_pids": [True]},
    {"fim": {"differs_from_baseline": 1, "settled_seconds": 3}},
    {"fim": {"differs_from_baseline": True, "settled_seconds": -1}},
    {"fim": {"differs_from_baseline": True}}, {"fim": "yes"},
    {"writer_tree": "reg.exe"}, {"writer_tree": [{"pid": 1}]},
    {"writer_tree": [{"pid": 5, "image": "C:\\a.exe", "alive": True, "risk_score": 2}]},
    "context",
])
def test_a_malformed_context_is_rejected_not_guessed_at(context):
    with pytest.raises(ContextError):
        decide(make_alert(), context)


# ---- determinism and validity over many inputs ----------------------------------------


def grid():
    for layer, zone, event_type, risk, pid, image, root, access, suspended, state in itertools.product(
        ("signature", "fim", "rule"),
        ("documents", "persistence", "lsass", "network"),
        ("process_access", "network_connect", "fim_change"),
        (None, 0.5, 0.8, 0.97),
        (0, 4, 700),
        ("System", SVCHOST, DESKTOP_SVCHOST),
        (None, True, False),
        ((), ("vm_read",)),
        (False, True),
        (None, (True, 0.5), (True, 5)),
    ):
        if pid == 0 and not (layer in ("fim", "signature") or event_type in ("fim_change", "file_scan")):
            continue
        yield layer, zone, event_type, risk, pid, image, root, access, suspended, state


def test_every_decision_validates_and_is_deterministic():
    """A fixed random sample of the full grid (about 20,000 combinations), so it stays fast."""
    cases = list(grid())
    count = 0
    for layer, zone, event_type, risk, pid, image, root, access, suspended, state in random.Random(7).sample(cases, 1200):
        risk = None if pid == 0 else risk  # an alert with no process is never scored
        alert = make_alert(layer=layer, zone=zone, event_type=event_type, risk=risk, pid=pid, image=image,
                           microsoft_root=root, access=access, path="C:\\a\\b.txt")
        context = {"suspended_pids": [pid] if suspended else []}
        if state:
            context["fim"] = {"differs_from_baseline": state[0], "settled_seconds": state[1]}
        for policy in (POLICY, ENFORCING):
            first = run(alert, context, policy)
            assert first == decide(copy.deepcopy(alert), copy.deepcopy(context), policy)
            for entry in first["actions"]:
                if entry["action"] in ("suspend", "block_network", "request_kill") and entry["status"] in ("pending", "awaiting_approval"):
                    assert entry["target"]["pid"] > 0
        count += 1
    assert count == 1200 and len(cases) > 10000


def test_decide_does_not_change_its_inputs():
    alert, context = make_alert(zone="documents", risk=0.9), {"suspended_pids": [1], "writer_tree": TREE}
    before = copy.deepcopy((alert, context))
    run(alert, context)
    assert (alert, context) == before


def test_the_sample_alerts_all_get_a_valid_decision():
    alerts = json.loads((SAMPLES / "alerts.json").read_text(encoding="utf-8"))
    assert len(alerts) == 10
    for alert in alerts:
        run(alert)


# ---- the contract changes -------------------------------------------------------------


def valid(kind, instance):
    return [e.message for e in VALIDATORS[kind].iter_errors(instance)]


def test_decision_schema_allows_pending_only_for_automatic_actions():
    decision = run(make_alert(zone="documents", risk=0.9))
    assert valid("decision", decision) == []
    pending = decision["actions"][0]
    assert pending["status"] == "pending" and pending["executed_at"] is None
    broken = copy.deepcopy(decision)
    broken["actions"][0]["executed_at"] = "2026-11-05T09:30:06Z"
    assert valid("decision", broken)
    request = copy.deepcopy(decision)
    request["actions"][0].update(action="request_kill", automatic=False)
    assert valid("decision", request)


def test_decision_schema_target_is_checked():
    decision = run(make_alert(zone="documents", risk=0.9))
    for bad in ({"pid": 0, "image": "x"}, {"pid": 5}, {"pid": 5, "image": "x", "extra": 1}):
        broken = copy.deepcopy(decision)
        broken["actions"][0]["target"] = bad
        assert valid("decision", broken)


def test_alert_and_event_schemas_take_an_optional_microsoft_root():
    alert = make_alert(microsoft_root=True)
    assert valid("alert", alert) == []
    alert["subject"]["microsoft_root"] = "yes"
    assert valid("alert", alert)
    event = json.loads((SAMPLES / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert valid("event", event) == []
    event["process"]["microsoft_root"] = True
    assert valid("event", event) == []
    event["process"]["microsoft_root"] = "yes"
    assert valid("event", event)


def test_detection_copies_microsoft_root_from_the_event_and_never_invents_it():
    from detection.behaviour import reset_engine
    from detection.replay import replay
    from tests.event_builder import P, RUN_KEY, Recording

    for sent, expected in ((True, True), (False, False), (None, "absent")):
        reset_engine()
        recording = Recording()
        event = recording.add(P(5332, 1, SYSTEM32 + "reg.exe"), "registry_set", 1.0, registry_key=RUN_KEY)
        if sent is not None:
            event["process"]["microsoft_root"] = sent
        alert = next(a for a in replay(recording.events) if a["rule_id"] == "R-T1547-001")
        assert alert["subject"].get("microsoft_root", "absent") == expected
        assert valid("alert", alert) == []
