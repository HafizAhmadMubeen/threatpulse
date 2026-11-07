"""The rule evaluator: read-only, rule-neutral, and honest about what is in-sample."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from detection import rule_eval
from detection.behaviour import load_rules
from tests.event_builder import P, Recording
from tests.test_features import attack_recording
from tests.test_training import benign_recording, make_session

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "behaviour"


def rules_fingerprint() -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(RULES.glob("*.yaml"))}


@pytest.fixture
def export(tmp_path):
    for batch in (1, 3):
        make_session(tmp_path, f"s{batch}-attack", attack_recording(), batch=batch, technique="T1486")
        make_session(tmp_path, f"s{batch}-benign", benign_recording(), batch=batch, malicious=False)
    return tmp_path


def spec(export, numbers=(1, 3)):
    return [(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in numbers]


def test_a_rule_for_the_technique_firing_in_the_test_part_is_a_detection(export):
    result = rule_eval.evaluate(spec(export), only_labelled=False)
    tech = result["summary"]["per_technique"]["T1486"]
    assert tech["sessions"] == 2 and tech["detected"] == 2
    assert tech["rules_fired_in_test_part"]["R-T1486-001"] == 2
    assert tech["detected_out_of_sample_batches_3_4"] == {"detected": 1, "sessions": 1}
    rule = result["summary"]["per_rule"]["R-T1486-001"]
    assert rule["fired_in_test_part_of_own"] == 2 and rule["own_technique_sessions"] == 2


def test_other_rules_firing_in_the_test_part_are_cross_fires_not_hits(export):
    make_session(export, "s1-wrong", attack_recording(), batch=1, technique="T1059.001")
    result = rule_eval.evaluate(spec(export), only_labelled=False)
    tech = result["summary"]["per_technique"]["T1059.001"]
    assert tech["sessions"] == 1 and tech["detected"] == 0  # the attack recording does not do what T1059.001 rules want
    assert "R-T1486-001" in tech["rules_fired_in_test_part"]
    assert "T1059.001" in result["summary"]["per_rule"]["R-T1486-001"]["cross_fired_in_test_part_of_other_techniques"]


def test_benign_sessions_without_alerts_and_with_alerts_are_counted(export):
    quiet = rule_eval.evaluate(spec(export), only_labelled=False)["summary"]
    assert quiet["benign_sessions"] == 2 and quiet["benign_sessions_with_any_alert"] == 0
    noisy = Recording()
    app = P(900, 1, "C:\\Program Files\\App\\app.exe", "app.exe")
    noisy.start(app, 2.0)
    noisy.add(app, "registry_set", 3.0, registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App")
    make_session(export, "s3-noisy", noisy, batch=3, malicious=False)
    summary = rule_eval.evaluate(spec(export), only_labelled=False)["summary"]
    assert summary["benign_sessions"] == 3 and summary["benign_sessions_with_any_alert"] == 1
    assert summary["benign_by_batch"]["3"] == {"sessions": 2, "with_alert": 1}
    rule = summary["per_rule"]["R-T1547-001"]
    assert rule["benign_sessions_with_alert"] == 1 and rule["benign_alerts"] == 1
    assert rule["benign_sessions_with_alert_batches_3_4"] == {"with_alert": 1, "sessions": 2}


def test_alerts_before_start_utc_are_not_counted(export):
    early = Recording()
    app = P(901, 1, "C:\\Program Files\\App\\app.exe", "app.exe")
    early.start(app, 0.1)  # session.json starts at 0.8 s
    early.add(app, "registry_set", 0.2, registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Early")
    make_session(export, "s1-early", early, batch=1, malicious=False)
    summary = rule_eval.evaluate(spec(export), only_labelled=False)["summary"]
    assert summary["benign_sessions_with_any_alert"] == 0
    assert summary["alerts_outside_the_window"] == {"before_start": 1}


def test_fim_alerts_are_placed_by_the_test_window_since_they_have_no_labels(export):
    result = rule_eval.evaluate(spec(export), only_labelled=False)
    fim = [a for s in result["sessions"] if s["label"] == "malicious" for a in s["alerts"] if a["layer"] == "fim"]
    assert fim and all(a["placed_by_window"] and a["part"] == "test" for a in fim)
    assert result["summary"]["per_rule"]["R-FIM-PERSISTENCE"]["placed_by_window_only"] is True
    assert "by time window" in rule_eval.markdown(result)


def test_it_changes_no_rule_and_no_input(export, tmp_path_factory):
    before, inputs = rules_fingerprint(), {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in export.rglob("*") if p.is_file()}
    out = tmp_path_factory.mktemp("rule-eval-out")
    assert rule_eval.main(["--batch", "1", str(export / "batch-1"), str(export / "batch-1-labels"),
                           "--batch", "3", str(export / "batch-3"), str(export / "batch-3-labels"), "--out", str(out)]) == 0
    assert rules_fingerprint() == before
    assert inputs == {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in export.rglob("*") if p.is_file()}
    assert json.loads((out / "rule_eval.json").read_text(encoding="utf-8"))["summary"]["attack_sessions"] == 2
    assert "Where each rule comes from" in (out / "rule_eval.md").read_text(encoding="utf-8")


def test_the_cli_refuses_an_output_inside_an_input_and_labels_without_parts(export):
    with pytest.raises(SystemExit):
        rule_eval.main(["--batch", "1", str(export / "batch-1"), str(export / "batch-1-labels"),
                        "--out", str(export / "batch-1" / "report")])
    make_session(export, "s1-old", attack_recording(), batch=1, part=False)
    with pytest.raises(rule_eval.RuleEvalError, match="part"):
        rule_eval.evaluate(spec(export, (1,)), only_labelled=False)


def test_only_labelled_leaves_out_sessions_that_have_no_labels(export):
    make_session(export, "s3-first-attempt", attack_recording(), batch=3)
    (export / "batch-3-labels" / "s3-first-attempt" / "labels.csv").unlink()
    with pytest.raises(rule_eval.RuleEvalError, match="no labels"):
        rule_eval.evaluate(spec(export), only_labelled=False)
    result = rule_eval.evaluate(spec(export), only_labelled=True)
    assert "s3-first-attempt" not in {s["session_id"] for s in result["sessions"]}


# ---- provenance: the claims about in-sample status are checked against the repo ----------------


def test_the_engine_change_affects_exactly_the_rules_that_dedupe_on_text():
    affected = {r.id for r in load_rules() if any(name != "pid" for name in r.dedupe_by)}
    assert set(rule_eval.RULE_HISTORY["engine_change_after_data"]["affects"]) == affected
    assert set(rule_eval.BATCH_STATUS) == {1, 2, 3, 4} and rule_eval.OUT_OF_SAMPLE == (3, 4)


def test_rule_files_have_one_commit_so_nothing_was_tuned_after_data():
    """If a rule file is ever edited, this fails, and RULE_HISTORY must be updated: the report
    states which results are in-sample from it."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("no git history here")
    log = subprocess.run(["git", "log", "--format=%h", "--", "rules/behaviour/*.yaml"], cwd=ROOT,
                         capture_output=True, text=True, check=False)
    if log.returncode != 0 or log.stdout.strip() == "":
        pytest.skip("git history not available")
    commits = log.stdout.split()
    assert commits and commits[-1] == "9a68638" and len(commits) == 1, commits


def test_invalid_events_are_counted_and_reported_never_dropped_silently(export):
    bad = Recording()
    app = P(902, 1, "C:\\Program Files\\App\\app.exe", "app.exe")
    bad.start(app, 2.0)
    bad.add(app, "registry_set", 3.0, registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Bad",
            change={"kind": "added", "old_value": None, "new_value": "x"})  # not allowed on an ETW event
    make_session(export, "s1-bad", bad, batch=1, malicious=False)
    result = rule_eval.evaluate(spec(export), only_labelled=False)
    assert result["summary"]["events_skipped_as_invalid"] == 1
    assert "Skipped as invalid against the Event schema: 1" in rule_eval.markdown(result)


def test_every_rule_states_what_it_was_written_or_tuned_against(export):
    result = rule_eval.evaluate(spec(export), only_labelled=False)
    per_rule = result["summary"]["per_rule"]
    assert set(per_rule) == {r.id for r in load_rules()}
    for rule_id, r in per_rule.items():
        assert "out-of-sample" in r["written_or_tuned_against"] and "batches 3 and 4" in r["written_or_tuned_against"]
        assert ("IN-SAMPLE" in r["written_or_tuned_against"]) == (rule_id in rule_eval.RULE_HISTORY["engine_change_after_data"]["affects"])
    assert "guess" in per_rule["R-T1486-001"]["written_or_tuned_against"]
    text = rule_eval.markdown(result)
    assert "Written or tuned against" in text and "Batches 3 and 4 only (out-of-sample)" in text
