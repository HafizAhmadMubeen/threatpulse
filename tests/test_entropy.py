"""The entropy signal for ransomware (R-T1486-002) and the rule that acts on it.

Files here are synthetic: random bytes stand in for encrypted output, repeated text for
an extracted document. No real malware, nothing is executed.
"""

import ast
import os
import stat
from pathlib import Path

import pytest

from backend.pipeline import run_session
from backend.rag.prompt import is_high_risk
from detection import entropy, ransom
from detection.entropy import FileSampler, Limits, Sample, is_suspect, magic_of, shannon_entropy
from detection.ransom import HIGH, LOW, UNKNOWN, verdict_of
from policy import decide
from tests.event_builder import POWERSHELL, P, Recording
from tests.test_features import write_session
from tests.test_policy import POLICY, SVCHOST, make_alert, run

ROOT = Path(__file__).resolve().parent.parent
DOCS = "C:\\Users\\lab\\Documents\\ThreatPulseTest"
JPEG_HEADER = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
TEXT = b"The quarterly report is attached. Please review the figures before Friday.\n" * 40


def random_bytes(size: int = 4096) -> bytes:
    return os.urandom(size)


@pytest.fixture
def home(tmp_path):
    """A fake user profile. `translate` maps the recording's C:\\Users\\lab onto it."""
    (tmp_path / "Documents" / "ThreatPulseTest").mkdir(parents=True)
    return tmp_path


def translate_for(home: Path):
    return lambda path: str(home) + path.replace("C:\\Users\\lab", "").replace("\\", "/")


def sampler_for(home: Path, **limits) -> FileSampler:
    return FileSampler(translate=translate_for(home), limits=Limits(**limits) if limits else None)


def put(home: Path, name: str, data: bytes) -> str:
    """Write a file into the fake documents folder, return its recorded (Windows) path."""
    (home / "Documents" / "ThreatPulseTest" / name).write_bytes(data)
    return f"{DOCS}\\{name}"


# ---- entropy and format ---------------------------------------------------------------


def test_entropy_of_random_and_repeated_bytes():
    assert shannon_entropy(random_bytes(8192)) > 7.9
    assert shannon_entropy(TEXT) < 5
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"\x00" * 1000) == 0


def test_magic_and_suspect_rules():
    random = random_bytes()
    jpeg = JPEG_HEADER + random
    assert magic_of(jpeg) == "jpeg" and magic_of(random[:0] + b"PK\x03\x04" + random) == "zip"
    high = lambda magic: Sample(entropy=7.9, magic=magic, size=4096)  # noqa: E731
    # Random bytes with no header: encrypted-looking, whatever the name.
    assert is_suspect(high(None), "C:\\Users\\lab\\Documents\\a.docx")
    assert is_suspect(high(None), "C:\\Users\\lab\\Documents\\a.locked")
    # Compressed data that is what its name says (extracting a zip full of JPEGs): ordinary.
    assert not is_suspect(high("jpeg"), "C:\\Users\\lab\\Documents\\a.jpg")
    assert not is_suspect(high("zip"), "C:\\Users\\lab\\Documents\\a.docx")
    assert not is_suspect(high("zip"), "C:\\Users\\lab\\Documents\\a.unknownext")
    # A header for the wrong type is a mismatch.
    assert is_suspect(high("jpeg"), "C:\\Users\\lab\\Documents\\a.docx")
    # Low entropy is never suspect. The threshold is 7.5 bits per byte.
    assert not is_suspect(Sample(entropy=7.49, magic=None, size=4096), "C:\\Users\\lab\\Documents\\a.txt")
    assert is_suspect(Sample(entropy=7.5, magic=None, size=4096), "C:\\Users\\lab\\Documents\\a.txt")


def test_verdict_needs_five_files_and_80_percent():
    assert verdict_of([True] * 4) == UNKNOWN          # too few files
    assert verdict_of([True] * 5) == HIGH
    assert verdict_of([True] * 4 + [False]) == HIGH   # exactly 80%
    assert verdict_of([True] * 7 + [False] * 3) == UNKNOWN
    assert verdict_of([False] * 5) == LOW
    assert verdict_of([]) == UNKNOWN


# ---- the sampler: what it reads and what it refuses -----------------------------------


def test_sampler_reads_a_document_file(home):
    sampler = sampler_for(home)
    sample = sampler.sample(put(home, "a.locked", random_bytes(8192)), now=10)
    assert sample.entropy > 7.9 and sample.magic is None and sample.size == 8192
    low = sampler.sample(put(home, "b.txt", TEXT), now=10)
    assert low.entropy < 5


def test_sampler_reads_the_middle_of_a_big_file(home):
    # A text head followed by random data: the head alone would look ordinary.
    data = TEXT[:2000].ljust(entropy.HEAD_BYTES, b" ") + random_bytes(entropy.MIDDLE_BYTES * 4)
    sample = sampler_for(home).sample(put(home, "big.dat", data), now=1)
    head_only = shannon_entropy(data[:entropy.HEAD_BYTES])
    assert head_only < 1 and sample.entropy > 4  # the random middle was read too


def test_sampler_refuses_files_outside_the_documents_zone(home):
    (home / "AppData" / "Local").mkdir(parents=True)
    (home / "AppData" / "Local" / "x.bin").write_bytes(random_bytes())
    (home / "Downloads").mkdir()
    (home / "Downloads" / "y.bin").write_bytes(random_bytes())
    # Even under a Documents folder, program data is not the user's files.
    (home / "AppData" / "Local" / "Documents").mkdir()
    (home / "AppData" / "Local" / "Documents" / "z.bin").write_bytes(random_bytes())
    sampler = sampler_for(home)
    for path in ("C:\\Users\\lab\\AppData\\Local\\x.bin", "C:\\Users\\lab\\Downloads\\y.bin",
                 "C:\\Users\\lab\\AppData\\Local\\Documents\\z.bin", None, 42):
        assert sampler.sample(path, now=1) is None
    assert sampler.refused["outside_zone"] == 5


def test_sampler_never_opens_a_file_outside_the_zone(home, monkeypatch):
    opened = []
    real_open = os.open
    monkeypatch.setattr(os, "open", lambda *a, **k: opened.append(a[0]) or real_open(*a, **k))
    (home / "Downloads").mkdir()
    (home / "Downloads" / "y.bin").write_bytes(random_bytes())
    assert sampler_for(home).sample("C:\\Users\\lab\\Downloads\\y.bin", now=1) is None
    assert opened == []


def test_sampler_does_not_follow_a_symlinked_file(home):
    secret = home / "secret.bin"
    secret.write_bytes(random_bytes())
    link = home / "Documents" / "ThreatPulseTest" / "link.docx"
    link.symlink_to(secret)
    sampler = sampler_for(home)
    assert sampler.sample(f"{DOCS}\\link.docx", now=1) is None
    assert sampler.refused["link"] == 1


def test_sampler_does_not_follow_a_symlinked_folder(home):
    outside = home / "elsewhere"
    outside.mkdir()
    (outside / "f.bin").write_bytes(random_bytes())
    (home / "Documents" / "ThreatPulseTest" / "sub").symlink_to(outside, target_is_directory=True)
    sampler = sampler_for(home)
    assert sampler.sample(f"{DOCS}\\sub\\f.bin", now=1) is None
    assert sampler.refused["link"] == 1


def test_sampler_treats_a_windows_reparse_point_as_a_link():
    class Info:
        st_mode = stat.S_IFDIR
        st_file_attributes = 0x400
    assert entropy.is_link(Info())


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX pipes")
def test_sampler_does_not_open_a_pipe(home):
    os.mkfifo(home / "Documents" / "ThreatPulseTest" / "pipe.docx")
    sampler = sampler_for(home)
    assert sampler.sample(f"{DOCS}\\pipe.docx", now=1) is None  # and it returns, it does not hang
    assert sampler.refused["not_regular"] == 1


def test_sampler_limits_size_and_survives_missing_files(home, monkeypatch):
    sampler = sampler_for(home)
    assert sampler.sample(put(home, "tiny.txt", random_bytes(100)), now=1) is None
    assert sampler.refused["too_small"] == 1
    assert sampler.sample(f"{DOCS}\\gone.txt", now=1) is None
    assert sampler.refused["vanished"] == 1
    monkeypatch.setattr(entropy, "MAX_FILE_BYTES", 1000)
    assert sampler.sample(put(home, "big.bin", random_bytes(2000)), now=1) is None
    assert sampler.refused["too_big"] == 1
    assert sampler.sample(f"{DOCS}\\bad\x00name", now=1) is None  # no crash


def test_budget_stops_reading_and_recovers_with_time(home):
    sampler = sampler_for(home, files_per_window=3, window_seconds=10)
    paths = [put(home, f"f{i}.bin", random_bytes()) for i in range(5)]
    got = [sampler.sample(p, now=1.0) for p in paths]
    assert [g is not None for g in got] == [True, True, True, False, False]
    assert sampler.refused["budget"] == 2
    assert sampler.sample(paths[3], now=20.0) is not None  # a new window

    by_bytes = sampler_for(home, bytes_per_window=5000)
    assert by_bytes.sample(paths[0], now=1) is not None and by_bytes.sample(paths[1], now=1) is not None
    assert by_bytes.sample(paths[2], now=1) is None


# ---- the pipeline: a burst with and without encrypted output --------------------------

SCRIPT = P(6120, 4724, POWERSHELL)


def burst(recording, count: int, start: float, spread: float = 0.08):
    for i in range(count):
        recording.add(SCRIPT, "file_delete", start + i * spread, path=f"{DOCS}\\orig{i}.txt")


def outputs(home, recording, names_and_data, start: float):
    for i, (name, data) in enumerate(names_and_data):
        path = put(home, name, data)
        recording.add(SCRIPT, "file_create", start + i * 0.05, path=path)


def replay(tmp_path, recording, home=None, **options):
    folder = write_session(tmp_path / "s", recording, labels=False, session_id="s")
    sampler = sampler_for(home) if home else None
    return run_session(folder, sampler=sampler, **options)


def rules_of(result) -> list[str]:
    return sorted(a["rule_id"] for a in result.alerts)


def ransomware_recording(home, count=25):
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    outputs(home, recording, [(f"orig{i}.txt.locked", random_bytes()) for i in range(count)], start=1.0)
    burst(recording, count, start=4.0)
    return recording


def test_ransomware_burst_with_random_output_raises_r_t1486_002(tmp_path, home):
    result = replay(tmp_path, ransomware_recording(home), home)
    assert rules_of(result) == ["R-T1486-001", "R-T1486-002"]
    assert result.entropy_verdicts == {"high": 1}
    ransom_alert = next(a for a in result.alerts if a["rule_id"] == "R-T1486-002")
    burst_alert = next(a for a in result.alerts if a["rule_id"] == "R-T1486-001")
    assert ransom_alert["subject"]["pid"] == 6120 and ransom_alert["object"]["zone"] == "documents"
    assert set(burst_alert["evidence_event_ids"]) <= set(ransom_alert["evidence_event_ids"])
    assert ransom_alert["risk_score"] is None
    assert ransom_alert["alert_id"] != burst_alert["alert_id"]
    # Never suppressed: the burst alert is still there, and only alert_only.
    by_alert = {d["alert_id"]: d for d in result.decisions}
    burst_actions = [(a["action"], a["status"]) for a in by_alert[burst_alert["alert_id"]]["actions"]]
    assert burst_actions == [("alert_only", "executed")]
    assert by_alert[burst_alert["alert_id"]]["policy_rules"] == []
    ransom_decision = by_alert[ransom_alert["alert_id"]]
    assert ransom_decision["policy_rules"] == ["P3b-ransomware-entropy"]
    [action] = ransom_decision["actions"]
    assert (action["action"], action["status"], action["target"]["pid"]) == ("suspend", "pending", 6120)
    # It is a high-risk alert, so it gets a report even though risk_score is null.
    assert [r["alert_id"] for r in result.reports] == [ransom_alert["alert_id"]]


def test_zip_extraction_burst_keeps_only_r_t1486_001(tmp_path, home):
    """The batch 2 benign zip session: many deletes, and the files left behind are ordinary
    documents. Text, and JPEGs with a real header, are not encrypted-looking."""
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    files = [(f"doc{i}.txt", TEXT) for i in range(10)]
    files += [(f"photo{i}.jpg", JPEG_HEADER + random_bytes()) for i in range(10)]
    files += [(f"sheet{i}.docx", b"PK\x03\x04" + random_bytes()) for i in range(10)]
    outputs(home, recording, files, start=1.0)
    burst(recording, 1019, start=4.0, spread=0.01)
    result = replay(tmp_path, recording, home)
    assert rules_of(result) == ["R-T1486-001"]
    assert result.entropy_verdicts == {"low": 1}
    [decision] = result.decisions
    assert [(a["action"], a["status"]) for a in decision["actions"]] == [("alert_only", "executed")]
    assert result.reports == []


def test_replay_without_a_reader_is_unknown_and_changes_nothing(tmp_path, home):
    result = replay(tmp_path, ransomware_recording(home), home=None)
    assert rules_of(result) == ["R-T1486-001"]
    assert result.entropy_reader is False
    assert result.entropy_verdicts == {"unknown": 1}
    assert [(a["action"], a["status"]) for d in result.decisions for a in d["actions"]] == [("alert_only", "executed")]


def test_recorded_windows_paths_do_not_exist_here_so_the_verdict_is_unknown(tmp_path, home):
    recording = ransomware_recording(home)
    folder = write_session(tmp_path / "s", recording, labels=False, session_id="s")
    result = run_session(folder, sampler=FileSampler())  # no translation: C:\... is not a path in WSL
    if os.name != "nt":
        assert rules_of(result) == ["R-T1486-001"]
        assert result.entropy_verdicts == {"unknown": 1}


def test_files_that_are_gone_by_replay_time_stay_unknown(tmp_path, home):
    recording = ransomware_recording(home)
    for f in (home / "Documents" / "ThreatPulseTest").glob("*.locked"):
        f.unlink()
    result = replay(tmp_path, recording, home)
    assert rules_of(result) == ["R-T1486-001"]
    assert result.entropy_verdicts == {"unknown": 1}
    assert result.entropy_refused["vanished"] == 25


def test_wiper_that_only_deletes_stays_unknown(tmp_path, home):
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    burst(recording, 25, start=1.0)
    result = replay(tmp_path, recording, home)
    assert rules_of(result) == ["R-T1486-001"] and result.entropy_verdicts == {"unknown": 1}


def test_escalates_later_when_the_encrypted_files_arrive_after_the_burst(tmp_path, home):
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    burst(recording, 12, start=1.0)  # the burst alert fires here, with nothing written yet
    outputs(home, recording, [(f"n{i}.locked", random_bytes()) for i in range(8)], start=3.0)
    recording.add(SCRIPT, "file_write", 8.0, path=f"{DOCS}\\n0.locked")  # a later write: judged again
    result = replay(tmp_path, recording, home)
    assert rules_of(result) == ["R-T1486-001", "R-T1486-002"]
    assert next(a for a in result.alerts if a["rule_id"] == "R-T1486-002")["ts"] > \
        next(a for a in result.alerts if a["rule_id"] == "R-T1486-001")["ts"]


def test_escalates_once_per_process(tmp_path, home):
    recording = ransomware_recording(home)
    for i in range(5):
        recording.add(SCRIPT, "file_write", 10.0 + 3 * i, path=f"{DOCS}\\orig{i}.txt.locked")
    result = replay(tmp_path, recording, home)
    assert rules_of(result).count("R-T1486-002") == 1


def test_format_mimicking_output_stays_at_r_t1486_001(tmp_path, home):
    """Documented limit: output that starts with a real header and has a matching extension
    looks like an ordinary compressed file."""
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    outputs(home, recording, [(f"f{i}.docx", b"PK\x03\x04" + random_bytes()) for i in range(10)], start=1.0)
    burst(recording, 12, start=4.0)
    assert rules_of(replay(tmp_path, recording, home)) == ["R-T1486-001"]


def test_low_entropy_output_stays_at_r_t1486_001(tmp_path, home):
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    outputs(home, recording, [(f"f{i}.locked", TEXT) for i in range(10)], start=1.0)
    burst(recording, 12, start=4.0)
    assert rules_of(replay(tmp_path, recording, home)) == ["R-T1486-001"]


def test_budget_exhausted_is_unknown_not_low(tmp_path, home):
    recording = ransomware_recording(home)
    folder = write_session(tmp_path / "s", recording, labels=False, session_id="s")
    sampler = sampler_for(home, files_per_window=2)
    result = run_session(folder, sampler=sampler)
    assert rules_of(result) == ["R-T1486-001"] and result.entropy_verdicts == {"unknown": 1}


def test_writes_outside_the_documents_zone_are_not_read(tmp_path, home):
    (home / "AppData" / "Local" / "Temp").mkdir(parents=True)
    recording = Recording()
    recording.start(SCRIPT, 0.5)
    for i in range(10):
        path = home / "AppData" / "Local" / "Temp" / f"t{i}.bin"
        path.write_bytes(random_bytes())
        recording.add(SCRIPT, "file_create", 1.0 + i * 0.05, path=f"C:\\Users\\lab\\AppData\\Local\\Temp\\t{i}.bin")
    burst(recording, 12, start=4.0)
    result = replay(tmp_path, recording, home)
    assert rules_of(result) == ["R-T1486-001"] and result.entropy_verdicts == {"unknown": 1}


# ---- the policy rule and the report rule ------------------------------------------------


def ransom_alert(**kwargs):
    return make_alert(rule_id="R-T1486-002", zone="documents", **kwargs)


def test_p3b_suspends_on_r_t1486_002_without_a_risk_score():
    decision = run(ransom_alert(risk=None))
    assert decision["policy_rules"] == ["P3b-ransomware-entropy"]
    [action] = decision["actions"]
    assert (action["action"], action["status"], action["target"]["pid"]) == ("suspend", "pending", 4321)


def test_p3b_does_not_fire_for_the_burst_alone_or_other_zones():
    assert run(make_alert(rule_id="R-T1486-001", zone="documents", risk=None))["policy_rules"] == []
    assert run(make_alert(rule_id="R-T1486-001", zone="documents", risk=0.1))["policy_rules"] == []
    assert "P3b-ransomware-entropy" not in run(make_alert(rule_id="R-T1486-002", zone="persistence"))["policy_rules"]
    assert run(make_alert(rule_id="R-T1486-002", zone="none"))["policy_rules"] == []


def test_p3b_respects_never_suspend():
    decision = run(ransom_alert(image=SVCHOST, microsoft_root=True))
    [action] = decision["actions"]
    assert action["action"] == "suspend" and action["status"] == "skipped"
    assert "never-suspend" in action["reason"]


def test_p3b_and_p3_give_one_suspend():
    decision = run(ransom_alert(risk=0.95))
    assert decision["policy_rules"] == ["P3-ransomware", "P3b-ransomware-entropy"]
    assert [a["action"] for a in decision["actions"]] == ["suspend"]


def test_the_policy_file_has_p3b_and_it_loads():
    assert "P3b-ransomware-entropy" in [rule.id for rule in POLICY.rules]
    rule = next(r for r in POLICY.rules if r.id == "P3b-ransomware-entropy")
    assert rule.when == {"zone": "documents", "rule_id": "R-T1486-002"} and rule.actions == ("suspend",)


def test_policy_rejects_a_bad_rule_id_condition():
    from policy.loader import PolicyError, parse_rules
    with pytest.raises(PolicyError):
        parse_rules([{"id": "P9-x", "when": {"rule_id": "not a rule"}, "actions": ["suspend"]}])


def test_r_t1486_002_is_high_risk_and_001_is_not():
    assert is_high_risk(make_alert(rule_id="R-T1486-002", zone="documents", risk=None))
    assert not is_high_risk(make_alert(rule_id="R-T1486-001", zone="documents", risk=None))
    assert is_high_risk(make_alert(rule_id="R-T1486-001", zone="documents", risk=0.9))


def test_the_dashboard_and_the_report_rule_agree():
    text = (ROOT / "frontend" / "src" / "components.tsx").read_text(encoding="utf-8")
    assert ransom.RANSOM_RULE_ID in text
    assert ransom.RANSOM_RULE_ID in (ROOT / "backend" / "rag" / "prompt.py").read_text(encoding="utf-8")
    assert ransom.RANSOM_RULE_ID in (ROOT / "rules" / "policy.yaml").read_text(encoding="utf-8")


# ---- structure ----------------------------------------------------------------------------


def imports_of(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


@pytest.mark.parametrize("name", ["entropy.py", "ransom.py"])
def test_detection_modules_import_nothing_from_policy_or_backend_and_run_nothing(name):
    modules = imports_of(ROOT / "detection" / name)
    assert not {m for m in modules if m.split(".")[0] in ("policy", "backend", "subprocess", "ctypes", "socket", "urllib")}
    source = (ROOT / "detection" / name).read_text(encoding="utf-8")
    for word in ("os.system", "os.popen", "exec(", "eval(", "importlib", "pickle", "os.startfile"):
        assert word not in source


def test_policy_never_imports_detection_entropy_or_backend():
    for path in (ROOT / "policy").glob("*.py"):
        assert not {m for m in imports_of(path) if m.split(".")[0] == "backend"}
