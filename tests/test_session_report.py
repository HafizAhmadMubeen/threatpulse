"""The session report tool must never change what it reads."""

import hashlib
import json
from pathlib import Path

import pytest

from detection import session_report
from tests.event_builder import POWERSHELL, RUN_KEY, P, Recording
from tests.test_features import write_session


def make_session(folder: Path, label: str = "malicious") -> Path:
    recording = Recording()
    writer = P(200, 1, "C:\\Windows\\System32\\reg.exe")
    recording.add(writer, "registry_set", 1.0, registry_key=RUN_KEY)
    recording.add(P(300, 1, POWERSHELL, "powershell.exe"), "process_start", 2.0)
    write_session(folder, recording, labels=True, label=label, test_id="T1547.001-1")
    return folder


def digest(folder: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        hasher.update(path.name.encode() + path.read_bytes())
    return hasher.hexdigest()


def test_it_reads_a_session_with_a_bom_and_reports_the_rule(tmp_path, capsys):
    folder = make_session(tmp_path / "in" / "s1")
    assert (folder / "session.json").read_bytes().startswith(b"\xef\xbb\xbf")
    assert session_report.main([str(folder), "--out", str(tmp_path / "out")]) == 0
    assert "R-T1547-001 x1" in capsys.readouterr().out
    report = json.loads((tmp_path / "out" / "session_report.json").read_text(encoding="utf-8"))
    assert report[0]["alerts"][0]["rule_id"] == "R-T1547-001"
    assert report[0]["label"] == "malicious"


def test_it_changes_nothing_in_the_session_folder(tmp_path):
    folder = make_session(tmp_path / "in" / "s1")
    before = digest(folder)
    session_report.main([str(folder), "--out", str(tmp_path / "out")])
    assert digest(folder) == before


@pytest.mark.parametrize("where", ["inside", "same"])
def test_it_refuses_to_write_into_the_data_it_reads(tmp_path, where):
    folder = make_session(tmp_path / "in" / "s1")
    out = folder / "report" if where == "inside" else folder
    with pytest.raises(SystemExit):
        session_report.main([str(folder), "--out", str(out)])
    assert not (folder / "report").exists() and not (folder / "session_report.json").exists()


def test_a_benign_alert_is_a_false_positive_and_says_which_part(tmp_path):
    folder = make_session(tmp_path / "in" / "s1", label="benign")
    result = session_report.report_session(folder)
    assert result["label"] == "benign"
    assert [row["rule_id"] for row in result["alerts"]] == ["R-T1547-001"]


def test_part_comes_from_the_v2_column_when_there_is_one():
    assert session_report.part_of({"label": "malicious"}) == "malicious"
    assert session_report.part_of({"label": "benign", "part": "harness"}) == "harness"
    assert session_report.part_of({"label": "malicious", "part": "test"}) == "test"
    assert session_report.part_of(None) == "unlabelled"
