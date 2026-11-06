"""Tests against the real pinned ATT&CK data and the real local model.

Run on their own with: uv run pytest -m attack_data -v
They skip when the data is missing, so read the skip count: a skip here proves nothing.
"""

import json
import socket

import pytest

from backend.rag import attack_data, index
from backend.rag.attack_data import load_attack_data
from backend.rag.prompt import build_messages, is_high_risk
from backend.rag.validator import check_technique_id
from contracts import validate_samples as vs
from detection.pe_heuristics import CHECKS

MODEL_FILE = attack_data.MODEL_DIR / "onnx" / "model.onnx"
ready = attack_data.STIX_PATH.is_file() and MODEL_FILE.is_file() and index.CHROMA_DIR.is_dir()

pytestmark = [
    pytest.mark.attack_data,
    pytest.mark.skipif(
        not ready, reason="run: uv run python -m backend.rag.fetch && uv run python -m backend.rag.index"
    ),
]

# These queries are the requirement. If one fails, report it. Don't reword it.
TOP_K = 5
QUERIES = [
    ("process reads LSASS memory", "T1003.001"),
    ("Run key persistence", "T1547.001"),
    ("ransomware encryption", "T1486"),
    ("download a tool with PowerShell", "T1105"),
]


@pytest.fixture(scope="module")
def data():
    return load_attack_data()


def test_gate_2_10_every_active_technique_is_indexed(data):
    collection, _ = index.open_index()
    assert len(data.techniques) == 706
    assert collection.count() == len(data.techniques)


def test_the_index_records_the_pin():
    collection, _ = index.open_index()
    assert collection.metadata["stix_sha256"] == attack_data.STIX_SHA256
    assert collection.metadata["attack_version"] == "20.1"


def test_revoked_and_deprecated_techniques_are_not_indexed(data):
    collection, _ = index.open_index()
    stored = set(collection.get(include=[])["ids"])
    assert stored == set(data.techniques)
    assert not stored & set(data.replaced_by)
    assert not stored & data.deprecated


@pytest.mark.parametrize(("query", "expected"), QUERIES)
def test_retrieval_finds_the_technique(query, expected):
    found = [result.id for result in index.search(query, k=TOP_K)]
    assert expected in found, f"{query!r} returned {found}"


def test_t1562_001_is_rejected_and_reports_t1685(data):
    check = check_technique_id("T1562.001", data)
    assert check.status == "revoked"
    assert check.replacement == "T1685"
    assert data.techniques["T1685"].name == "Disable or Modify Tools"


def test_every_revoked_id_ends_at_an_active_technique_or_at_nothing(data):
    assert len(data.replaced_by) == 149
    for replacement in data.replaced_by.values():
        assert replacement is None or replacement in data.techniques


def test_deprecated_count(data):
    assert len(data.deprecated) == 12


def test_every_active_technique_has_detection_text(data):
    assert all(t.detection_strategy for t in data.techniques.values())


def test_the_lsass_document_has_its_real_detection_text(data):
    document = data.techniques["T1003.001"].document
    assert "OS Credential Dumping: LSASS Memory" in document
    assert "Detection:" in document
    assert "lsass.exe" in document
    assert "(Citation:" not in document


def test_every_technique_id_this_project_uses_is_active(data):
    used = {t for alert in vs.load_json(vs.SAMPLES_DIR / "alerts.json") for t in alert["technique_ids"]}
    used |= {t["id"] for r in vs.load_json(vs.SAMPLES_DIR / "reports.json") for t in r["techniques"]}
    used |= {check.technique for check in CHECKS.values() if check.technique}
    assert used
    for technique_id in sorted(used):
        assert check_technique_id(technique_id, data).valid, technique_id


def test_sample_report_technique_names_are_real(data):
    for report in vs.load_json(vs.SAMPLES_DIR / "reports.json"):
        for technique in report["techniques"]:
            assert data.techniques[technique["id"]].name.endswith(technique["name"])


def test_windows_only_is_the_default_and_can_be_switched_off(data):
    query = "Linux kernel module rootkit"
    default = index.search(query, k=20)
    assert all(data.techniques[result.id].windows for result in default)
    everything = index.search(query, k=20, windows_only=False)
    assert any(not data.techniques[result.id].windows for result in everything)


def test_search_works_with_the_network_blocked(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("search tried to use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    assert index.search("process reads LSASS memory", k=3)


def test_the_loaded_model_uses_only_the_cpu():
    _, model = index.open_index()
    assert model.model.get_providers() == ["CPUExecutionProvider"]


def test_a_real_prompt_for_the_injection_sample(data):
    alerts = vs.load_json(vs.SAMPLES_DIR / "alerts.json")
    events = vs.load_jsonl(vs.SAMPLES_DIR / "events.jsonl")
    alert = alerts[8]
    assert is_high_risk(alert)
    reference = index.reference_for_alert(alert, data)
    assert reference[0]["id"] == "T1071.001"
    assert len(reference) >= 2
    system, user = build_messages(alert, events, reference)
    assert "ignore all previous instructions" not in system["content"]
    block = user["content"].split("<telemetry>")[1].split("</telemetry>")[0]
    assert "ignore all previous instructions" in json.loads(block)["alert"]["subject"]["image"]
    assert "T1071.001" in user["content"].split("<attack_reference>")[1]
