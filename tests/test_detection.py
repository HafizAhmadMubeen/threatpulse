"""scan_file tests. Test files are built here at runtime and hold no EICAR content."""

import hashlib
import json
import os
import random
import re
from pathlib import Path

import pytest
import yara

import detection
from detection import __main__ as cli
from detection import alerts as alert_module
from detection import hashes, pe_heuristics, scanner, yara_rules
from detection.pe_heuristics import CHECKS, HIGH_ENTROPY, analyze_pe, entropy
from contracts import validate_samples as vs
from tests.pe_builder import CODE, DATA, NORMAL_IMPORTS, Section, build_pe

REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_SCHEMA = vs.load_validators()["alert"]
MARKER = b"THREATPULSE-TEST-MARKER"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

RANDOM_BYTES = random.Random(1234).randbytes(0x4000)  # high entropy
FILLER = b"\xcc" * 0x400  # low entropy, and does nothing


def plain_pe(**options) -> bytes:
    return build_pe([Section(b".text", FILLER), Section(b".rdata", FILLER, flags=DATA)], **options)


def upx_like_pe() -> bytes:
    """The layout UPX produces: an empty section to unpack into, then compressed data."""
    unpacked_rva = 0x1000
    packed_rva = unpacked_rva + 0x10000
    return build_pe(
        [
            Section(b"UPX0", virtual_size=0x10000),
            Section(b"UPX1", RANDOM_BYTES),
        ],
        entry_point=packed_rva + 0x100,
        imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"]},
    )


def kinds(data: bytes) -> list[str]:
    return analyze_pe(data).kinds


def write(tmp_path: Path, data: bytes, name: str = "sample.bin") -> str:
    target = tmp_path / name
    target.write_bytes(data)
    return str(target)


def assert_valid(alert: dict) -> None:
    assert [error.message for error in ALERT_SCHEMA.iter_errors(alert)] == []


def assert_no_process(alert: dict) -> None:
    assert alert["subject"] == {
        "pid": 0, "image": "unknown", "signed": False, "signer": None,
        "trusted_path": False, "ancestors": [],
    }
    assert alert["risk_score"] is None
    assert alert["event_type"] == "file_scan"
    assert alert["evidence_event_ids"] == []
    assert alert["object"]["zone"] == "none"


# Hash list


def test_marker_hash_is_listed():
    assert hashes.lookup(hashlib.sha256(MARKER).hexdigest()) == "TEST-MARKER"


def test_eicar_hash_is_listed():
    assert hashes.lookup(EICAR_SHA256) == "EICAR"


def test_an_unknown_hash_is_not_listed():
    assert hashes.lookup(hashlib.sha256(b"clean").hexdigest()) is None


@pytest.mark.parametrize(
    "entries",
    [
        [{"sha256": "ABC", "name": "BAD"}],
        [{"sha256": "A" * 64, "name": "UPPERCASE-HASH"}],
        [{"sha256": "a" * 64, "name": "lower case"}],
        [{"sha256": "a" * 64, "name": "ONE"}, {"sha256": "a" * 64, "name": "TWO"}],
    ],
)
def test_a_bad_hash_list_stops_startup(tmp_path, entries):
    path = tmp_path / "known_bad.json"
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    with pytest.raises(ValueError):
        hashes.parse_hash_list(path)


# YARA


def test_marker_rule_matches():
    assert yara_rules.match(MARKER) == [
        {"rule": "ThreatPulse_Test_Marker", "signature": "TEST-MARKER"}
    ]


def test_marker_rule_ignores_a_marker_inside_a_larger_file():
    assert yara_rules.match(b"x" * 64 + MARKER) == []
    assert yara_rules.match(MARKER + b"x" * 2048) == []


def test_clean_data_matches_no_rule():
    assert yara_rules.match(b"just some ordinary text") == []


def test_rules_ship_for_both_signatures():
    names = {rule.identifier: rule.meta["signature"] for rule in yara_rules.compiled_rules()}
    assert names == {"EICAR_Test_File": "EICAR", "ThreatPulse_Test_Marker": "TEST-MARKER"}


def test_rules_compile_once(monkeypatch):
    calls = []
    real = yara.compile
    monkeypatch.setattr(yara, "compile", lambda **kw: calls.append(kw) or real(**kw))
    yara_rules.compiled_rules.cache_clear()
    try:
        for _ in range(3):
            yara_rules.match(MARKER)
        assert len(calls) == 1
        assert calls[0]["includes"] is False
    finally:
        yara_rules.compiled_rules.cache_clear()


def test_a_rule_cannot_include_another_file(tmp_path):
    (tmp_path / "bad.yar").write_text('include "other.yar"\n', encoding="utf-8")
    with pytest.raises(yara.Error):
        yara_rules.compile_rules(tmp_path)


def test_a_broken_rule_stops_startup(tmp_path):
    (tmp_path / "bad.yar").write_text("rule {", encoding="utf-8")
    with pytest.raises(yara.Error):
        yara_rules.compile_rules(tmp_path)


def test_a_rule_without_a_signature_name_stops_startup(tmp_path):
    (tmp_path / "bad.yar").write_text("rule NoMeta { condition: true }", encoding="utf-8")
    with pytest.raises(ValueError, match="NoMeta"):
        yara_rules.compile_rules(tmp_path)


def test_an_empty_rules_folder_stops_startup(tmp_path):
    with pytest.raises(ValueError):
        yara_rules.compile_rules(tmp_path)


def test_rule_locations_cannot_be_redirected():
    for module in (hashes, yara_rules, scanner):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert not re.search(r"environ|getenv|yara\.load", source)
    assert hashes.HASH_LIST_PATH == REPO_ROOT / "rules" / "hashes" / "known_bad.json"
    assert yara_rules.RULES_DIR == REPO_ROOT / "rules" / "yara"


def test_no_repo_file_holds_the_eicar_file():
    """Hashes every candidate instead of comparing, so this test holds no EICAR content."""
    for folder in ("rules", "detection", "tests", "contracts", "backend"):
        for path in (REPO_ROOT / folder).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or ".state" in path.parts:
                continue
            data = path.read_bytes()
            start = data.find(b"X5O!")
            while start != -1:
                assert hashlib.sha256(data[start:start + 68]).hexdigest() != EICAR_SHA256, path
                start = data.find(b"X5O!", start + 1)


# PE heuristics


def test_entropy_values():
    assert entropy(b"") == 0
    assert entropy(b"\x00" * 1000) == 0
    assert entropy(bytes(range(256))) == pytest.approx(8)
    assert entropy(RANDOM_BYTES) > HIGH_ENTROPY


def test_a_plain_pe_scores_zero():
    result = analyze_pe(plain_pe())
    assert result.status == "parsed"
    assert result.score == 0
    assert result.reasons == []
    assert result.rule_name is None


def test_a_upx_layout_scores_higher_than_a_plain_file():
    packed = analyze_pe(upx_like_pe())
    assert packed.score > analyze_pe(plain_pe()).score
    assert packed.score >= scanner.HEURISTIC_ALERT_SCORE
    assert packed.rule_name == "UPX-PACKED"
    assert packed.technique_ids == ["T1027.002", "T1027"]


def test_every_finding_on_a_upx_layout_has_a_readable_reason():
    reasons = analyze_pe(upx_like_pe()).reasons
    assert "Packer section name: UPX0" in reasons
    assert "Packer section name: UPX1" in reasons
    assert "Executable section UPX0 has 0 raw bytes but 65536 virtual bytes" in reasons
    assert "Entry point is outside the first code section (UPX0)" in reasons
    assert "Very few imports: 3" in reasons
    assert any(reason.startswith("High entropy in executable section UPX1: ") for reason in reasons)


def test_repeats_of_one_kind_count_once():
    data = build_pe([Section(b"UPX0", FILLER), Section(b"UPX1", FILLER), Section(b"UPX2", FILLER)])
    result = analyze_pe(data)
    assert len([kind for kind, _ in result.findings if kind == "upx"]) == 3
    assert result.score == CHECKS["upx"].weight


def test_the_score_is_capped():
    result = pe_heuristics.HeuristicResult("parsed")
    for kind in CHECKS:
        result.add(kind, "reason")
    assert result.score == 1.0


@pytest.mark.parametrize("name", [b".aspack", b".themida", b".vmp0", b".MPRESS1"])
def test_other_packer_section_names(name):
    assert kinds(build_pe([Section(name, FILLER)])) == ["packer"]


def test_high_entropy_counts_only_in_executable_sections():
    """Compressed resources are normal. Compressed code isn't."""
    data = build_pe([Section(b".text", FILLER), Section(b".rsrc", RANDOM_BYTES, flags=DATA)])
    assert "entropy" not in kinds(data)
    assert "entropy" in kinds(build_pe([Section(b".text", RANDOM_BYTES)]))


def test_entropy_needs_enough_data():
    assert "entropy" not in kinds(build_pe([Section(b".text", RANDOM_BYTES[:512])]))


def test_size_mismatch_in_a_code_section():
    data = build_pe([Section(b".text", FILLER, virtual_size=0x10000)])
    assert kinds(data) == ["size_mismatch"]


def test_uninitialised_data_is_not_a_size_mismatch():
    data = build_pe([Section(b".text", FILLER), Section(b".bss", virtual_size=0x10000, flags=DATA)])
    assert kinds(data) == []


def test_entry_point_outside_the_first_code_section():
    sections = [Section(b".text", FILLER), Section(b".other", FILLER, flags=CODE)]
    assert "entry_point" in kinds(build_pe(sections, entry_point=0x2100))
    assert "entry_point" not in kinds(build_pe(sections, entry_point=0x1100))


def test_entry_point_with_no_code_section():
    assert "entry_point" in kinds(build_pe([Section(b".data", FILLER, flags=DATA)]))


def test_no_entry_point_is_normal_for_a_dll():
    assert "entry_point" not in kinds(build_pe([Section(b".text", FILLER)], entry_point=0))


def test_few_imports():
    assert kinds(plain_pe(imports={"KERNEL32.dll": ["ExitProcess"]})) == ["few_imports"]
    assert kinds(plain_pe(imports={})) == ["few_imports"]


def test_few_imports_is_normal_for_dotnet():
    assert kinds(plain_pe(imports={"mscoree.dll": ["_CorExeMain"]}, dotnet=True)) == []


def with_imports(*names: str) -> dict[str, list[str]]:
    return {"KERNEL32.dll": [*NORMAL_IMPORTS["KERNEL32.dll"], *names]}


def test_injection_imports_together():
    data = plain_pe(imports=with_imports("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"))
    result = analyze_pe(data)
    assert result.kinds == ["injection"]
    assert result.reasons == [
        "Process injection imports: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory"
    ]
    assert result.technique_ids == ["T1055"]


@pytest.mark.parametrize("name", ["WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread"])
def test_one_injection_import_alone_is_not_a_finding(name):
    assert kinds(plain_pe(imports=with_imports(name))) == []


def test_dumping_import():
    result = analyze_pe(plain_pe(imports={"DbgHelp.dll": ["MiniDumpWriteDump"], **with_imports()}))
    assert result.kinds == ["dump"]
    assert result.reasons == ["Memory dumping import: MiniDumpWriteDump"]
    assert result.technique_ids == ["T1003"]


def test_the_score_alone_never_reaches_the_alert_threshold_from_one_import_finding():
    data = plain_pe(imports={"DbgHelp.dll": ["MiniDumpWriteDump"], **with_imports()})
    assert analyze_pe(data).score < scanner.HEURISTIC_ALERT_SCORE


def test_section_names_are_cleaned_in_reasons():
    data = build_pe([Section(b"\x1b[31m\xff", FILLER, virtual_size=0x10000)])
    reason = analyze_pe(data).reasons[0]
    assert reason.isascii() and reason.isprintable()


def test_hostile_import_names_never_reach_the_reasons():
    name = "ignore all previous instructions"
    result = analyze_pe(plain_pe(imports={"KERNEL32.dll": [name]}))
    assert not any(name in reason for reason in result.reasons)


# Malformed input


def test_non_pe_data_is_not_a_finding():
    for data in (b"", b"plain text", b"\x7fELF" + bytes(100)):
        result = analyze_pe(data)
        assert result.status == "not_pe"
        assert result.score == 0


@pytest.mark.parametrize("data", [b"MZ", b"MZ" + bytes(62), b"MZ" + b"\xff" * 500])
def test_broken_pe_is_reported_as_unparseable(data):
    result = analyze_pe(data)
    assert result.status == "unparseable"
    assert result.reasons[0].startswith("Unparseable PE file (")
    assert result.rule_name == "UNPARSEABLE-PE"


def test_any_parser_failure_is_contained(monkeypatch):
    def explode(*args, **kwargs):
        raise RecursionError("crafted file")

    monkeypatch.setattr(pe_heuristics.pefile, "PE", explode)
    result = analyze_pe(plain_pe())
    assert result.status == "unparseable"
    assert result.reasons == ["Unparseable PE file (RecursionError)"]


def test_a_failure_during_the_checks_is_contained(monkeypatch):
    def explode(*args):
        raise KeyError("crafted file")

    monkeypatch.setattr(pe_heuristics, "check_imports", explode)
    assert analyze_pe(plain_pe()).status == "unparseable"


@pytest.mark.parametrize("build", [plain_pe, upx_like_pe])
def test_truncation_at_any_length_is_safe(build):
    data = build()
    for length in range(0, len(data), 61):
        assert analyze_pe(data[:length]).status in ("parsed", "not_pe", "unparseable")


def test_random_corruption_is_safe():
    rng = random.Random(42)
    original = upx_like_pe()
    for _ in range(300):
        data = bytearray(original)
        for _ in range(rng.randint(1, 40)):
            data[rng.randrange(0, 0x400)] = rng.randrange(256)
        result = analyze_pe(bytes(data))
        assert result.status in ("parsed", "not_pe", "unparseable")
        assert 0 <= result.score <= 1


def test_section_count_is_capped():
    sections = [Section(b"UPX0", FILLER[:32], flags=DATA) for _ in range(pe_heuristics.MAX_SECTIONS + 4)]
    findings = analyze_pe(build_pe(sections, imports=NORMAL_IMPORTS)).findings
    assert len([kind for kind, _ in findings if kind == "upx"]) == pe_heuristics.MAX_SECTIONS


def test_a_pe_over_the_limit_is_not_parsed(monkeypatch):
    monkeypatch.setattr(pe_heuristics, "MAX_PE_BYTES", 100)
    assert analyze_pe(plain_pe()).status == "too_large"


def test_the_size_limit_is_64_mib():
    assert pe_heuristics.MAX_PE_BYTES == 64 * 1024 * 1024
    assert scanner.MAX_SCAN_BYTES == 64 * 1024 * 1024


# scan_file


def test_marker_gives_one_alert_listing_both_methods(tmp_path):
    alerts = detection.scan_file(write(tmp_path, MARKER))
    assert len(alerts) == 1
    alert = alerts[0]
    assert_valid(alert)
    assert_no_process(alert)
    assert alert["layer"] == "signature"
    assert alert["rule_id"] == "SIG-TEST-MARKER"
    assert alert["object"]["file_sha256"] == hashlib.sha256(MARKER).hexdigest()
    assert alert["static_analysis"] == {
        "score": None,
        "reasons": ["SHA-256 match", "YARA rule ThreatPulse_Test_Marker"],
    }


def test_marker_variant_is_caught_by_yara_alone(tmp_path):
    """A changed byte defeats the hash, which is why YARA is here too."""
    alerts = detection.scan_file(write(tmp_path, MARKER + b"\r\n"))
    assert [a["rule_id"] for a in alerts] == ["SIG-TEST-MARKER"]
    assert alerts[0]["static_analysis"]["reasons"] == ["YARA rule ThreatPulse_Test_Marker"]


def test_clean_file_gives_no_alerts(tmp_path):
    assert detection.scan_file(write(tmp_path, b"nothing to see here\n")) == []


def test_empty_file_gives_no_alerts(tmp_path):
    assert detection.scan_file(write(tmp_path, b"")) == []


def test_clean_pe_gives_no_alerts(tmp_path):
    assert detection.scan_file(write(tmp_path, plain_pe())) == []


def test_packed_pe_gives_a_heuristic_alert(tmp_path):
    path = write(tmp_path, upx_like_pe())
    alerts = detection.scan_file(path)
    assert len(alerts) == 1
    alert = alerts[0]
    assert_valid(alert)
    assert_no_process(alert)
    assert alert["layer"] == "heuristic"
    assert alert["rule_id"] == "HEUR-UPX-PACKED"
    assert alert["technique_ids"] == ["T1027.002", "T1027"]
    assert alert["object"]["path"] == path
    assert alert["static_analysis"]["score"] >= 0.5
    assert "Packer section name: UPX0" in alert["static_analysis"]["reasons"]


def test_a_static_score_never_becomes_a_risk_score(tmp_path):
    alert = detection.scan_file(write(tmp_path, upx_like_pe()))[0]
    assert alert["static_analysis"]["score"] > 0
    assert alert["risk_score"] is None


def test_scores_below_the_threshold_give_no_alert_but_show_in_the_details(tmp_path):
    data = build_pe([Section(b".text", FILLER, virtual_size=0x10000)])
    path = write(tmp_path, data)
    assert detection.scan_file(path) == []
    assert detection.scan_details(path)["heuristics"]["score"] == CHECKS["size_mismatch"].weight


def test_exactly_at_the_threshold_gives_an_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "HEURISTIC_ALERT_SCORE", CHECKS["size_mismatch"].weight)
    data = build_pe([Section(b".text", FILLER, virtual_size=0x10000)])
    assert len(detection.scan_file(write(tmp_path, data))) == 1


def test_the_alert_threshold_is_050():
    assert scanner.HEURISTIC_ALERT_SCORE == 0.50


def test_unparseable_pe_gives_a_valid_alert(tmp_path):
    alerts = detection.scan_file(write(tmp_path, b"MZ" + b"\xff" * 500))
    assert len(alerts) == 1
    assert_valid(alerts[0])
    assert alerts[0]["rule_id"] == "HEUR-UNPARSEABLE-PE"
    assert alerts[0]["technique_ids"] == []
    assert alerts[0]["static_analysis"]["reasons"][0].startswith("Unparseable PE file")


def test_every_heuristic_rule_gives_a_valid_alert(tmp_path):
    for index, kind in enumerate(CHECKS):
        result = pe_heuristics.HeuristicResult("parsed")
        result.add(kind, "reason")
        result.add("unparseable", "reason")
        alert = scanner.build_alerts(str(tmp_path / str(index)), "a" * 64, {}, result)[0]
        assert_valid(alert)


def test_signature_and_heuristic_alerts_together(tmp_path, monkeypatch):
    data = upx_like_pe()
    monkeypatch.setattr(hashes, "known_bad", lambda: {hashlib.sha256(data).hexdigest(): "KNOWN"})
    alerts = detection.scan_file(write(tmp_path, data))
    assert [a["rule_id"] for a in alerts] == ["SIG-KNOWN", "HEUR-UPX-PACKED"]
    assert alerts[0]["static_analysis"] == {"score": None, "reasons": ["SHA-256 match"]}
    for alert in alerts:
        assert_valid(alert)


def test_different_signatures_give_separate_alerts():
    reasons = scanner.signature_reasons("ONE", [{"rule": "Two", "signature": "TWO"}])
    assert reasons == {"ONE": ["SHA-256 match"], "TWO": ["YARA rule Two"]}


def test_alert_ids_are_unique_and_use_the_event_id_format(tmp_path):
    path = write(tmp_path, MARKER)
    ids = [detection.scan_file(path)[0]["alert_id"] for _ in range(5)]
    assert len(set(ids)) == 5
    assert all(re.fullmatch(r"a-\d{8}T\d{6}-\d{6,}", value) for value in ids)
    assert ids[0].startswith(f"a-{alert_module.RUN_START}-")


def test_an_invalid_alert_is_a_bug_and_raises():
    with pytest.raises(ValueError, match="invalid alert"):
        alert_module.file_scan_alert("nonsense", "X", [], "p", "a" * 64, {"score": None, "reasons": ["r"]})


def test_oversized_file_gets_the_hash_check_only(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_SCAN_BYTES", 16)
    monkeypatch.setattr(scanner, "CHUNK_BYTES", 8)
    padded = MARKER + b"x" * 100
    monkeypatch.setattr(hashes, "known_bad", lambda: {hashlib.sha256(padded).hexdigest(): "KNOWN"})
    path = write(tmp_path, padded)
    details = detection.scan_details(path)
    assert details["oversized"] is True
    assert details["heuristics"] is None
    assert details["yara_matches"] == []
    assert [a["rule_id"] for a in details["alerts"]] == ["SIG-KNOWN"]


def test_a_file_exactly_at_the_limit_is_scanned(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_SCAN_BYTES", len(MARKER))
    monkeypatch.setattr(scanner, "CHUNK_BYTES", 8)
    details = detection.scan_details(write(tmp_path, MARKER))
    assert details["oversized"] is False
    assert details["yara_matches"]


def test_a_yara_failure_keeps_the_other_layers(tmp_path, monkeypatch):
    def timeout(data):
        raise yara.TimeoutError("too slow")

    monkeypatch.setattr(yara_rules, "match", timeout)
    details = detection.scan_details(write(tmp_path, MARKER))
    assert details["yara_error"] == "TimeoutError"
    assert details["alerts"][0]["static_analysis"]["reasons"] == ["SHA-256 match"]


def test_a_missing_file_gives_no_alerts(tmp_path):
    path = str(tmp_path / "gone.bin")
    assert detection.scan_file(path) == []
    assert detection.scan_details(path)["error"] == "FileNotFoundError"


def test_a_directory_gives_no_alerts(tmp_path):
    assert detection.scan_file(str(tmp_path)) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFO support")
def test_a_fifo_is_refused_without_hanging(tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path)
    assert detection.scan_file(str(path)) == []


def test_all_layers_judge_the_same_bytes(tmp_path, monkeypatch):
    """A file swapped during the scan can't show one layer clean bytes and another bad ones."""
    path = write(tmp_path, b"clean")
    real = scanner.read_file

    def read_then_swap(target):
        content = real(target)
        Path(target).write_bytes(MARKER)
        return content

    monkeypatch.setattr(scanner, "read_file", read_then_swap)
    assert detection.scan_file(path) == []


def test_cli_prints_every_layer(tmp_path, capsys):
    assert cli.main([write(tmp_path, MARKER)]) == 0
    result = json.loads(capsys.readouterr().out)[0]
    assert result["hash_match"] == "TEST-MARKER"
    assert result["yara_matches"][0]["rule"] == "ThreatPulse_Test_Marker"
    assert result["heuristics"]["status"] == "not_pe"
    assert len(result["alerts"]) == 1


def test_detection_never_runs_or_loads_a_file():
    forbidden = re.compile(
        r"subprocess|ctypes|os\.system|os\.startfile|os\.exec|LoadLibrary|importlib|\bexec\(|\beval\("
    )
    for path in Path(detection.__file__).parent.glob("*.py"):
        assert not forbidden.search(path.read_text(encoding="utf-8")), path


def test_pefile_gets_bytes_and_never_a_path(monkeypatch, tmp_path):
    calls = []
    real = pe_heuristics.pefile.PE

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(pe_heuristics.pefile, "PE", spy)
    detection.scan_file(write(tmp_path, plain_pe()))
    assert calls[0][0] == ()
    assert isinstance(calls[0][1]["data"], bytes)
    assert "name" not in calls[0][1]
