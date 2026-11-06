"""scan_file: hash list, YARA and static PE heuristics.

Files are telemetry, so anything can be in them. A file is read once into memory, so all
three layers judge the same bytes, even if it changes on disk during the scan. A file that
vanished or is locked is normal on a live system, and gives no alerts rather than a crash.
"""

import hashlib
import logging
import os
import stat
from dataclasses import dataclass

import yara

from detection import hashes, pe_heuristics, yara_rules
from detection.alerts import file_scan_alert

log = logging.getLogger(__name__)

MAX_SCAN_BYTES = pe_heuristics.MAX_PE_BYTES
CHUNK_BYTES = 1024 * 1024
HEURISTIC_ALERT_SCORE = 0.50


@dataclass
class FileContent:
    sha256: str
    size: int
    data: bytes | None  # None when over the limit: hashed, but not scanned further


def read_file(path: str) -> FileContent:
    """Raises OSError. Anything but a regular file is refused first, because reading a FIFO
    or a device could hang forever."""
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise OSError(f"not a regular file: {path!r}")
    hasher = hashlib.sha256()
    kept = bytearray()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            hasher.update(chunk)
            size += len(chunk)
            if size <= MAX_SCAN_BYTES:
                kept += chunk
            else:
                kept.clear()
    data = bytes(kept) if size <= MAX_SCAN_BYTES else None
    return FileContent(hasher.hexdigest(), size, data)


def signature_reasons(known_name: str | None, yara_matches: list[dict]) -> dict[str, list[str]]:
    """One alert per signature name, so a file matched two ways gives one delete request.
    The reasons keep every method that matched."""
    reasons: dict[str, list[str]] = {}
    if known_name:
        reasons.setdefault(known_name, []).append("SHA-256 match")
    for found in yara_matches:
        reasons.setdefault(found["signature"], []).append(f"YARA rule {found['rule']}")
    return reasons


def build_alerts(
    path: str, sha256: str, signatures: dict[str, list[str]], result: pe_heuristics.HeuristicResult | None
) -> list[dict]:
    alerts = [
        file_scan_alert(
            "signature", f"SIG-{name}", [], path, sha256, {"score": None, "reasons": reasons}
        )
        for name, reasons in signatures.items()
    ]
    if result is not None and result.score >= HEURISTIC_ALERT_SCORE:
        alerts.append(
            file_scan_alert(
                "heuristic",
                f"HEUR-{result.rule_name}",
                result.technique_ids,
                path,
                sha256,
                {"score": result.score, "reasons": result.reasons},
            )
        )
    return alerts


def scan_details(path: str) -> dict:
    """Every layer's result, for the VM checks. scan_file returns only the alerts."""
    details: dict = {"path": path, "alerts": []}
    try:
        content = read_file(path)
    except OSError as error:
        log.warning("cannot read %r: %s", path, type(error).__name__)
        return details | {"error": type(error).__name__}

    known_name = hashes.lookup(content.sha256)
    details |= {
        "sha256": content.sha256,
        "size": content.size,
        "oversized": content.data is None,
        "hash_match": known_name,
        "yara_matches": [],
        "yara_error": None,
        "heuristics": None,
    }
    result = None
    if content.data is None:
        log.warning("%r is over the %d byte limit: hash check only", path, MAX_SCAN_BYTES)
    else:
        try:
            details["yara_matches"] = yara_rules.match(content.data)
        except yara.Error as error:
            log.warning("YARA failed on %r: %s", path, type(error).__name__)
            details["yara_error"] = type(error).__name__
        result = pe_heuristics.analyze_pe(content.data)
        details["heuristics"] = {
            "status": result.status,
            "score": result.score,
            "reasons": result.reasons,
        }

    signatures = signature_reasons(known_name, details["yara_matches"])
    details["alerts"] = build_alerts(path, content.sha256, signatures, result)
    return details


def scan_file(path: str) -> list[dict]:
    """Alerts for one file (ROADMAP.md Section 2). They have no known process, so the
    pipeline fills in subject, evidence and risk_score when an event triggered the scan."""
    return scan_details(path)["alerts"]
