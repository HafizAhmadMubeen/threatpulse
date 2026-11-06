"""write_report: STUB. No LLM call, no network, no provider (PHASES.md step 3.7 is later).

*** STUB ***  It fills a fixed template from the alert and its evidence events, so the
dashboard has something to show for a high-risk alert. The text starts with "STUB report"
so nobody reads it as an analysis. The real write_report will use
`backend.rag.prompt.build_messages`, which wraps the telemetry as data.

The alert and event text here is attacker-influenced. It is copied as plain text, cut to
a length, and never interpreted.
"""


from functools import lru_cache

from backend.rag.attack_data import AttackData, load_attack_data
from backend.rag.validator import check_technique_id

IS_STUB = True
MAX_TIMELINE = 12
MAX_TEXT = 160


@lru_cache(maxsize=1)
def attack_data() -> AttackData | None:
    try:
        return load_attack_data()
    except Exception:  # the pinned data is not downloaded: the report says it is unchecked
        return None


def short(text: object) -> str:
    text = str(text)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "..."


def program(path: str) -> str:
    return short(path.replace("\\", "/").rsplit("/", 1)[-1] or "unknown")


def techniques_for(alert: dict) -> tuple[list[dict], bool]:
    """Technique IDs are checked against the ATT&CK data. An ID that is not there is
    dropped, a revoked one is replaced by its successor. Without the data nothing can be
    checked, so the report says so."""
    data, found, checked = attack_data(), [], True
    for technique_id in alert["technique_ids"]:
        evidence = short(f"Rule {alert['rule_id']} matched {len(alert['evidence_event_ids'])} event(s).")
        if data is None:
            found.append({"id": technique_id, "name": "unchecked (ATT&CK data not loaded)", "evidence": evidence})
            checked = False
            continue
        result = check_technique_id(technique_id, data)
        if result.valid:
            found.append({"id": result.id, "name": result.name, "evidence": evidence})
        elif result.status == "revoked" and result.replacement and result.name:
            found.append({"id": result.replacement, "name": result.name, "evidence": evidence})
    return found, checked


def timeline_for(events: list[dict]) -> list[str]:
    lines = []
    for event in sorted(events, key=lambda e: e["ts"])[:MAX_TIMELINE]:
        target = event["target"]
        what = target.get("registry_key") or target.get("path") or target.get("dest_ip") or ""
        lines.append(short(f"{event['ts'][11:19]} {program(event['process']['image'])} {event['event_type']} {what}".strip()))
    return lines or ["No evidence events (the alert names no process)."]


def write_report(alert: dict, events: list[dict]) -> dict:
    """`events` are the alert's evidence events, never a raw event stream."""
    techniques, validated = techniques_for(alert)
    subject = alert["subject"]
    who = "an unknown process" if subject["pid"] == 0 else program(subject["image"])
    return {
        "report_id": "r-" + alert["alert_id"][2:],
        "alert_id": alert["alert_id"],
        "summary": short(
            f"STUB report, no LLM call. Rule {alert['rule_id']} ({alert['layer']} layer) fired on "
            f"{alert['event_type']} by {who}. Read the evidence events for details."
        ),
        "techniques": techniques,
        "timeline": timeline_for(events),
        "validated": validated,
    }
