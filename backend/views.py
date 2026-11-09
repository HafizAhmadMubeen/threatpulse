"""Builds API responses from the data files and the review store."""

import copy
from collections import Counter

from backend.data import DataSet
from backend.store import ReviewStore

LAYERS = ("signature", "heuristic", "fim", "rule", "ml")
ZONES = ("documents", "persistence", "lsass", "network", "none")
STATUSES = ("pending", "executed", "failed", "skipped", "awaiting_approval", "approved", "rejected")


def with_reviews(decision: dict, store: ReviewStore) -> dict:
    """A review only fills in an action still waiting. Once the policy engine has moved
    an action on, the file is the record of what happened."""
    reviews = store.decision_reviews(decision["decision_id"])
    if not reviews:
        return decision
    merged = copy.deepcopy(decision)
    for action in merged["actions"]:
        if action["status"] == "awaiting_approval" and action["action"] in reviews:
            action.update(reviews[action["action"]])
    return merged


def decisions(data: DataSet, store: ReviewStore) -> list[dict]:
    return [with_reviews(decision, store) for decision in data.decisions]


def fim_change(event: dict, data: DataSet, store: ReviewStore) -> dict:
    alert_id = next(
        (a["alert_id"] for a in data.alerts if event["event_id"] in a["evidence_event_ids"]),
        None,
    )
    item = {
        "event_id": event["event_id"],
        "ts": event["ts"],
        "path": event["target"]["path"],
        "registry_key": event["target"]["registry_key"],
        "change": event["target"]["change"],
        "alert_id": alert_id,
        "status": "pending",
    }
    review = store.fim_review(event["event_id"])
    if review:
        item.update(status="approved", **review)
    return item


def fim_changes(data: DataSet, store: ReviewStore) -> list[dict]:
    return [
        fim_change(event, data, store)
        for event in data.events
        if event["event_type"] == "fim_change"
    ]


def count_by(values: list[str], keys: tuple[str, ...]) -> dict[str, int]:
    counts = Counter(values)
    return {key: counts[key] for key in keys}


def stats(data: DataSet, store: ReviewStore) -> dict:
    actions = [action for decision in decisions(data, store) for action in decision["actions"]]
    action_statuses = count_by([action["status"] for action in actions], STATUSES)
    reported = {report["alert_id"] for report in data.reports}
    sent_to_llm = {
        event_id
        for alert in data.alerts
        if alert["alert_id"] in reported
        for event_id in alert["evidence_event_ids"]
    }
    known_events = {event["event_id"] for event in data.events}
    return {
        "events_total": len(data.events),
        "alerts_total": len(data.alerts),
        "alerts_not_scored": sum(alert["risk_score"] is None for alert in data.alerts),
        "alerts_by_layer": count_by([alert["layer"] for alert in data.alerts], LAYERS),
        "alerts_by_zone": count_by([alert["object"]["zone"] for alert in data.alerts], ZONES),
        "actions_by_status": action_statuses,
        "pending_approvals": action_statuses["awaiting_approval"],
        "fim_changes_pending": sum(
            change["status"] == "pending" for change in fim_changes(data, store)
        ),
        "reports_total": len(data.reports),
        "events_filtered_before_llm": len(known_events - sent_to_llm),
        "skipped_records": dict(data.skipped),
    }
