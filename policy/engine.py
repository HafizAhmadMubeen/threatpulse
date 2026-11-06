"""The ABAC policy engine: decide(alert, context) -> Decision (PHASES.md step 3.1).

Generation: 4th, access control (NIST SP 800-162). A rule's `when` is a test on
attributes of the subject (the process), the object (the zone) and the environment
(lsass_mode, what is already suspended). Everything that decides an outcome is an
argument, so the same inputs always give the same Decision.

Two things this module deliberately never does:
- It never reads `static_analysis`. A static score says what a file looks like, not what
  a process did, so it can't trigger enforcement (PLANNING.md Section 5.2).
- It never imports from `backend/`. The LLM and its reports must have no path into
  enforcement (CLAUDE.md design rule 1). Tests check both.

decide() only plans. Every automatic action leaves with status `pending` and
`executed_at` null, and policy.execute (a later step) runs it and updates the status.
"""

import re
from datetime import datetime, timezone
from functools import lru_cache

from contracts.validate_samples import load_validators
from policy import paths
from policy.loader import Policy, Rule, load_policy

TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3})?Z$")
REQUEST_ACTIONS = ("request_kill", "request_delete")
# Actions that stop or cut off a program, so they must never reach a critical one.
GUARDED_ACTIONS = ("suspend", "block_network", "request_kill")


class AlertError(ValueError):
    """The alert does not match the Alert schema. A bug upstream, so it is raised."""


class ContextError(ValueError):
    """The context is malformed. A bug in the caller, so it is raised, not guessed at."""


@lru_cache(maxsize=1)
def default_policy() -> Policy:
    return load_policy()


@lru_cache(maxsize=1)
def alert_validator():
    return load_validators()["alert"]


# ---- context ----------------------------------------------------------------------


def is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def read_candidates(raw: object) -> list[dict]:
    """The writer's tree: processes a FIM change may have come from."""
    if not isinstance(raw, list):
        raise ContextError("writer_tree: expected a list")
    candidates = []
    for item in raw:
        if not (isinstance(item, dict) and isinstance(item.get("pid"), int) and not isinstance(item["pid"], bool)
                and item["pid"] > 0 and isinstance(item.get("image"), str) and item["image"]
                and isinstance(item.get("alive"), bool)):
            raise ContextError("writer_tree: each entry needs pid, image and alive")
        score = item.get("risk_score")
        if score is not None and not (is_number(score) and 0 <= score <= 1):
            raise ContextError("writer_tree: risk_score must be 0 to 1, or null")
        root = item.get("microsoft_root")
        if root is not None and not isinstance(root, bool):
            raise ContextError("writer_tree: microsoft_root must be true or false")
        candidates.append({"pid": item["pid"], "image": item["image"], "alive": item["alive"],
                           "risk_score": score, "microsoft_root": root})
    return candidates


def read_context(alert: dict, context: dict | None) -> dict:
    context = {} if context is None else context
    if not isinstance(context, dict):
        raise ContextError("context must be a dict")
    now = context.get("now", alert["ts"])
    if not (isinstance(now, str) and TIMESTAMP.match(now)):
        raise ContextError("now: expected a UTC timestamp like 2026-11-05T09:30:00.000Z")
    suspended = context.get("suspended_pids", [])
    if not (isinstance(suspended, (list, tuple, set, frozenset))
            and all(isinstance(pid, int) and not isinstance(pid, bool) for pid in suspended)):
        raise ContextError("suspended_pids: expected a collection of pids")
    fim = context.get("fim")
    if fim is not None:
        ok = (isinstance(fim, dict)
              and (fim.get("differs_from_baseline") is None or isinstance(fim["differs_from_baseline"], bool))
              and is_number(fim.get("settled_seconds")) and fim["settled_seconds"] >= 0)
        if not ok:
            raise ContextError("fim: expected {differs_from_baseline: true/false/null, settled_seconds: >= 0}")
    return {
        "now": now,
        "suspended": frozenset(suspended),
        "fim": fim,
        "tree": read_candidates(context.get("writer_tree", [])),
    }


# ---- attributes -------------------------------------------------------------------


def on_list(entries, image: str, pid: int, microsoft_root: bool | None, *, unknown_counts: bool):
    """The first entry this process matches, or None.

    Match is by full path, and also by signature when the entry asks for one. A process
    whose microsoft_root is unknown (an old recording) matches only if `unknown_counts`.
    That is true for the never-suspend list, where a wrong "no" could freeze Windows, and
    false for the LSASS allowlist, where a wrong "yes" would hide an attack.
    """
    for entry in entries:
        if entry.system:
            if pid == 4 and image.lower() == "system":
                return entry, None
        elif paths.matches(image, entry.path):
            if entry.signature == "none" or microsoft_root is True:
                return entry, None
            if microsoft_root is None and unknown_counts:
                return entry, "microsoft_root unknown"
            # Explicitly false: the file at this path is not Microsoft's. Not exempt.
    return None


def protection(policy: Policy, image: str, pid: int, microsoft_root: bool | None) -> str | None:
    found = on_list(policy.never_suspend, image, pid, microsoft_root, unknown_counts=True)
    if found is None:
        return None
    entry, note = found
    reason = f"never-suspend list: {entry.path}"
    return f"{reason} ({note})" if note else reason


def fim_state(fim: dict | None, debounce: float) -> str:
    if fim is None or fim["differs_from_baseline"] is None:
        return "unknown"
    if not fim["differs_from_baseline"]:
        return "matches_baseline"
    return "differs_settled" if fim["settled_seconds"] >= debounce else "differs_unsettled"


def risk_basis(alert: dict, tree: list[dict]) -> float | None:
    """The score `risk_score_gte` tests. It is the alert's own score. An alert with no
    process, such as a FIM change, has a null score, so then it is the best score in the
    writer's tree. Null never matches anything."""
    if alert["subject"]["pid"] > 0:
        return alert["risk_score"]
    scores = [c["risk_score"] for c in tree if c["risk_score"] is not None]
    return max(scores) if scores else None


def matches_when(rule: Rule, facts: dict, policy: Policy) -> bool:
    for key, wanted in rule.when.items():
        if key == "risk_score_gte":
            threshold = policy.thresholds[wanted] if isinstance(wanted, str) else wanted
            score = facts["risk"]
            if score is None or score < threshold:  # null is "not scored", never a match
                return False
        elif facts[key] != wanted:
            return False
    return True


# ---- actions ----------------------------------------------------------------------


def action(name: str, status: str, *, now: str | None = None, reason: str | None = None,
           target: dict | None = None) -> dict:
    entry = {"action": name, "automatic": name not in REQUEST_ACTIONS, "status": status,
             "executed_at": now if status == "executed" else None}
    if reason:
        entry["reason"] = reason
    if target:
        entry["target"] = target
    return entry


def pick_target(alert: dict, ctx: dict, policy: Policy, minimum: float | None) -> tuple[dict | None, str | None]:
    """Who a process action is aimed at, or why there is nobody.

    The alert's own process when it has one. Otherwise the highest-scoring live process
    in the writer's tree, skipping any that the never-suspend list protects."""
    subject = alert["subject"]
    if subject["pid"] > 0:
        return {"pid": subject["pid"], "image": subject["image"],
                "microsoft_root": subject.get("microsoft_root")}, None
    if not ctx["tree"]:
        return None, "the alert names no process and no writer tree was given"
    live = [c for c in ctx["tree"] if c["alive"]]
    if not live:
        return None, "every process in the writer's tree has exited"
    scored = [c for c in live if c["risk_score"] is not None and (minimum is None or c["risk_score"] >= minimum)]
    if not scored:
        return None, "no live process in the writer's tree is scored high enough"
    scored.sort(key=lambda c: (-c["risk_score"], c["pid"]))
    refused = []
    for candidate in scored:
        why = protection(policy, candidate["image"], candidate["pid"], candidate["microsoft_root"])
        if why is None:
            return candidate, None
        refused.append(why)
    return None, refused[0]


def plan(rule: Rule, name: str, alert: dict, ctx: dict, facts: dict, policy: Policy,
         notes: list[str]) -> dict | None:
    """One planned action for one rule, or None for a request that can't be made."""
    now = ctx["now"]
    if name == "alert_only":
        return action("alert_only", "executed", now=now)

    if name == "restore":
        state = facts["fim_state"]
        if state == "differs_settled":
            return action("restore", "pending")
        if state == "differs_unsettled":
            return action("restore", "skipped",
                          reason=f"change has not settled for {policy.fim_debounce_seconds:g} s yet; decide again later")
        return action("restore", "skipped", reason="baseline state unknown, so nothing is restored")

    if name == "request_delete":
        if alert["object"]["path"] is None:
            notes.append("request_delete: the alert has no file path")
            return None
        return action("request_delete", "awaiting_approval")

    # suspend, block_network, request_kill: aimed at a process, and guarded.
    minimum = None
    if isinstance(rule.when.get("risk_score_gte"), (str, float, int)):
        wanted = rule.when["risk_score_gte"]
        minimum = policy.thresholds[wanted] if isinstance(wanted, str) else wanted
    target, why_not = pick_target(alert, ctx, policy, minimum)
    if target is None:
        if name in REQUEST_ACTIONS:
            notes.append(f"{name}: {why_not}")
            return None
        return action(name, "skipped", reason=why_not)
    shown = {"pid": target["pid"], "image": target["image"]}
    refusal = protection(policy, target["image"], target["pid"], target.get("microsoft_root"))
    if refusal:
        if name in REQUEST_ACTIONS:  # the schema has no skipped status for a request
            notes.append(f"{name}: {refusal}")
            return None
        return action(name, "skipped", reason=refusal, target=shown)
    if name == "request_kill":
        return action(name, "awaiting_approval", target=shown)
    return action(name, "pending", target=shown)


# ---- decide -----------------------------------------------------------------------


def decide(alert: dict, context: dict | None = None, policy: Policy | None = None) -> dict:
    """Plan the response to one Alert. See rules/policy.yaml for the rules.

    `context` is what the engine can't see on its own:
      now            UTC timestamp of the decision (default: the alert's ts)
      suspended_pids pids already suspended (for P5)
      fim            {"differs_from_baseline": bool | None, "settled_seconds": float}
                     taken after the debounce, from the FIM baseline
      writer_tree    processes a FIM change may have come from, each
                     {"pid", "image", "alive", "risk_score", "microsoft_root"}
    """
    policy = policy or default_policy()
    errors = [e.message for e in alert_validator().iter_errors(alert)]
    if errors:
        raise AlertError(f"alert does not match the schema: {errors[0]}")
    ctx = read_context(alert, context)

    subject, obj = alert["subject"], alert["object"]
    root = subject.get("microsoft_root")
    allowlisted = on_list(policy.lsass_allowlist, subject["image"], subject["pid"], root,
                          unknown_counts=False) is not None
    state = fim_state(ctx["fim"], policy.fim_debounce_seconds)
    facts = {
        "event_type": alert["event_type"],
        "zone": obj["zone"],
        "layer": alert["layer"],
        "access_includes": None,  # set per rule below
        "in_lsass_allowlist": allowlisted,
        "change_approved": state == "matches_baseline",
        "already_suspended": subject["pid"] in ctx["suspended"],
        "risk": risk_basis(alert, ctx["tree"]),
        "fim_state": state,
    }

    fired, planned, notes = [], [], []
    for rule in policy.rules:
        wanted_right = rule.when.get("access_includes")
        facts["access_includes"] = wanted_right if wanted_right in obj["access"] else None
        if not matches_when(rule, facts, policy):
            continue
        fired.append(rule.id)
        names = rule.actions
        if rule.id.startswith("P1-") and policy.lsass_mode == "learning":
            names = ("alert_only",)  # learning mode: look, don't touch
        for name in names:
            entry = plan(rule, name, alert, ctx, facts, policy, notes)
            if entry is not None:
                planned.append(entry)

    actions, seen = [], set()
    for entry in planned:  # the same action on the same process is one action
        key = (entry["action"], entry.get("target", {}).get("pid"))
        if key not in seen:
            seen.add(key)
            actions.append(entry)
    if any(a["action"] != "alert_only" for a in actions):
        actions = [a for a in actions if a["action"] != "alert_only"]
    if not actions:
        actions = [action("alert_only", "executed", now=ctx["now"])]

    attributes = {
        "zone": obj["zone"],
        "signed": subject["signed"],
        "trusted_path": subject["trusted_path"],
        "risk_score": alert["risk_score"],
        "lsass_mode": policy.lsass_mode,
        "already_suspended": facts["already_suspended"],
        "change_approved": facts["change_approved"],
        "fim_state": state,
    }
    if root is not None:
        attributes["microsoft_root"] = root
    if notes:
        attributes["not_requested"] = sorted(set(notes))

    return {
        "decision_id": "d-" + alert["alert_id"][2:],
        "alert_id": alert["alert_id"],
        "ts": ctx["now"],
        "policy_rules": fired,
        "actions": actions,
        "attributes": attributes,
    }
