"""execute(decision, alert): run what `decide` planned (PHASES.md step 3.2).

Generation: 4th, access control. The policy engine decides, this module acts, and the two
never meet any other way: nothing from the backend or an LLM reaches this code, and the
Decision it is given is checked against its schema first.

What it does with a Decision:
- an automatic action in status `pending` is run, and ends as `executed`, `failed` or
  `skipped`, with a reason on the last two
- `request_kill` and `request_delete` are run only when an analyst has approved them:
  status `approved` with `reviewed_by` and `reviewed_at`. `awaiting_approval` and
  `rejected` are never touched
- every other status is left exactly as it is, so running execute twice acts once
- outside the lab VM nothing runs: automatic actions become `skipped` with "not in lab VM"
  and approved requests stay approved

The input is not changed. The returned Decision is validated again before it leaves.
The Windows work is in actions_windows.py; undo() reverses it from the journal.
"""

import copy
from datetime import datetime, timezone
from functools import lru_cache

from contracts.validate_samples import load_validators
from policy import actions_windows as win
from policy.engine import alert_validator, default_policy

REQUEST_ACTIONS = ("request_kill", "request_delete")
HANDLERS = {
    "suspend": win.do_suspend,
    "block_network": win.do_block_network,
    "restore": win.do_restore,
    "request_kill": win.do_kill,
    "request_delete": win.do_delete,
}


class ExecuteError(ValueError):
    """The Decision or the Alert is malformed, or the result would be. A bug in the caller."""


@lru_cache(maxsize=1)
def decision_validator():
    return load_validators()["decision"]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def settle(act: dict, status: str, *, reason: str | None = None, at: str | None = None) -> None:
    act["status"] = status
    act["executed_at"] = at
    if reason:
        act["reason"] = reason
    else:
        act.pop("reason", None)


def is_approved(act: dict) -> bool:
    return bool(act.get("reviewed_by")) and bool(act.get("reviewed_at"))


def note(result: dict, text: str) -> None:
    result["attributes"].setdefault("enforcement_notes", []).append(text)


def execute(decision: dict, alert: dict, *, api=None, policy=None, layout=None, now=None) -> dict:
    """Run the actions of `decision` that are ready, and return the updated Decision.

    `alert` is the Alert the decision was made for: `restore` and `request_delete` take
    the item from its `object`, because the Decision names only processes. The optional
    arguments are for tests: a fake `api`, another `layout`, a fixed `now()`.
    """
    api = api or win.WindowsApi()
    layout = layout or win.Layout()
    policy = policy or default_policy()
    clock = now or utc_now

    for what, validator, item in (("decision", decision_validator(), decision),
                                  ("alert", alert_validator(), alert)):
        problems = [e.message for e in validator.iter_errors(item)]
        if problems:
            raise ExecuteError(f"the {what} does not match its schema: {problems[0]}")
    if decision["alert_id"] != alert["alert_id"]:
        raise ExecuteError(f"decision {decision['decision_id']} is for {decision['alert_id']}, not {alert['alert_id']}")

    result = copy.deepcopy(decision)
    outside = win.lab_guard(api, layout)
    journal = win.Journal(api, layout)

    for index, act in enumerate(result["actions"]):
        name, is_request = act["action"], act["action"] in REQUEST_ACTIONS
        if is_request and act["status"] != "approved" or not is_request and act["status"] != "pending":
            continue  # nothing to run: already settled, or waiting for / refused by an analyst
        if is_request and not is_approved(act):
            note(result, f"{name} #{index}: approved without reviewed_by and reviewed_at, so it was not run")
            continue
        if outside:
            if is_request:  # a request has no skipped status: leave the approval for the VM
                note(result, f"{name} #{index}: not run. {outside}")
            else:
                settle(act, "skipped", reason=outside)
            continue
        handler = HANDLERS.get(name)
        if handler is None:
            settle(act, "failed", reason=f"no handler for {name}", at=None)
            continue

        ctx = win.Ctx(api, policy, layout, alert, decision["decision_id"], index, clock(), journal)
        try:
            handler(ctx, act)
        except win.Refused as stop:
            if ctx.begun:
                ctx.finish("failed")
            settle(act, "failed" if is_request else "skipped", reason=str(stop))
        except win.ActionFailed as problem:
            if ctx.begun:
                ctx.finish("failed")
            settle(act, "failed", reason=str(problem), at=ctx.now)
        except Exception as error:  # one broken action must not stop the others
            if ctx.begun:
                ctx.finish("failed")
            settle(act, "failed", reason=f"unexpected {type(error).__name__}: {error}", at=ctx.now)
        else:
            ctx.finish("done")
            settle(act, "executed", at=ctx.now)

    problems = [e.message for e in decision_validator().iter_errors(result)]
    if problems:
        raise ExecuteError(f"execute produced an invalid decision: {problems[0]}")
    return result


def undo(decision_id: str | None = None, *, api=None, policy=None, layout=None, now=None) -> list[dict]:
    """Reverse what execute did, newest first. With a decision ID only that decision's
    actions, otherwise every action still active in the journal.

    Returns one row per action: {"id", "action", "result": undone | skipped | failed,
    "detail"}. A terminated process can't be brought back, so a kill is `skipped`.
    Refuses outside the lab VM."""
    api = api or win.WindowsApi()
    layout = layout or win.Layout()
    policy = policy or default_policy()
    clock = now or utc_now
    outside = win.lab_guard(api, layout)
    if outside:
        raise win.Refused(outside)

    journal = win.Journal(api, layout)
    rows = []
    for entry in reversed(journal.active(decision_id)):
        ctx = win.Ctx(api, policy, layout, {}, entry["decision_id"], entry["index"], clock(), journal)
        row = {"id": entry["id"], "action": entry["action"]}
        try:
            row["detail"] = win.undo_entry(ctx, entry)
            ctx.finish("undone")
            row["result"] = "undone"
        except win.Refused as stop:
            row.update(result="skipped", detail=str(stop))
        except Exception as error:
            row.update(result="failed", detail=f"{type(error).__name__}: {error}")
        rows.append(row)
    return rows


def enable_controlled_folder_access(*, api=None, policy=None, layout=None, now=None) -> str:
    """Turn Controlled Folder Access on in the lab VM. Returns the previous mode, which
    `undo("setup")` puts back. Setup only: execute() never calls this, and it must not be
    done before a recording snapshot. Raises Refused outside the lab VM."""
    return win.set_up_controlled_folder_access(
        api or win.WindowsApi(), layout or win.Layout(), policy or default_policy(), (now or utc_now)())
