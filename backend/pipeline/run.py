"""Replay one recorded session through the whole pipeline.

Order of work for each event, in time order:
  1. update what we remember (processes, writers, FIM state)
  2. match_rules (stateful), and a hash-list check of a started process's own SHA-256
  3. score_process for the alert's process tree  (None without a model in triage/models/)
  4. decide(alert, context)                      (PLANS only: automatic actions stay pending)
  5. write_report, only for a high-risk alert    (STUB: no LLM)

A persistence-zone decision waits until the change has settled (the FIM debounce), and is
then made with what was known at that moment, never with later events.
"""

import heapq
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.pipeline import report_stub
from backend.pipeline.state import FimState, ProcessTable, Proc, WriteIndex, item_of, when
from backend.rag.prompt import is_high_risk
from contracts.validate_samples import load_validators
from detection import alerts as alert_module
from detection import hashes
from detection.behaviour import RuleEngine, sort_events
from detection.entropy import FileSampler
from detection.ransom import BURST_RULE_ID, HIGH, RANSOM_RULE_ID, UNKNOWN, RansomJudge
from detection.scanner import scan_file
from detection.timeline import format_ts, read_jsonl
from policy import decide
from policy.engine import default_policy
from triage.features import events_of_tree_containing
from triage.score import score_process

log = logging.getLogger(__name__)
RUN_START = re.compile(r"^e-([0-9]{8}T[0-9]{6})-")


class PipelineError(ValueError):
    pass


@dataclass
class SessionResult:
    session: dict
    alerts: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    reports: list[dict] = field(default_factory=list)
    events: int = 0
    fim_events: int = 0
    skipped_events: int = 0
    rejected_by_rules: int = 0
    microsoft_root_events: int = 0
    # Per ransomware burst (R-T1486-001), the final entropy verdict: high, low or unknown.
    # Without a file reader (every replay outside the lab VM) all of them are unknown.
    entropy_reader: bool = False
    entropy_verdicts: dict = field(default_factory=dict)
    entropy_refused: dict = field(default_factory=dict)


def read_session(folder: Path) -> dict:
    try:
        session = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        session = {}
    if not isinstance(session, dict):
        session = {}
    session.setdefault("session_id", folder.name)
    return session


def run_start_of(events: list[dict]) -> str:
    for event in events:
        found = RUN_START.match(event["event_id"])
        if found:
            return found.group(1)
    raise PipelineError("no event ID with a run start")


def moment(seconds: float) -> str:
    return format_ts(datetime.fromtimestamp(seconds, tz=timezone.utc))


def hash_alert(engine: RuleEngine, event: dict, name: str) -> dict | None:
    """The process image's own SHA-256 is on the known-bad list. Replays have no file to
    scan, so this is the one first-generation check that works from the recording."""
    image, sha256 = event["process"]["image"], event["process"]["sha256"]
    alert = {
        "alert_id": alert_module.next_alert_id(),
        "ts": event["ts"],
        "layer": "signature",
        "rule_id": f"SIG-{name}",
        "technique_ids": [],
        "risk_score": None,
        "event_type": "process_start",
        "static_analysis": {"score": None, "reasons": ["SHA-256 of the process image matched the known-bad list"]},
        "subject": engine.subject_for(event),
        "object": {"zone": "none", "path": image, "registry_key": None, "access": [], "file_sha256": sha256},
        "evidence_event_ids": [event["event_id"]],
    }
    return alert_module.checked(alert)


def file_scan_alerts(engine: RuleEngine, event: dict) -> list[dict]:
    """--scan-files: run scan_file on the image if it exists on this machine."""
    image = event["process"]["image"]
    if not os.path.isfile(image):
        return []
    found = []
    for alert in scan_file(image):
        alert.update(
            alert_id=alert_module.next_alert_id(), ts=event["ts"], event_type="process_start",
            subject=engine.subject_for(event), evidence_event_ids=[event["event_id"]],
        )
        found.append(alert_module.checked(alert))
    return found


REJUDGE_SECONDS = 2.0  # how often a burst process is looked at again as it writes more


@dataclass
class Burst:
    """A process that tripped R-T1486-001, and whether it has been escalated yet."""
    alert: dict
    judged_at: float
    verdict: str = UNKNOWN
    escalated: bool = False


class Replay:
    def __init__(self, scorer, reporter, scan_files: bool, sampler: FileSampler | None = None):
        self.scorer, self.reporter, self.scan_files = scorer, reporter, scan_files
        # No sampler means no file is ever opened: replay stays deterministic.
        self.sampler = sampler
        self.judge = RansomJudge(sampler) if sampler else None
        self.bursts: dict[Proc, Burst] = {}
        self.validators = load_validators()
        self.policy = default_policy()
        self.engine = RuleEngine()
        self.table, self.writes, self.fim = ProcessTable(), WriteIndex(), FimState()
        self.queue: list[tuple[float, int, dict, Proc | None]] = []
        self.sequence = 0
        self.by_id: dict[str, dict] = {}
        self.hash_seen: set[str] = set()
        self.result: SessionResult | None = None

    # ---- one event ----------------------------------------------------------------

    def feed(self, event: dict) -> None:
        now = when(event)
        self.flush(now)
        self.by_id[event["event_id"]] = event
        proc = self.table.observe(event)
        self.writes.observe(event, proc)
        self.fim.observe(event)
        if self.judge:
            self.judge.observe(event)
        found = self.engine.process(event)
        found += self.signature_alerts(event)
        found += self.ransom_alerts(event, found, proc, now)
        for alert in found:
            self.take(alert, proc)

    def ransom_alerts(self, event: dict, found: list[dict], proc: Proc | None, now: float) -> list[dict]:
        """R-T1486-002: a delete burst (R-T1486-001) whose process wrote encrypted-looking
        files. Raised once per process, in addition to the burst alert, never instead of it.
        Without a sampler every burst stays unknown and this returns nothing."""
        if proc is None:
            return []
        for alert in found:
            if alert["rule_id"] == BURST_RULE_ID and proc not in self.bursts:
                self.bursts[proc] = Burst(alert=alert, judged_at=-float("inf"))
        burst = self.bursts.get(proc)
        if burst is None or burst.escalated or self.judge is None:
            return []
        stopping = event["event_type"] == "process_stop"
        if now - burst.judged_at < REJUDGE_SECONDS and not stopping:
            return []
        burst.judged_at = now
        verdict, evidence = self.judge.judge(proc.pid, now, settle=0.0 if stopping else 1.0)
        burst.verdict = verdict
        if verdict != HIGH:
            return []
        burst.escalated = True
        base = burst.alert
        escalated = {
            **base,
            "alert_id": alert_module.next_alert_id(),
            "ts": event["ts"],
            "rule_id": RANSOM_RULE_ID,
            "evidence_event_ids": list(dict.fromkeys([*base["evidence_event_ids"], *evidence[:20]])),
        }
        return [alert_module.checked(escalated)]

    def signature_alerts(self, event: dict) -> list[dict]:
        if event["event_type"] != "process_start":
            return []
        sha256 = event["process"]["sha256"]
        found = []
        name = hashes.lookup(sha256) if sha256 else None
        if name and sha256 not in self.hash_seen:
            self.hash_seen.add(sha256)
            found.append(hash_alert(self.engine, event, name))
        if self.scan_files:
            found += file_scan_alerts(self.engine, event)
        return found

    def take(self, alert: dict, proc: Proc | None) -> None:
        """Score the alert's process tree, then decide now or when the change has settled."""
        if alert["subject"]["pid"] > 0 and proc is not None:
            alert["risk_score"] = self.score(proc)
        self.result.alerts.append(alert)
        due = self.due(alert)
        self.sequence += 1
        heapq.heappush(self.queue, (due, self.sequence, alert, proc))
        if alert["object"]["zone"] != "persistence":
            self.flush(due)  # nothing to wait for

    # ---- scoring and context ------------------------------------------------------

    def score(self, proc: Proc) -> float | None:
        # The tree training saw: the process's own tree, not everything up to an unobserved root.
        value = self.scorer(events_of_tree_containing(proc.tree_events(), proc.pid))
        if value is not None and not (isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1):
            raise PipelineError(f"score_process returned {value!r}, not a number from 0 to 1 or None")
        return value

    def item(self, alert: dict) -> str:
        return item_of({"registry_key": alert["object"]["registry_key"], "path": alert["object"]["path"]})

    def due(self, alert: dict) -> float:
        """When to decide. A persistence change waits until it has been the same for the
        FIM debounce, so a quick remove-and-re-add is judged by where it ended up."""
        start = when(alert)
        if alert["object"]["zone"] != "persistence":
            return start
        debounce = self.policy.fim_debounce_seconds
        last = self.fim.last_change(self.item(alert))
        return max(start + debounce, (last + debounce) if last is not None else 0.0)

    def writer_tree(self, alert: dict, proc: Proc | None, now: float) -> list[dict]:
        writer = proc
        if alert["subject"]["pid"] == 0:
            writer = self.writes.writer_of(self.item(alert), when(alert))
        if writer is None:
            return []
        chain = writer.chain()
        score = self.score(writer)
        return [{"pid": p.pid, "image": p.image, "alive": p.alive, "risk_score": score,
                 "microsoft_root": p.microsoft_root} for p in chain]

    def context(self, alert: dict, proc: Proc | None, now: float) -> dict:
        context = {"now": moment(now), "suspended_pids": []}  # nothing is executed, so none are
        if alert["object"]["zone"] == "persistence":
            item = self.item(alert)
            fim = self.fim.context(item, now) if item else None
            if fim is not None:
                context["fim"] = fim
            context["writer_tree"] = self.writer_tree(alert, proc, now)
        return context

    # ---- decisions and reports ----------------------------------------------------

    def flush(self, now: float) -> None:
        while self.queue and self.queue[0][0] <= now:
            due, _, alert, proc = heapq.heappop(self.queue)
            later = self.due(alert)
            if later > due:  # the item changed again: wait for it to settle
                self.sequence += 1
                heapq.heappush(self.queue, (later, self.sequence, alert, proc))
                continue
            self.finish(alert, proc, due)

    def finish(self, alert: dict, proc: Proc | None, now: float) -> None:
        decision = decide(alert, self.context(alert, proc, now))
        self.result.decisions.append(decision)
        # The report is written after the decision and is never read by it.
        if is_high_risk(alert):
            evidence = [self.by_id[i] for i in alert["evidence_event_ids"] if i in self.by_id]
            report = self.reporter(alert, evidence)
            errors = [e.message for e in self.validators["report"].iter_errors(report)]
            if errors:
                raise PipelineError(f"report for {alert['alert_id']} is invalid: {errors[0]}")
            self.result.reports.append(report)


def run_session(folder: Path, *, scorer=score_process, reporter=report_stub.write_report,
                scan_files: bool = False, sampler: FileSampler | None = None) -> SessionResult:
    """Replays one session folder (events.jsonl and fim.jsonl). Reads only.

    `sampler` lets the ransomware check read the newly written document files. It is for
    the lab VM, where those files exist. Without it every burst verdict is unknown."""
    validator = load_validators()["event"]
    agent, _ = read_jsonl(folder / "events.jsonl")
    fim, _ = read_jsonl(folder / "fim.jsonl")
    events = [e for e in (*agent, *fim) if validator.is_valid(e)]
    if not events:
        raise PipelineError(f"{folder}: no usable events")

    result = SessionResult(session=read_session(folder))
    result.events, result.fim_events = len(agent), len(fim)
    result.skipped_events = len(agent) + len(fim) - len(events)
    result.microsoft_root_events = sum(1 for e in events if "microsoft_root" in e["process"])
    replay = Replay(scorer, reporter, scan_files, sampler)
    replay.result = result

    # Alert IDs carry the recording's run start: the same every replay, and different for
    # every recording, which matters because analyst reviews are keyed on these IDs.
    alert_module.start_run(run_start_of([e for e in events if e["source"] != "fim"] or events))
    for event in sort_events(events):
        replay.feed(event)
    replay.flush(float("inf"))
    result.rejected_by_rules = replay.engine.rejected
    result.entropy_reader = sampler is not None
    verdicts = [b.verdict for b in replay.bursts.values()]
    result.entropy_verdicts = {v: verdicts.count(v) for v in ("high", "low", "unknown") if v in verdicts}
    result.entropy_refused = dict(sampler.refused) if sampler else {}

    for items in (result.alerts, result.decisions, result.reports):
        items.sort(key=lambda item: item["alert_id"])
    return result
