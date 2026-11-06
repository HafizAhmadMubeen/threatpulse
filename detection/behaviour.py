"""Behaviour rules: 3rd generation. Sigma-style YAML in rules/behaviour/, run by a small engine.

match_rules(event) keeps state, because behaviour is about several events: who started
whom, how many files one process deleted, a connection followed by a file. Feed it events
in time order (replay() sorts them first).

Events are attacker-influenced telemetry, so the engine never evaluates them as code:
- rule files are read with yaml.safe_load and checked field by field before use
- matching is plain text comparison, with no regular expressions, so no text can make a
  rule run for a long time
- an event that isn't well formed is counted and skipped, and never stops the stream

Alerts come out with no risk score. The orchestrator adds the ML score (step 3.9).
"""

import logging
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from detection import zones
from detection.alerts import NO_PROCESS, checked, next_alert_id
from detection.timeline import format_ts, order_key, parse_ts

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "behaviour"
MAX_EVIDENCE = 20
MAX_ANCESTORS = 8

EVENT_TYPES = {
    "process_start", "process_stop", "process_access", "file_create", "file_write",
    "file_rename", "file_delete", "registry_set", "registry_delete", "network_connect",
    "fim_change",
}
FIELDS = {
    "event_type", "source", "pid", "ppid", "process.image", "process.cmdline", "process.user",
    "process.signed", "process.signer", "target.path", "target.old_path", "target.registry_key",
    "target.pid", "target.access_mask", "target.access_rights", "target.dest_ip",
    "target.dest_port", "target.change.kind", "parent.image",
}
MODIFIERS = {"contains", "contains_all", "startswith", "endswith"}
TEXT_MODIFIERS = MODIFIERS
KINDS = {"single", "threshold", "sequence"}
RULE_KEYS = {
    "id", "title", "description", "layer", "zone", "techniques", "type", "detection",
    "threshold", "sequence", "dedupe_by",
}
ZONE_NAMES = {"documents", "persistence", "lsass", "network", "none"}
RULE_ID = re.compile(r"^R-[A-Z0-9]+(-[A-Z0-9]+)*$")
TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
EVENT_ID = re.compile(r"^e-[0-9]{8}T[0-9]{6}-[0-9]{6,}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class RuleError(ValueError):
    """A rule file is wrong. Raised at load time so a broken rule can't pass as a quiet one."""


@dataclass(frozen=True)
class Condition:
    name: str
    modifier: str  # "" means equals
    values: tuple


@dataclass(frozen=True)
class Step:
    selection: tuple  # a tuple of alternatives, each a tuple of Conditions that must all hold
    filter: tuple


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    layer: str
    zone: str
    techniques: tuple[str, ...]
    kind: str
    steps: tuple[Step, ...]
    dedupe_by: tuple[str, ...]
    count: int = 0
    window: float = 0.0
    group_by: tuple[str, ...] = ()


def as_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


# Loading


def as_list(value: object) -> list:
    return value if isinstance(value, list) else [value]


def compile_condition(key: object, value: object, where: str) -> Condition:
    if not isinstance(key, str):
        raise RuleError(f"{where}: field name {key!r} is not text")
    name, _, modifier = key.partition("|")
    if name not in FIELDS:
        raise RuleError(f"{where}: unknown field {name!r}")
    if modifier and modifier not in MODIFIERS:
        raise RuleError(f"{where}: unknown modifier {modifier!r}")
    values = as_list(value)
    if not values:
        raise RuleError(f"{where}: {key} has no values")
    for item in values:
        if isinstance(item, (dict, list)):
            raise RuleError(f"{where}: {key} has a nested value")
        if modifier and not isinstance(item, str):
            raise RuleError(f"{where}: {key} needs text values")
    if modifier == "contains_all" and not isinstance(value, list):
        raise RuleError(f"{where}: contains_all needs a list")
    lowered = tuple(item.lower() if isinstance(item, str) else item for item in values)
    return Condition(name, modifier, lowered)


def compile_selection(raw: object, where: str) -> tuple:
    alternatives = raw if isinstance(raw, list) else [raw]
    compiled = []
    for alternative in alternatives:
        if not isinstance(alternative, dict) or not alternative:
            raise RuleError(f"{where}: a selection must be a map of fields, or a list of them")
        compiled.append(tuple(compile_condition(k, v, where) for k, v in alternative.items()))
    return tuple(compiled)


def compile_step(raw: object, where: str, allow_condition: bool = True) -> Step:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: must be a map")
    extra = set(raw) - {"selection", "filter", "condition"}
    if extra:
        raise RuleError(f"{where}: unknown keys {sorted(extra)}")
    if "selection" not in raw:
        raise RuleError(f"{where}: needs a selection")
    has_filter = "filter" in raw
    # The condition is fixed text, not an expression. It only has to agree with the maps.
    expected = "selection and not filter" if has_filter else "selection"
    if raw.get("condition", expected) != expected:
        raise RuleError(f"{where}: condition must be {expected!r}")
    return Step(
        compile_selection(raw["selection"], f"{where} selection"),
        compile_selection(raw["filter"], f"{where} filter") if has_filter else (),
    )


def positive_int(value: object, where: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise RuleError(f"{where} must be a positive number")
    return value


def field_list(value: object, where: str) -> tuple[str, ...]:
    names = as_list(value)
    for name in names:
        if name not in FIELDS:
            raise RuleError(f"{where}: unknown field {name!r}")
    return tuple(names)


def compile_rule(raw: object, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: each rule must be a map")
    rule_id = raw.get("id")
    where = f"{source} {rule_id}"
    extra = set(raw) - RULE_KEYS
    if extra:
        raise RuleError(f"{where}: unknown keys {sorted(extra)}")
    if not isinstance(rule_id, str) or not RULE_ID.match(rule_id):
        raise RuleError(f"{source}: bad rule id {rule_id!r}")
    for key in ("title", "zone", "techniques"):
        if key not in raw:
            raise RuleError(f"{where}: missing {key}")
    layer = raw.get("layer", "rule")
    if layer not in ("rule", "fim"):
        raise RuleError(f"{where}: layer must be rule or fim")
    if raw["zone"] not in ZONE_NAMES:
        raise RuleError(f"{where}: unknown zone {raw['zone']!r}")
    techniques = tuple(as_list(raw["techniques"])) if raw["techniques"] else ()
    for technique in techniques:
        if not isinstance(technique, str) or not TECHNIQUE_ID.match(technique):
            raise RuleError(f"{where}: bad technique {technique!r}")
    kind = raw.get("type", "single")
    if kind not in KINDS:
        raise RuleError(f"{where}: type must be one of {sorted(KINDS)}")

    count, window, group_by = 0, 0.0, ()
    if kind == "sequence":
        if "detection" in raw or "threshold" in raw or "sequence" not in raw:
            raise RuleError(f"{where}: a sequence rule has only a sequence")
        sequence = raw["sequence"]
        if not isinstance(sequence, dict) or set(sequence) != {"within_seconds", "group_by", "steps"}:
            raise RuleError(f"{where}: sequence needs within_seconds, group_by and steps")
        steps_raw = sequence["steps"]
        if not isinstance(steps_raw, list) or len(steps_raw) < 2:
            raise RuleError(f"{where}: a sequence needs at least two steps")
        steps = tuple(compile_step(s, f"{where} step {i + 1}") for i, s in enumerate(steps_raw))
        window = float(positive_int(sequence["within_seconds"], f"{where} within_seconds"))
        group_by = field_list(sequence["group_by"], where)
    else:
        if "detection" not in raw or "sequence" in raw:
            raise RuleError(f"{where}: needs a detection")
        if kind == "threshold":
            threshold = raw.get("threshold")
            if not isinstance(threshold, dict) or set(threshold) != {"count", "window_seconds", "group_by"}:
                raise RuleError(f"{where}: threshold needs count, window_seconds and group_by")
            count = int(positive_int(threshold["count"], f"{where} count"))
            window = float(positive_int(threshold["window_seconds"], f"{where} window_seconds"))
            group_by = field_list(threshold["group_by"], where)
        elif "threshold" in raw:
            raise RuleError(f"{where}: threshold is only for type threshold")
        steps = (compile_step(raw["detection"], f"{where} detection"),)

    dedupe = raw.get("dedupe_by", ["pid"])
    return Rule(
        id=rule_id, title=str(raw["title"]), layer=layer, zone=raw["zone"],
        techniques=techniques, kind=kind, steps=steps,
        dedupe_by=field_list(dedupe, where) if dedupe else (), count=count, window=window,
        group_by=group_by,
    )


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    """Every file must load. A rule that silently goes missing would look like a quiet system."""
    rules: list[Rule] = []
    seen: set[str] = set()
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise RuleError(f"no rule files in {directory}")
    for path in files:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            raise RuleError(f"{path.name}: not valid YAML ({type(error).__name__})") from error
        if not isinstance(document, list) or not document:
            raise RuleError(f"{path.name}: must be a list of rules")
        for raw in document:
            rule = compile_rule(raw, path.name)
            if rule.id in seen:
                raise RuleError(f"{path.name}: repeated rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


# Matching


def field_value(event: dict, name: str, procs: dict) -> object:
    if name == "parent.image":
        parent = procs.get(event.get("ppid"))
        return parent.image if parent else None
    value: object = event
    for part in name.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def value_matches(modifier: str, expected: tuple, actual: object) -> bool:
    if isinstance(actual, list):
        return any(value_matches(modifier, expected, item) for item in actual)
    if not modifier:
        if isinstance(actual, str):
            return actual.lower() in expected
        return any(type(actual) is type(item) and actual == item for item in expected)
    if not isinstance(actual, str):
        return False
    text = actual.lower()
    if modifier == "contains":
        return any(needle in text for needle in expected)
    if modifier == "contains_all":
        return all(needle in text for needle in expected)
    if modifier == "startswith":
        return text.startswith(expected)
    return text.endswith(expected)


def selection_matches(selection: tuple, event: dict, procs: dict) -> bool:
    return any(
        all(value_matches(c.modifier, c.values, field_value(event, c.name, procs)) for c in alternative)
        for alternative in selection
    )


def step_matches(step: Step, event: dict, procs: dict) -> bool:
    if not selection_matches(step.selection, event, procs):
        return False
    return not (step.filter and selection_matches(step.filter, event, procs))


# The engine


@dataclass
class ProcInfo:
    image: str
    ppid: int


@dataclass
class Pending:
    """How far one group has got through a sequence."""
    done: list = field(default_factory=list)  # (time, event_id) for each step completed


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else load_rules()
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.procs: dict[int, ProcInfo] = {}
            self.rejected = 0
            self._seen: set[tuple] = set()
            self._windows: dict[tuple, deque] = {}
            self._pending: dict[tuple, Pending] = {}

    # Public

    def process(self, event: object) -> list[dict]:
        with self._lock:
            parsed = self._accept(event)
            if parsed is None:
                self.rejected += 1
                return []
            when = parsed
            self._observe(event)
            alerts = []
            for rule in self.rules:
                hit = self._evaluate(rule, event, when)
                if hit is not None:
                    alert = self._alert(rule, event, when, hit)
                    if alert is not None:
                        alerts.append(alert)
            return alerts

    # Internals

    def _accept(self, event: object) -> float | None:
        if not isinstance(event, dict):
            return None
        if event.get("event_type") not in EVENT_TYPES:
            return None
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not EVENT_ID.match(event_id):
            return None
        if not isinstance(event.get("process"), dict) or not isinstance(event.get("target"), dict):
            return None
        try:
            return parse_ts(event.get("ts")).timestamp()
        except (ValueError, OverflowError, OSError):
            return None

    def _observe(self, event: dict) -> None:
        pid, ppid = event.get("pid"), event.get("ppid")
        image = event["process"].get("image")
        if not (isinstance(pid, int) and not isinstance(pid, bool) and pid > 0):
            return
        if not isinstance(image, str) or not image:
            return
        ppid = ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else 0
        if event["event_type"] == "process_start":
            self.procs[pid] = ProcInfo(image, ppid)  # a new process, even if the pid was reused
        else:
            self.procs.setdefault(pid, ProcInfo(image, ppid))

    def _group(self, rule: Rule, names: tuple[str, ...], event: dict) -> tuple:
        return (rule.id, *(repr(field_value(event, name, self.procs)) for name in names))

    def _evaluate(self, rule: Rule, event: dict, when: float) -> list[str] | None:
        """Returns the evidence event IDs if the rule fires on this event."""
        if rule.kind == "single":
            if not step_matches(rule.steps[0], event, self.procs):
                return None
            return self._once(rule, event, [event["event_id"]])
        if rule.kind == "threshold":
            return self._threshold(rule, event, when)
        return self._sequence(rule, event, when)

    def _once(self, rule: Rule, event: dict, evidence: list[str]) -> list[str] | None:
        if rule.dedupe_by:
            key = self._group(rule, rule.dedupe_by, event)
            if key in self._seen:
                return None
            self._seen.add(key)
        return evidence

    def _threshold(self, rule: Rule, event: dict, when: float) -> list[str] | None:
        if not step_matches(rule.steps[0], event, self.procs):
            return None
        key = self._group(rule, rule.group_by, event)
        if ("fired", *key) in self._seen:
            return None
        window = self._windows.setdefault(key, deque())
        window.append((when, event["event_id"]))
        while window and window[0][0] < when - rule.window:
            window.popleft()
        if len(window) < rule.count:
            return None
        self._seen.add(("fired", *key))
        self._windows.pop(key, None)
        return [event_id for _, event_id in list(window)[-MAX_EVIDENCE:]]

    def _sequence(self, rule: Rule, event: dict, when: float) -> list[str] | None:
        key = self._group(rule, rule.group_by, event)
        if ("fired", *key) in self._seen:
            return None
        pending = self._pending.setdefault(key, Pending())
        if pending.done and when - pending.done[-1][0] > rule.window:
            pending.done = []  # too slow, so start again
        index = len(pending.done)
        if step_matches(rule.steps[index], event, self.procs):
            pending.done.append((when, event["event_id"]))
        elif index > 0 and step_matches(rule.steps[0], event, self.procs):
            pending.done = [(when, event["event_id"])]  # a fresher first step
        if len(pending.done) < len(rule.steps):
            return None
        self._seen.add(("fired", *key))
        evidence = [event_id for _, event_id in pending.done]
        self._pending.pop(key, None)
        return evidence

    def _ancestors(self, event: dict) -> list[dict]:
        chain, seen = [], {event.get("pid")}
        parent = event.get("ppid")
        while len(chain) < MAX_ANCESTORS and parent in self.procs and parent not in seen:
            seen.add(parent)
            chain.append({"pid": parent, "image": self.procs[parent].image})
            parent = self.procs[parent].ppid
        return chain

    def _subject(self, event: dict) -> dict:
        pid = event["pid"]
        process = event["process"]
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return {**NO_PROCESS, "ancestors": []}
        image = process.get("image")
        return {
            "pid": pid,
            "image": image if isinstance(image, str) and image else "unknown",
            "signed": process.get("signed") is True,
            "signer": as_text(process.get("signer")),
            "trusted_path": zones.is_trusted_image(image),
            "ancestors": self._ancestors(event),
        }

    def _alert(self, rule: Rule, event: dict, when: float, evidence: list[str]) -> dict | None:
        target = event["target"]
        rights = target.get("access_rights")
        change = target.get("change") if isinstance(target.get("change"), dict) else {}
        new_value = change.get("new_value")
        alert = {
            "alert_id": next_alert_id(),
            "ts": format_ts(datetime.fromtimestamp(when, tz=timezone.utc)),
            "layer": rule.layer,
            "rule_id": rule.id,
            "technique_ids": list(rule.techniques),
            "risk_score": None,
            "event_type": event["event_type"],
            "subject": self._subject(event),
            "object": {
                "zone": rule.zone,
                "path": as_text(target.get("path")),
                "registry_key": as_text(target.get("registry_key")),
                "access": sorted({r for r in rights if isinstance(r, str) and r}) if isinstance(rights, list) else [],
                "file_sha256": new_value if isinstance(new_value, str) and SHA256.match(new_value) else None,
            },
            "evidence_event_ids": list(dict.fromkeys(evidence)),
        }
        try:
            return checked(alert)
        except ValueError:
            # The event had a field of the wrong type. It isn't worth stopping the stream for.
            self.rejected += 1
            log.warning("rule %s matched an event that can't be turned into a valid alert", rule.id)
            return None


# The contract function

_engine: RuleEngine | None = None
_engine_lock = threading.Lock()


def default_engine() -> RuleEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = RuleEngine()
        return _engine


def reset_engine() -> None:
    """Forget everything seen so far. Call this between sessions."""
    default_engine().reset()


def match_rules(event: dict) -> list[dict]:
    """ROADMAP.md Section 2. Events must arrive in time order: see replay.py."""
    return default_engine().process(event)


def sort_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=order_key)
