"""Loads and checks rules/policy.yaml.

A wrong policy file must stop startup. A rule that silently doesn't load looks exactly
like a quiet system, and for enforcement that is the dangerous reading.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from policy import paths

POLICY_FILE = Path(__file__).resolve().parent.parent / "rules" / "policy.yaml"

ACTIONS = ("alert_only", "suspend", "block_network", "restore", "request_kill", "request_delete")
ZONES = ("documents", "persistence", "lsass", "network", "none")
LAYERS = ("signature", "heuristic", "fim", "rule", "ml")
EVENT_TYPES = (
    "process_start", "process_stop", "process_access", "file_create", "file_write",
    "file_rename", "file_delete", "registry_set", "registry_delete", "network_connect",
    "fim_change", "file_scan",
)
SIGNATURES = ("microsoft", "none")
THRESHOLDS = ("auto_contain", "request_kill", "alert")
TOP_LEVEL = (
    "thresholds", "fim_debounce_seconds", "trusted_dirs", "never_suspend", "lsass_mode",
    "lsass_allowlist", "rules", "default",
)
# `when` keys the engine knows how to evaluate, and what each value must look like.
CONDITIONS = (
    "event_type", "zone", "layer", "access_includes", "in_lsass_allowlist",
    "change_approved", "risk_score_gte", "already_suspended",
)
RULE_ID = re.compile(r"^P[0-9]+[a-z]?-[a-z0-9-]+$")


class PolicyError(ValueError):
    """The policy file is wrong. Raised at load time, never during a decision."""


@dataclass(frozen=True)
class PathEntry:
    """`signature` is what must be true of the process at that path: a verified
    Microsoft signature, or `none` for our own unsigned programs."""

    path: str
    signature: str
    system: bool = False  # the kernel's System process: pid 4, image "System"


@dataclass(frozen=True)
class Rule:
    id: str
    when: dict
    actions: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    thresholds: dict
    fim_debounce_seconds: float
    trusted_dirs: tuple[str, ...]
    never_suspend: tuple[PathEntry, ...]
    lsass_mode: str
    lsass_allowlist: tuple[PathEntry, ...]
    rules: tuple[Rule, ...]
    default: tuple[str, ...]


def fail(message: str) -> None:
    raise PolicyError(message)


def is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check_keys(where: str, data: object, allowed: tuple[str, ...], required: tuple[str, ...] = ()):
    if not isinstance(data, dict):
        fail(f"{where}: expected a mapping")
    for key in data:
        if key not in allowed:
            fail(f"{where}: unknown key {key!r}")
    for key in required:
        if key not in data:
            fail(f"{where}: missing {key!r}")


def parse_thresholds(data: object) -> dict:
    check_keys("thresholds", data, THRESHOLDS, THRESHOLDS)
    for name, value in data.items():
        if not is_number(value) or not 0 <= value <= 1:
            fail(f"thresholds.{name}: must be a number from 0 to 1")
    if not data["alert"] <= data["auto_contain"] <= data["request_kill"]:
        fail("thresholds: expected alert <= auto_contain <= request_kill")
    return {name: float(value) for name, value in data.items()}


def parse_entries(where: str, data: object, allow_system: bool) -> tuple[PathEntry, ...]:
    if not isinstance(data, list):
        fail(f"{where}: expected a list")
    entries = []
    for index, item in enumerate(data):
        label = f"{where}[{index}]"
        check_keys(label, item, ("path", "signature", "system"))
        if item.get("system") is True:
            if not allow_system or set(item) != {"system"}:
                fail(f"{label}: 'system' stands alone, and only in never_suspend")
            entries.append(PathEntry(path="System", signature="microsoft", system=True))
            continue
        path, signature = item.get("path"), item.get("signature", "microsoft")
        if signature not in SIGNATURES:
            fail(f"{label}: signature must be one of {SIGNATURES}")
        if not isinstance(path, str) or not path:
            fail(f"{label}: 'path' is required")
        # `*` may only replace a whole folder name, and never the file name.
        segments = path.replace("/", "\\").split("\\")
        if any("*" in part and part != "*" for part in segments) or segments[-1] == "*":
            fail(f"{label}: '*' may only stand for one whole folder name")
        if paths.normalise(path.replace("\\*\\", "\\x\\")) is None:
            fail(f"{label}: must be a full path with a drive letter, e.g. C:\\Windows\\...")
        entries.append(PathEntry(path=path, signature=signature))
    return tuple(entries)


def parse_condition(rule_id: str, key: str, value: object) -> object:
    where = f"rule {rule_id}: when.{key}"
    if key == "event_type" and value not in EVENT_TYPES:
        fail(f"{where}: unknown event type {value!r}")
    if key == "zone" and value not in ZONES:
        fail(f"{where}: unknown zone {value!r}")
    if key == "layer" and value not in LAYERS:
        fail(f"{where}: unknown layer {value!r}")
    if key == "access_includes" and not (isinstance(value, str) and value):
        fail(f"{where}: expected an access right name")
    if key in ("in_lsass_allowlist", "change_approved", "already_suspended") and not isinstance(value, bool):
        fail(f"{where}: expected true or false")
    if key == "risk_score_gte" and not (value in THRESHOLDS or (is_number(value) and 0 <= value <= 1)):
        fail(f"{where}: expected a number from 0 to 1, or one of {THRESHOLDS}")
    return value


def parse_rules(data: object) -> tuple[Rule, ...]:
    if not isinstance(data, list) or not data:
        fail("rules: expected a non-empty list")
    rules, seen = [], set()
    for index, item in enumerate(data):
        check_keys(f"rules[{index}]", item, ("id", "when", "actions"), ("id", "when", "actions"))
        rule_id = item["id"]
        if not isinstance(rule_id, str) or not RULE_ID.match(rule_id):
            fail(f"rules[{index}]: id must look like P2b-persistence-origin")
        if rule_id in seen:
            fail(f"rule {rule_id}: duplicate id")
        seen.add(rule_id)
        check_keys(f"rule {rule_id}: when", item["when"], CONDITIONS)
        if not item["when"]:
            fail(f"rule {rule_id}: 'when' is empty, so it would match every alert")
        when = {key: parse_condition(rule_id, key, value) for key, value in item["when"].items()}
        actions = item["actions"]
        if not isinstance(actions, list) or not actions or any(a not in ACTIONS for a in actions):
            fail(f"rule {rule_id}: actions must be a non-empty list from {ACTIONS}")
        rules.append(Rule(id=rule_id, when=when, actions=tuple(actions)))
    return tuple(rules)


def parse_policy(data: object) -> Policy:
    check_keys("policy", data, TOP_LEVEL, TOP_LEVEL)
    mode = data["lsass_mode"]
    if mode not in ("learning", "enforcing"):
        fail("lsass_mode: must be learning or enforcing")
    debounce = data["fim_debounce_seconds"]
    if not is_number(debounce) or not 0 <= debounce <= 60:
        fail("fim_debounce_seconds: must be a number from 0 to 60")
    trusted = data["trusted_dirs"]
    if not isinstance(trusted, list) or not all(isinstance(d, str) and d for d in trusted):
        fail("trusted_dirs: expected a list of folders")
    if data["default"] != ["alert_only"]:
        fail("default: must be [alert_only]")
    return Policy(
        thresholds=parse_thresholds(data["thresholds"]),
        fim_debounce_seconds=float(debounce),
        trusted_dirs=tuple(trusted),
        never_suspend=parse_entries("never_suspend", data["never_suspend"], allow_system=True),
        lsass_mode=mode,
        lsass_allowlist=parse_entries("lsass_allowlist", data["lsass_allowlist"], allow_system=False),
        rules=parse_rules(data["rules"]),
        default=("alert_only",),
    )


def load_policy(path: Path = POLICY_FILE) -> Policy:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise PolicyError(f"cannot read {path}: {error}") from error
    return parse_policy(data)
