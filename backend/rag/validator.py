"""Checks technique IDs against the pinned STIX data (CLAUDE.md design rule 5).

An ID an LLM produced is a claim, not a fact. Only "valid" means it's safe to show, and
a revoked ID reports what replaced it, following any chain to the final active ID.
"""

import re
from dataclasses import dataclass

from backend.rag.attack_data import AttackData, load_attack_data

TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


@dataclass(frozen=True)
class IdCheck:
    id: str
    status: str  # valid, revoked, deprecated, unknown or malformed
    name: str | None = None
    replacement: str | None = None  # the final active ID, for a revoked technique

    @property
    def valid(self) -> bool:
        return self.status == "valid"


def check_technique_id(technique_id: str, data: AttackData | None = None) -> IdCheck:
    data = data or load_attack_data()
    if not isinstance(technique_id, str) or not TECHNIQUE_ID.match(technique_id):
        return IdCheck(str(technique_id), "malformed")
    if technique_id in data.techniques:
        return IdCheck(technique_id, "valid", data.techniques[technique_id].name)
    if technique_id in data.replaced_by:
        replacement = data.replaced_by[technique_id]
        active = data.techniques.get(replacement) if replacement else None
        return IdCheck(technique_id, "revoked", active.name if active else None, replacement)
    if technique_id in data.deprecated:
        return IdCheck(technique_id, "deprecated")
    return IdCheck(technique_id, "unknown")


def check_technique_ids(technique_ids: list[str], data: AttackData | None = None) -> list[IdCheck]:
    data = data or load_attack_data()
    return [check_technique_id(technique_id, data) for technique_id in technique_ids]
