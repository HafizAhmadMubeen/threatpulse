"""Reads the pinned ATT&CK STIX bundle into one document per technique.

Since ATT&CK moved detection guidance out of techniques, x_mitre_detection is empty on
every active technique. It now lives in x-mitre-detection-strategy objects, joined by
"detects" relationships, which point to x-mitre-analytic objects.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "attack"

ATTACK_VERSION = "20.1"
STIX_URL = (
    f"https://github.com/mitre-attack/attack-stix-data/releases/download/v{ATTACK_VERSION}/"
    "enterprise-attack.json"
)
STIX_PATH = DATA_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"
STIX_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
STIX_MAX_BYTES = 64 * 1024 * 1024

MODEL_NAME = "all-MiniLM-L6-v2"
MODEL_URL = "https://chroma-onnx-models.s3.amazonaws.com/all-MiniLM-L6-v2/onnx.tar.gz"
MODEL_SHA256 = "913d7300ceae3b2dbc2c50d1de4baacab4be7b9380491c27fab7418616a16ec3"
MODEL_MAX_BYTES = 256 * 1024 * 1024
MODEL_DIR = DATA_DIR / "models" / MODEL_NAME
MODEL_ARCHIVE = MODEL_DIR / "onnx.tar.gz"

EMBED_MAX_CHARS = 1000  # the model reads 256 tokens, so the rest would be ignored anyway

CITATION = re.compile(r"\(Citation: [^)]*\)")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
CODE_TAG = re.compile(r"</?code>")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str  # "OS Credential Dumping: LSASS Memory" for a sub-technique
    description: str
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    detection_strategy: str
    detection: tuple[str, ...]

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.id

    @property
    def windows(self) -> bool:
        return "Windows" in self.platforms

    @property
    def document(self) -> str:
        """The full text, which is what a report's prompt receives."""
        lines = [
            f"{self.id} {self.name}",
            f"Tactics: {', '.join(self.tactics)}",
            f"Platforms: {', '.join(self.platforms)}",
            "",
            self.description,
        ]
        if self.detection_strategy or self.detection:
            lines += ["", f"Detection: {self.detection_strategy}", *self.detection]
        return "\n".join(lines)

    @property
    def embedding_text(self) -> str:
        """The part that fits in the model's window, with the most telling text first."""
        lines = [
            self.name,
            f"Tactics: {', '.join(self.tactics)}",
            self.detection_strategy,
            self.description,
        ]
        return "\n".join(line for line in lines if line)[:EMBED_MAX_CHARS]


@dataclass
class AttackData:
    techniques: dict[str, Technique] = field(default_factory=dict)  # active ones only
    replaced_by: dict[str, str | None] = field(default_factory=dict)  # revoked -> final ID
    deprecated: set[str] = field(default_factory=set)


def clean(text: str) -> str:
    """Citations and links are noise for embeddings, and a link is nothing to offer an LLM."""
    text = LINK.sub(r"\1", CITATION.sub("", text))
    return re.sub(r"[ \t]+", " ", CODE_TAG.sub("", text)).strip()


def external_id(item: dict) -> str | None:
    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def is_active(item: dict) -> bool:
    return not item.get("revoked") and not item.get("x_mitre_deprecated")


def detection_text(strategy: dict, by_id: dict[str, dict]) -> tuple[str, ...]:
    analytics = (by_id.get(ref) for ref in strategy.get("x_mitre_analytic_refs", []))
    active = [item for item in analytics if item and is_active(item) and item.get("description")]
    # This project runs on Windows, so its guidance comes first.
    active.sort(key=lambda item: "Windows" not in item.get("x_mitre_platforms", []))
    return tuple(clean(item["description"]) for item in active)


def final_replacement(stix_id: str, revoked_by: dict[str, str], by_id: dict[str, dict]) -> str | None:
    """A replacement can itself be revoked, so this follows the chain to the end. Returns
    None if it ends at nothing active."""
    seen = {stix_id}
    current = stix_id
    while current in revoked_by:
        current = revoked_by[current]
        if current in seen:
            return None
        seen.add(current)
    item = by_id.get(current)
    return external_id(item) if item and is_active(item) else None


def parse_stix(objects: list[dict]) -> AttackData:
    by_id = {item["id"]: item for item in objects if "id" in item}
    relationships = [item for item in objects if item.get("type") == "relationship"]
    revoked_by = {
        item["source_ref"]: item["target_ref"]
        for item in relationships
        if item.get("relationship_type") == "revoked-by"
    }
    strategies: dict[str, dict] = {}
    for item in relationships:
        if item.get("relationship_type") == "detects":
            strategy = by_id.get(item["source_ref"])
            if strategy and is_active(strategy):
                strategies[item["target_ref"]] = strategy

    patterns = [item for item in objects if item.get("type") == "attack-pattern"]
    names = {external_id(item): item.get("name", "") for item in patterns}

    data = AttackData()
    for item in patterns:
        technique_id = external_id(item)
        if technique_id is None:
            continue
        if item.get("revoked"):
            data.replaced_by[technique_id] = final_replacement(item["id"], revoked_by, by_id)
        elif item.get("x_mitre_deprecated"):
            data.deprecated.add(technique_id)
        else:
            parent = technique_id.split(".")[0]
            name = item["name"]
            if parent != technique_id and parent in names:
                name = f"{names[parent]}: {name}"
            strategy = strategies.get(item["id"], {})
            data.techniques[technique_id] = Technique(
                id=technique_id,
                name=name,
                description=clean(item.get("description", "")),
                tactics=tuple(p["phase_name"] for p in item.get("kill_chain_phases", [])),
                platforms=tuple(item.get("x_mitre_platforms", [])),
                detection_strategy=clean(strategy.get("name", "")),
                detection=detection_text(strategy, by_id),
            )
    return data


def load_bundle(path: Path = STIX_PATH, sha256: str = STIX_SHA256) -> list[dict]:
    """The same pinned bytes every time, or nothing: reports are grounded on this file."""
    if not path.is_file():
        raise FileNotFoundError(f"{path} is missing. Run: uv run python -m backend.rag.fetch")
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != sha256:
        raise ValueError(f"{path.name} has SHA-256 {actual}, expected {sha256}")
    return json.loads(raw)["objects"]


@lru_cache(maxsize=1)
def load_attack_data() -> AttackData:
    return parse_stix(load_bundle())
