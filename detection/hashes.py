"""Known-bad SHA-256 list: 1st generation signatures.

An exact hash has no false positives, but one changed byte defeats it. That's why it
sits beside YARA, and why neither is the whole defence.
"""

import json
import re
from functools import lru_cache
from pathlib import Path

HASH_LIST_PATH = Path(__file__).resolve().parents[1] / "rules" / "hashes" / "known_bad.json"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
NAME = re.compile(r"^[A-Z0-9-]+$")


def parse_hash_list(path: Path) -> dict[str, str]:
    """Maps a hash to its signature name. A bad entry stops startup, because a list that
    silently loses entries looks exactly like a clean scan."""
    document = json.loads(path.read_text(encoding="utf-8"))
    hashes: dict[str, str] = {}
    for entry in document["entries"]:
        sha256, name = entry["sha256"], entry["name"]
        if not SHA256.match(sha256):
            raise ValueError(f"bad sha256 in {path.name}: {sha256!r}")
        if not NAME.match(name):
            raise ValueError(f"bad name in {path.name}: {name!r}")
        if sha256 in hashes:
            raise ValueError(f"repeated sha256 in {path.name}: {sha256}")
        hashes[sha256] = name
    return hashes


@lru_cache(maxsize=1)
def known_bad() -> dict[str, str]:
    return parse_hash_list(HASH_LIST_PATH)


def lookup(sha256: str) -> str | None:
    return known_bad().get(sha256)
