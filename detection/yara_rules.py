"""YARA rules from rules/yara/: 1st generation signatures, by pattern and not by exact hash.

Rules come only from the repo. The path is fixed here with no setting to change it,
rule files can't include other files, and precompiled rule files are never read, because
loading one from an untrusted source is not safe.
"""

import re
from functools import lru_cache
from pathlib import Path

import yara

RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "yara"
TIMEOUT_SECONDS = 30
SIGNATURE_NAME = re.compile(r"^[A-Z0-9-]+$")


def compile_rules(directory: Path) -> yara.Rules:
    """A rule that can't compile stops startup: a missing layer must not look like a clean scan."""
    paths = {path.stem: str(path) for path in sorted(directory.glob("*.yar"))}
    if not paths:
        raise ValueError(f"no YARA rules in {directory}")
    rules = yara.compile(filepaths=paths, includes=False, error_on_warning=True)
    for rule in rules:
        if not SIGNATURE_NAME.match(str(rule.meta.get("signature", ""))):
            raise ValueError(f"YARA rule {rule.identifier} needs meta: signature = \"NAME\"")
    return rules


@lru_cache(maxsize=1)
def compiled_rules() -> yara.Rules:
    return compile_rules(RULES_DIR)


def match(data: bytes) -> list[dict[str, str]]:
    """Raises yara.Error, including yara.TimeoutError, for the caller to report."""
    matches = compiled_rules().match(data=data, timeout=TIMEOUT_SECONDS)
    return [{"rule": m.rule, "signature": m.meta["signature"]} for m in matches]
