"""Checks the rule files against the real pinned ATT&CK data.

Run on their own with: uv run pytest tests/test_behaviour_real.py -v
They skip when the data is missing, so read the skip count: a skip here proves nothing.
"""

import pytest

from backend.rag import attack_data
from backend.rag.attack_data import load_attack_data
from backend.rag.validator import check_technique_id
from detection.behaviour import load_rules

pytestmark = [
    pytest.mark.attack_data,
    pytest.mark.skipif(
        not attack_data.STIX_PATH.is_file(), reason="run: uv run python -m backend.rag.fetch"
    ),
]


def test_every_technique_in_a_rule_file_is_active_in_attack():
    data = load_attack_data()
    used = {technique for rule in load_rules() for technique in rule.techniques}
    assert used
    for technique in sorted(used):
        assert check_technique_id(technique, data).valid, technique


def test_the_revoked_technique_is_not_used():
    data = load_attack_data()
    assert check_technique_id("T1562.001", data).replacement == "T1685"
    assert "T1562.001" not in {t for rule in load_rules() for t in rule.techniques}
