#!/usr/bin/env python3
"""Generate batch_plan.json: which sessions run in which batch, and in what order.

Usage: python agent/tools/make_batch_plan.py

Run once. The result is committed, so every recording follows the same order. The seed
is recorded in the file, and a test checks that this script still produces it.

Batches mix benign and attack sessions in random order, so that a batch doesn't correlate
with the label. Activities that change the system run last in their batch.
"""

import json
import random
from pathlib import Path

SEED = 20261106
CONFIG = Path(__file__).resolve().parents[1] / "config" / "recording_tests.json"
OUTPUT = Path(__file__).resolve().parent / "batch_plan.json"

FULL_BATCHES = 3  # host-only batches that also hold the two held-out tests
HOST_BATCHES = 5
HELD_OUT_IN_HOST_BATCHES = ("T1053.005-2", "T1218.011-9")
SYSTEM_CHANGING = ("install-uninstall", "windows-update")  # last in a batch, in this order
HOST_BENIGN = ["normal-use"] * 3 + ["admin-powershell"] * 3 + ["zip-files"] * 3 + ["install-uninstall"]

# Each windows-update session needs its own boot: a second one would find nothing to do.
NAT_BATCHES = (
    (2, ("install-uninstall", "windows-update")),
    (2, ("install-uninstall", "windows-update")),
    (1, ("windows-update",)),
)
T1105 = "T1105-29"
T1685 = "T1685-51"


def deal_host_benign(rng: random.Random) -> list[list[str]]:
    """Two different activities per host-only batch."""
    while True:
        activities = HOST_BENIGN.copy()
        rng.shuffle(activities)
        pairs = [activities[index:index + 2] for index in range(0, len(activities), 2)]
        if all(first != second for first, second in pairs):
            return pairs


def order_sessions(sessions: list[dict], rng: random.Random) -> list[dict]:
    def rank(session: dict) -> int:
        activity = session.get("activity")
        return SYSTEM_CHANGING.index(activity) + 1 if activity in SYSTEM_CHANGING else 0

    shuffled = sessions.copy()
    rng.shuffle(shuffled)
    return sorted(shuffled, key=rank)  # a stable sort keeps the random order within a rank


def build_plan(tests: list[dict]) -> dict:
    rng = random.Random(SEED)
    host_tests = [
        test["id"] for test in tests
        if test["pool"] == "training-technique" and test["network"] == "host-only"
    ]
    benign_pairs = deal_host_benign(rng)
    groups: list[tuple[str, list[dict]]] = []

    for index in range(HOST_BATCHES):
        sessions = [{"test_id": test_id} for test_id in host_tests]
        if index < FULL_BATCHES:
            sessions += [{"test_id": test_id} for test_id in HELD_OUT_IN_HOST_BATCHES]
        sessions += [{"test_id": "benign", "activity": activity} for activity in benign_pairs[index]]
        groups.append(("host-only", sessions))

    for t1105_runs, activities in NAT_BATCHES:
        sessions = [{"test_id": T1105} for _ in range(t1105_runs)]
        sessions += [{"test_id": "benign", "activity": activity} for activity in activities]
        groups.append(("nat", sessions))

    for _ in range(3):
        groups.append(("host-only", [{"test_id": T1685}]))

    runs: dict[str, int] = {}
    batches = []
    for number, (network, sessions) in enumerate(groups, start=1):
        ordered = []
        for order, session in enumerate(order_sessions(sessions, rng), start=1):
            test_id = session["test_id"]
            runs[test_id] = runs.get(test_id, 0) + 1
            ordered.append({"order": order, "run": runs[test_id], **session})
        batches.append({"batch": number, "network": network, "sessions": ordered})

    return {"seed": SEED, "batches": batches}


def render(plan: dict) -> str:
    return json.dumps(plan, indent=2) + "\n"


def main() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    OUTPUT.write_text(render(build_plan(config["tests"])), encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
