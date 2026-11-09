"""The ransomware verdict: did one process write encrypted-looking files in the documents zone?

R-T1486-001 (behaviour.py) counts deletes and renames, and cannot tell an archiver from a
ransomware. This module adds what the files turned into. For each process it samples the
files it newly wrote in the documents zone (detection/entropy.py) and answers:

  high     at least MIN_FILES sampled and at least 80% of them suspect
  low      at least MIN_FILES sampled and at most 20% of them suspect
  unknown  anything else: too few files, files gone or unreadable, a limit was hit, or no
           reader at all (a replay in WSL). Unknown never lowers anything.

The pipeline raises R-T1486-002 only for a burst with a `high` verdict. `low` and
`unknown` leave R-T1486-001 as it is. Nothing is ever suppressed.

Thresholds are starting guesses (PLANNING.md Section 10), not measured on real data.
"""

from collections import OrderedDict
from dataclasses import dataclass, field

from detection import zones
from detection.entropy import FileSampler, Sample, is_suspect

RANSOM_RULE_ID = "R-T1486-002"
BURST_RULE_ID = "R-T1486-001"
MIN_FILES = 5
HIGH_FRACTION = 0.80
LOW_FRACTION = 0.20
SETTLE_SECONDS = 1.0         # a file written less than this long ago may still be open
MAX_PATHS_PER_PID = 500      # remembered written paths, oldest dropped first
MAX_SAMPLED_PER_PID = 200
MAX_PIDS = 256
WRITTEN_EVENTS = ("file_create", "file_write", "file_rename")

HIGH, LOW, UNKNOWN = "high", "low", "unknown"


@dataclass
class Written:
    path: str
    seen_at: float
    event_id: str
    sampled_at: float | None = None
    suspect: bool | None = None


@dataclass
class Record:
    paths: "OrderedDict[str, Written]" = field(default_factory=OrderedDict)
    sampled: int = 0


def verdict_of(results: list[bool]) -> str:
    if len(results) < MIN_FILES:
        return UNKNOWN
    share = sum(results) / len(results)
    if share >= HIGH_FRACTION:
        return HIGH
    if share <= LOW_FRACTION:
        return LOW
    return UNKNOWN


class RansomJudge:
    def __init__(self, sampler: FileSampler):
        self.sampler = sampler
        self.records: "OrderedDict[int, Record]" = OrderedDict()

    def observe(self, event: dict) -> None:
        """Remember what a process wrote in the documents zone. Reads nothing."""
        pid = event["pid"]
        if pid <= 0 or event["source"] != "etw":
            return
        if event["event_type"] == "process_start":
            self.records.pop(pid, None)  # a reused pid is a new process
            return
        path = event["target"].get("path")
        if event["event_type"] not in WRITTEN_EVENTS or not zones.is_document_path(path):
            return
        record = self.records.get(pid)
        if record is None:
            record = self.records[pid] = Record()
            while len(self.records) > MAX_PIDS:
                self.records.popitem(last=False)
        key = path.lower()
        record.paths.pop(key, None)  # a rewrite is a new version of the file
        record.paths[key] = Written(path=path, seen_at=_seconds(event), event_id=event["event_id"])
        while len(record.paths) > MAX_PATHS_PER_PID:
            record.paths.popitem(last=False)

    def judge(self, pid: int, now: float, *, settle: float = SETTLE_SECONDS) -> tuple[str, list[str]]:
        """Samples what is not yet sampled (within the limits) and returns the verdict
        with the event IDs of the files that were suspect."""
        record = self.records.get(pid)
        if record is None:
            return UNKNOWN, []
        for written in list(record.paths.values()):
            if written.sampled_at is not None and written.sampled_at >= written.seen_at:
                continue
            if now - written.seen_at < settle or record.sampled >= MAX_SAMPLED_PER_PID:
                continue
            result = self.sampler.sample(written.path, now)
            if result is None:
                if self.sampler.last_refusal == "budget":
                    break  # out of budget for now; the next judgement tries again
                written.sampled_at, written.suspect = now, None  # gone, too small, a link...: not retried
                continue
            record.sampled += 1
            written.sampled_at, written.suspect = now, is_suspect(result, written.path)
        results = [w.suspect for w in record.paths.values() if w.suspect is not None]
        suspects = [w.event_id for w in record.paths.values() if w.suspect]
        return verdict_of(results), suspects


def _seconds(event: dict) -> float:
    from detection.timeline import parse_ts
    return parse_ts(event["ts"]).timestamp()


__all__ = ["RansomJudge", "Sample", "verdict_of", "RANSOM_RULE_ID", "BURST_RULE_ID", "HIGH", "LOW", "UNKNOWN"]
