"""A session's events in time order, without holding them in memory.

A recording can be 800 MB and a million events (a Windows Update session). The old way read
every event into a list of dicts, about 3 KB each, and sorted the list. This reads the files
twice instead:

1. one pass keeps, for each valid event, only its sort key and where its line starts;
2. the keys are sorted, then the events are read back one at a time in that order.

The order is exactly the one `sort_events` gives for the same events read with `read_jsonl`:
valid events of events.jsonl then fim.jsonl, stable-sorted on `order_key`. Ties keep file and
line order, because the position of a line is part of the key. Counting is the same too:
`unreadable` lines are those `read_jsonl` skips, and `parsed - valid` are the events the
schema rejects. Holding the index costs about 200 bytes per event, so a million events is
about 200 MB, against several GB for the events themselves.
"""

import json
import logging
from pathlib import Path
from typing import Callable, Iterator, Sequence

from detection.timeline import order_key, parse_ts

log = logging.getLogger(__name__)

SHIFT = 40  # a line's position is (file number << 40) | byte offset, so it orders like reading file 0 then file 1
MASK = (1 << SHIFT) - 1
BUFFER = 1 << 20


def decode(raw: bytes) -> dict | None:
    """The object on a line, or None when the line is not a JSON object (same rule as read_jsonl)."""
    try:
        item = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return item if isinstance(item, dict) else None


class SortedEvents:
    """Iterating yields each valid event (and, with `not_before`, each one at or after that
    time) as a fresh dict, in time order. Nothing but the index is kept. It can be iterated
    again: the files are read again."""

    def __init__(self, paths: Sequence[Path], is_valid: Callable[[dict], bool], not_before: float | None = None):
        self.paths = [Path(p) for p in paths]
        self.unreadable = 0   # lines that are not a JSON object
        self.parsed = 0       # JSON objects
        self.valid = 0        # of which the schema accepts
        index: list[tuple[str, int, int]] = []
        for number, path in enumerate(self.paths):
            if not path.is_file():
                continue
            offset = 0
            with path.open("rb", buffering=BUFFER) as stream:
                for raw in stream:
                    size = len(raw)
                    if raw.strip():
                        item = decode(raw)
                        if item is None:
                            self.unreadable += 1
                        else:
                            self.parsed += 1
                            if is_valid(item):
                                self.valid += 1
                                stamp, rank = order_key(item)
                                if not_before is None or parse_ts(item["ts"]).timestamp() >= not_before:
                                    index.append((stamp, rank, (number << SHIFT) | offset))
                    offset += size
        if self.unreadable:
            log.warning("%d unreadable line(s) skipped", self.unreadable)
        index.sort()
        self._index = index

    def __len__(self) -> int:
        return len(self._index)

    @property
    def skipped_invalid(self) -> int:
        return self.parsed - self.valid

    def __iter__(self) -> Iterator[dict]:
        handles: dict[int, object] = {}
        try:
            for _, _, position in self._index:
                number, offset = position >> SHIFT, position & MASK
                handle = handles.get(number)
                if handle is None:
                    handle = handles[number] = self.paths[number].open("rb", buffering=BUFFER)
                handle.seek(offset)
                event = decode(handle.readline())
                if event is None:  # the file changed under us
                    raise RuntimeError(f"{self.paths[number].name}: line at byte {offset} is no longer readable")
                yield event
        finally:
            for handle in handles.values():
                handle.close()
