"""Byte entropy of newly written document files: the "output looks encrypted" signal.

Generation: 3rd (behaviour), for the ransomware zone (PLANNING.md Section 5.6 P3,
"write rate + entropy"). A burst of deletes can be an archiver or a ransomware. What
separates them is the content that replaces the originals: encrypted bytes are close to
random (about 8 bits per byte) and carry no known file header.

Why entropy alone is not enough: JPEG, DOCX, ZIP and PDF files are compressed, so they
also score close to 8. A file is only *suspect* when its entropy is high AND it does not
look like the format it claims to be (no known magic bytes, or magic for another type).

Safety rules, all enforced here and tested:
- Only files whose event path is in the documents zone are ever opened.
- Links are never followed: every component of the path is checked with lstat (symlinks
  and Windows reparse points are refused), and the opened file must be the one lstat saw.
- Only regular files are opened (no pipes or devices), read-only, and nothing is
  executed, loaded or parsed. The bytes are only counted and compared with a few headers.
- Reads are limited: file size, bytes per file, and files and bytes per time window.
  When a limit is hit the answer is "no sample", which the verdict treats as unknown.

Limits of the idea (also in detection/README.md): ransomware that writes low-entropy
output, or output that starts with a real file header, is not seen as suspect here.
"""

import math
import os
import stat
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Callable

from detection import zones

ENTROPY_THRESHOLD = 7.5      # bits per byte. A starting guess (PLANNING.md Section 10).
MIN_BYTES = 512              # below this even random data scores under 7.6, so no verdict
HEAD_BYTES = 64 * 1024
MIDDLE_BYTES = 64 * 1024     # read only for files larger than head + middle
MAX_FILE_BYTES = 64 * 1024 * 1024
REPARSE_POINT = 0x400        # Windows FILE_ATTRIBUTE_REPARSE_POINT: junctions and links

# (name, offset, header bytes). A header is only a hint about format, never trusted further.
MAGICS = (
    ("zip", 0, b"PK\x03\x04"),
    ("pdf", 0, b"%PDF-"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("gif", 0, b"GIF87a"),
    ("gif", 0, b"GIF89a"),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("rar", 0, b"Rar!\x1a\x07"),
    ("gzip", 0, b"\x1f\x8b"),
    ("bzip2", 0, b"BZh"),
    ("ole2", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("mp3", 0, b"ID3"),
    ("mp4", 4, b"ftyp"),
    ("riff", 0, b"RIFF"),
)
# Which extensions belong to which format. An extension that is not listed has no
# expectation, so any known header is accepted for it.
EXTENSIONS = {
    "zip": ("zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "epub"),
    "pdf": ("pdf",),
    "png": ("png",),
    "jpeg": ("jpg", "jpeg"),
    "gif": ("gif",),
    "7z": ("7z",),
    "rar": ("rar",),
    "gzip": ("gz", "tgz"),
    "bzip2": ("bz2",),
    "ole2": ("doc", "xls", "ppt", "msg"),
    "mp3": ("mp3",),
    "mp4": ("mp4", "m4a", "m4v", "mov"),
    "riff": ("wav", "avi", "webp"),
}
EXPECTED = {ext: kind for kind, exts in EXTENSIONS.items() for ext in exts}


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0 to 8."""
    if not data:
        return 0.0
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


def magic_of(data: bytes) -> str | None:
    for kind, offset, header in MAGICS:
        if data[offset:offset + len(header)] == header:
            return kind
    return None


def extension_of(path: str) -> str:
    name = path.replace("/", "\\").rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


@dataclass(frozen=True)
class Sample:
    entropy: float
    magic: str | None
    size: int


def is_suspect(sample: Sample, path: str) -> bool:
    """High entropy, and not a format that explains it. A known header that fits the
    extension (or an extension with no expectation) is ordinary compressed data."""
    if sample.entropy < ENTROPY_THRESHOLD:
        return False
    if sample.magic is None:
        return True
    expected = EXPECTED.get(extension_of(path))
    return expected is not None and expected != sample.magic


@dataclass(frozen=True)
class Limits:
    window_seconds: float = 10.0
    files_per_window: int = 100
    bytes_per_window: int = 16 * 1024 * 1024


@dataclass
class Budget:
    """Files and bytes read per sliding time window. Time is the event time, so a replay
    spends it exactly as a live run would."""

    limits: Limits = field(default_factory=Limits)
    _spent: deque = field(default_factory=deque)

    def _trim(self, now: float) -> None:
        while self._spent and now - self._spent[0][0] > self.limits.window_seconds:
            self._spent.popleft()

    def allows(self, now: float) -> bool:
        self._trim(now)
        return (len(self._spent) < self.limits.files_per_window
                and sum(n for _, n in self._spent) < self.limits.bytes_per_window)

    def charge(self, now: float, nbytes: int) -> None:
        self._spent.append((now, nbytes))


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT)


def components(local: str) -> list[str]:
    """The path and every parent of it, shortest first."""
    parts, current = [], local
    while True:
        parts.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            return parts[::-1]
        current = parent


class FileSampler:
    """Reads a bounded sample of a document file and returns its entropy and header kind.

    `translate` maps the event's path to a path on this machine. The default is the path
    itself, which is right in the lab VM. In WSL a recording's `C:\\...` path does not
    exist, so nothing is read and every answer is "no sample".
    """

    def __init__(self, translate: Callable[[str], str] | None = None, limits: Limits | None = None):
        self.translate = translate or (lambda path: path)
        self.budget = Budget(limits or Limits())
        self.refused: Counter = Counter()
        self.last_refusal: str | None = None

    def sample(self, event_path: object, now: float) -> Sample | None:
        self.last_refusal = None
        if not zones.is_document_path(event_path):
            return self._no("outside_zone")
        if not self.budget.allows(now):
            return self._no("budget")
        try:
            local = self.translate(event_path)
            if "\x00" in local:
                return self._no("bad_path")
            before = None
            for part in components(local):
                before = os.lstat(part)
                if is_link(before):
                    return self._no("link")
            if not stat.S_ISREG(before.st_mode):
                return self._no("not_regular")
            if before.st_size > MAX_FILE_BYTES:
                return self._no("too_big")
            if before.st_size < MIN_BYTES:
                return self._no("too_small")
            data = self._read(local, before)
        except FileNotFoundError:
            return self._no("vanished")
        except (OSError, ValueError):
            return self._no("error")
        if data is None:
            return self._no("changed")
        self.budget.charge(now, len(data))
        return Sample(entropy=shannon_entropy(data), magic=magic_of(data), size=before.st_size)

    def _read(self, local: str, before: os.stat_result) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(local, flags)
        try:
            opened = os.fstat(fd)
            # The file opened must be the file checked: a swap in between is refused.
            if not stat.S_ISREG(opened.st_mode) or (before.st_ino and (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev)):
                return None
            data = os.read(fd, HEAD_BYTES)
            if opened.st_size > HEAD_BYTES + MIDDLE_BYTES:
                os.lseek(fd, opened.st_size // 2, os.SEEK_SET)
                data += os.read(fd, MIDDLE_BYTES)
            return data
        finally:
            os.close(fd)

    def _no(self, reason: str) -> None:
        self.refused[reason] += 1
        self.last_refusal = reason
        return None
