"""Windows path comparison for the policy engine.

The never-suspend list and the LSASS allowlist match by full path, so two spellings of
one path must compare equal, and a path that only looks similar must not. Pure string
work: nothing here touches a file system, so it runs the same in WSL and in the VM.
"""

import re

_SHORT_NAME = re.compile(r"~[0-9]")
_DRIVE = re.compile(r"^[A-Za-z]:\\")


def normalise(path: object) -> tuple[str, ...] | None:
    """Return the path as lower-case segments, or None when it can't be trusted.

    None means "no match" to every caller. That is the safe answer for a path that
    can't be resolved here: relative paths, `..` that climbs out of the drive, and 8.3
    short names (`PROGRA~1`), which would need a file system to expand. An attacker
    can choose a short name, so letting one match would let it borrow trust.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    text = path.replace("/", "\\")
    for prefix in ("\\\\?\\", "\\\\.\\"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if not _DRIVE.match(text):
        return None
    drive, rest = text[0].lower() + ":", text[3:]
    segments: list[str] = []
    for part in rest.split("\\"):
        # Windows ignores trailing dots and spaces, so `svchost.exe.` is `svchost.exe`.
        part = part.rstrip(". ") if part not in (".", "..") else part
        if part in ("", "."):
            continue
        if part == "..":
            if not segments:
                return None
            segments.pop()
            continue
        if _SHORT_NAME.search(part):
            return None
        segments.append(part.lower())
    if not segments:
        return None
    return (drive, *segments)


def matches(path: object, pattern: str) -> bool:
    """True when `path` is the file `pattern` names. A pattern segment `*` stands for
    exactly one whole segment (Defender's versioned folder), never part of a name."""
    actual = normalise(path)
    wanted = normalise(pattern.replace("\\*\\", "\\__any__\\"))
    if actual is None or wanted is None or len(actual) != len(wanted):
        return False
    return all(w == "__any__" or w == a for w, a in zip(wanted, actual))
