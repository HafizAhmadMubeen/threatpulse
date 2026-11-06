"""The protected zones as path and key patterns, shared by the rules and the features.

These are the only place a path or key shapes anything a model sees, and only as a
yes/no answer: "is this in a document folder". The rule files in rules/behaviour/ repeat
these lists, because a rule file has to stand alone, and a test keeps the two in step.
All matching ignores case.
"""

DOCUMENT_FOLDERS = ("\\Documents\\", "\\Desktop\\", "\\Pictures\\", "\\Videos\\", "\\Music\\")
# Programs keep their own "Documents" folders. A user's files aren't there.
DOCUMENT_EXCLUDES = ("\\AppData\\", "\\Windows\\", "\\Program Files", "\\ProgramData\\")

PERSISTENCE_KEYS = (
    "\\CurrentVersion\\Run\\",
    "\\CurrentVersion\\RunOnce\\",
    "\\CurrentVersion\\RunOnceEx\\",
    "\\CurrentVersion\\RunServices\\",
    "\\CurrentVersion\\RunServicesOnce\\",
    "\\Policies\\Explorer\\Run\\",
    "\\Winlogon\\Shell",
    "\\Winlogon\\Userinit",
)
STARTUP_FOLDER = "\\Start Menu\\Programs\\Startup\\"
HOSTS_SUFFIX = "\\drivers\\etc\\hosts"
LSASS_SUFFIX = "\\lsass.exe"

# PLANNING.md 5.6 trusted_dirs.
TRUSTED_DIRS = ("C:\\Windows\\System32\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\")


def contains_any(text: object, needles: tuple[str, ...]) -> bool:
    if not isinstance(text, str):
        return False
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def is_document_path(path: object) -> bool:
    return contains_any(path, DOCUMENT_FOLDERS) and not contains_any(path, DOCUMENT_EXCLUDES)


def is_persistence_key(key: object) -> bool:
    return contains_any(key, PERSISTENCE_KEYS)


def is_startup_path(path: object) -> bool:
    return contains_any(path, (STARTUP_FOLDER,))


def is_hosts_path(path: object) -> bool:
    return isinstance(path, str) and path.lower().endswith(HOSTS_SUFFIX)


def is_lsass_path(path: object) -> bool:
    return isinstance(path, str) and path.lower().endswith(LSASS_SUFFIX)


def is_trusted_image(image: object) -> bool:
    return isinstance(image, str) and image.lower().startswith(tuple(d.lower() for d in TRUSTED_DIRS))
