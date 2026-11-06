"""The Windows side of FIM: reading the registry and waiting for notifications.

Both APIs are one-shot, so each watch is re-armed before the rescan. A change arriving
during the rescan then fires again rather than being missed. What a notification says
is never used, so a directory buffer overflow costs nothing.

Windows constants are defined here with their documented values, not read from
pywin32: win32con lacks some of them, and that only shows up as a crash in the VM. The
Windows-only imports are guarded, so WSL tests can import this table.
"""

import sys

from baseline import KeyContents, Snapshot, read_key_tree, scan_folder
from targets import FolderTarget, RegistryTarget

if sys.platform == "win32":
    import winreg

    import pywintypes
    import win32api
    import win32event
    import win32file

# Predefined keys, as signed values. Windows sign-extends them on 64-bit.
HKEY_CURRENT_USER = -2147483647  # 0x80000001
HKEY_LOCAL_MACHINE = -2147483646  # 0x80000002

# Registry access rights
KEY_NOTIFY = 0x0010
KEY_WOW64_64KEY = 0x0100  # the target names give the real path, so never redirect them

# RegNotifyChangeKeyValue filters
REG_NOTIFY_CHANGE_NAME = 0x00000001  # a subkey is added or deleted
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004  # a value is added, deleted or changed

# ReadDirectoryChangesW filters
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

# CreateFile arguments
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000

# Wait results
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# GetLastError value
ERROR_ALREADY_EXISTS = 183

NOTIFY_ROOTS = {"HKCU": HKEY_CURRENT_USER, "HKLM": HKEY_LOCAL_MACHINE}
REGISTRY_FILTER = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
APPEARANCE_FILTER = REG_NOTIFY_CHANGE_NAME  # only a subkey being added or deleted matters
FOLDER_FILTER = (
    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE
)
FOLDER_SHARING = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
FOLDER_FLAGS = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED

_BUFFER_BYTES = 8192


def _read_key(root: int, path: str) -> KeyContents | None:
    """One key's values and subkey names. None if the key doesn't exist."""
    try:
        key = winreg.OpenKey(root, path, 0, winreg.KEY_READ | KEY_WOW64_64KEY)
    except FileNotFoundError:
        return None
    except OSError:
        return KeyContents(unreadable=True)  # reported, so a key that is hidden shows up
    with key:
        values = []
        index = 0
        while True:
            try:
                values.append(winreg.EnumValue(key, index))  # (name, data, type)
            except OSError:  # no more values
                break
            index += 1
        subkeys = []
        index = 0
        while True:
            try:
                subkeys.append(winreg.EnumKey(key, index))
            except OSError:  # no more subkeys
                break
            index += 1
    return KeyContents(tuple(values), tuple(subkeys))


def read_registry(target: RegistryTarget) -> Snapshot:
    """The values in one key, and below it for a subtree target. A missing key is empty."""
    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    root = roots[target.root]
    return read_key_tree(
        lambda path: _read_key(root, path), target.name, target.subkey, target.subtree
    )


class _RegistryWatch:
    def __init__(self, target: RegistryTarget, subtree: bool, flags: int):
        self._subtree = subtree
        self._flags = flags
        self._key = win32api.RegOpenKeyEx(
            NOTIFY_ROOTS[target.root], target.subkey, 0, KEY_NOTIFY | KEY_WOW64_64KEY
        )
        self.event = win32event.CreateEvent(None, False, False, None)
        self.rearm()

    def rearm(self) -> None:
        win32api.RegNotifyChangeKeyValue(self._key, self._subtree, self._flags, self.event, True)


class _FolderWatch:
    def __init__(self, target: FolderTarget):
        self._handle = win32file.CreateFile(
            target.path, FILE_LIST_DIRECTORY, FOLDER_SHARING, None, OPEN_EXISTING, FOLDER_FLAGS, None
        )
        self._buffer = win32file.AllocateReadBuffer(_BUFFER_BYTES)
        self._overlapped = pywintypes.OVERLAPPED()
        self._overlapped.hEvent = win32event.CreateEvent(None, False, False, None)
        self.event = self._overlapped.hEvent
        self._start()

    def _start(self) -> None:
        win32file.ReadDirectoryChangesW(
            self._handle, self._buffer, False, FOLDER_FILTER, self._overlapped
        )

    def rearm(self) -> None:
        win32file.GetOverlappedResult(self._handle, self._overlapped, True)
        self._start()


class WindowsSource:
    def __init__(
        self,
        registry: tuple[RegistryTarget, ...],
        folders: tuple[FolderTarget, ...],
        stop_event,
        poll_only: bool,
        appearance: tuple[RegistryTarget, ...] = (),
    ):
        self._registry = registry
        self._folders = folders
        self._appearance = appearance
        self._stop_event = stop_event
        self._poll_only = poll_only
        self._watches: dict[object, object] = {}  # target -> open watch
        self._reported: set[object] = set()
        self._open_missing_watches()

    def _open_missing_watches(self) -> None:
        """A target that can't be watched yet is still covered by the 60-second compare.

        Called again after every notification, so a key that has just appeared, such as
        RunOnceEx, is watched before the rescan that follows. The scan reads it anyway.
        """
        if self._poll_only:
            return
        openers = [
            (target, lambda t=target: _RegistryWatch(t, t.subtree, REGISTRY_FILTER))
            for target in self._registry
        ]
        openers += [
            (target, lambda t=target: _RegistryWatch(t, False, APPEARANCE_FILTER))
            for target in self._appearance
        ]
        openers += [(target, lambda t=target: _FolderWatch(t)) for target in self._folders]
        for target, open_watch in openers:
            if target in self._watches:
                continue
            try:
                self._watches[target] = open_watch()
                self._reported.discard(target)
            except pywintypes.error as error:
                if getattr(target, "optional", False) or target in self._reported:
                    continue
                self._reported.add(target)
                label = target.name if isinstance(target, RegistryTarget) else target.path
                print(f"Not watching {label}: {error.strerror}")
                print("The 60-second compare still covers it.")

    def scan(self) -> Snapshot:
        items: Snapshot = {}
        for target in self._registry:
            items.update(read_registry(target))
        for target in self._folders:
            items.update(scan_folder(target))
        return items

    def _rearm(self, target: object) -> None:
        try:
            self._watches[target].rearm()
        except pywintypes.error:
            del self._watches[target]  # the key or folder was deleted; reopened on timeout

    def wait(self, timeout_seconds: float) -> bool:
        watched = list(self._watches)
        handles = [self._stop_event] + [self._watches[target].event for target in watched]
        result = win32event.WaitForMultipleObjects(handles, False, int(timeout_seconds * 1000))

        if result == WAIT_TIMEOUT:
            self._open_missing_watches()
            return False
        index = result - WAIT_OBJECT_0
        if index == 0:
            return False

        # Re-arm everything that fired, so one change can't cause a second empty rescan.
        self._rearm(watched[index - 1])
        for target in watched[index:]:
            event = self._watches[target].event
            if win32event.WaitForSingleObject(event, 0) == WAIT_OBJECT_0:
                self._rearm(target)
        # Before the rescan, so that a change in a key that just appeared is not missed.
        self._open_missing_watches()
        return True
