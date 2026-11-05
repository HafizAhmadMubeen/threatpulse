"""The Windows side of FIM: reading the registry and waiting for notifications.

Both APIs are one-shot, so each watch is re-armed before the rescan. A change arriving
during the rescan then fires again rather than being missed. What a notification says
is never used, so a directory buffer overflow costs nothing.
"""

import winreg

import pywintypes
import win32api
import win32con
import win32event
import win32file

from baseline import Item, Snapshot, encode_registry_data, scan_folder
from targets import FolderTarget, RegistryTarget

_READ_ROOTS = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
_NOTIFY_ROOTS = {"HKCU": win32con.HKEY_CURRENT_USER, "HKLM": win32con.HKEY_LOCAL_MACHINE}

# The target names already give the real path, so this view must not redirect them.
_VIEW_64 = win32con.KEY_WOW64_64KEY

_BUFFER_BYTES = 8192
_FOLDER_FILTER = (
    win32con.FILE_NOTIFY_CHANGE_FILE_NAME
    | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
    | win32con.FILE_NOTIFY_CHANGE_SIZE
)
_FILE_LIST_DIRECTORY = 0x0001


def read_registry(target: RegistryTarget) -> Snapshot:
    """The values in one key. A missing key is empty, not an error."""
    items: Snapshot = {}
    try:
        key = winreg.OpenKey(
            _READ_ROOTS[target.root], target.subkey, 0, winreg.KEY_READ | _VIEW_64
        )
    except FileNotFoundError:
        return items
    with key:
        index = 0
        while True:
            try:
                name, data, reg_type = winreg.EnumValue(key, index)
            except OSError:  # no more values
                return items
            value_name = name or "(Default)"
            items[f"{target.name}\\{value_name}"] = Item(
                "registry", encode_registry_data(data), reg_type
            )
            index += 1


class _RegistryWatch:
    def __init__(self, target: RegistryTarget):
        self._key = win32api.RegOpenKeyEx(
            _NOTIFY_ROOTS[target.root], target.subkey, 0, win32con.KEY_NOTIFY | _VIEW_64
        )
        self.event = win32event.CreateEvent(None, False, False, None)
        self.rearm()

    def rearm(self) -> None:
        win32api.RegNotifyChangeKeyValue(
            self._key,
            False,
            win32con.REG_NOTIFY_CHANGE_NAME | win32con.REG_NOTIFY_CHANGE_LAST_SET,
            self.event,
            True,
        )


class _FolderWatch:
    def __init__(self, target: FolderTarget):
        self._handle = win32file.CreateFile(
            target.path,
            _FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
            None,
        )
        self._buffer = win32file.AllocateReadBuffer(_BUFFER_BYTES)
        self._overlapped = pywintypes.OVERLAPPED()
        self._overlapped.hEvent = win32event.CreateEvent(None, False, False, None)
        self.event = self._overlapped.hEvent
        self._start()

    def _start(self) -> None:
        win32file.ReadDirectoryChangesW(
            self._handle, self._buffer, False, _FOLDER_FILTER, self._overlapped
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
    ):
        self._registry = registry
        self._folders = folders
        self._stop_event = stop_event
        self._poll_only = poll_only
        self._watches: dict[object, object] = {}  # target -> open watch
        self._reported: set[object] = set()
        self._open_missing_watches()

    def _open_missing_watches(self) -> None:
        """A target that can't be watched yet is still covered by the 60-second compare."""
        if self._poll_only:
            return
        openers = [(target, _RegistryWatch) for target in self._registry]
        openers += [(target, _FolderWatch) for target in self._folders]
        for target, opener in openers:
            if target in self._watches:
                continue
            try:
                self._watches[target] = opener(target)
                self._reported.discard(target)
            except pywintypes.error as error:
                if target not in self._reported:
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

        if result == win32event.WAIT_TIMEOUT:
            self._open_missing_watches()
            return False
        index = result - win32event.WAIT_OBJECT_0
        if index == 0:
            return False

        # Re-arm everything that fired, so one change can't cause a second empty rescan.
        self._rearm(watched[index - 1])
        for target in watched[index:]:
            event = self._watches[target].event
            if win32event.WaitForSingleObject(event, 0) == win32event.WAIT_OBJECT_0:
                self._rearm(target)
        return True
