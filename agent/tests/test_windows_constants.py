"""Windows constants, checked without Windows.

windows_watch.py defines its own constants because pywin32's win32con lacks some of
them, which only showed up as a crash in the VM. The expected values are the ones
Microsoft documents.
"""

import ast
from pathlib import Path

import pytest

import windows_watch

FIM_FOLDER = Path(windows_watch.__file__).parent
PYWIN32_MODULES = {"win32api", "win32con", "win32event", "win32file", "pywintypes"}

DOCUMENTED = {
    "HKEY_CURRENT_USER": 0x80000001 - 2**32,
    "HKEY_LOCAL_MACHINE": 0x80000002 - 2**32,
    "KEY_NOTIFY": 0x0010,
    "KEY_WOW64_64KEY": 0x0100,
    "REG_NOTIFY_CHANGE_NAME": 0x00000001,
    "REG_NOTIFY_CHANGE_LAST_SET": 0x00000004,
    "FILE_NOTIFY_CHANGE_FILE_NAME": 0x00000001,
    "FILE_NOTIFY_CHANGE_SIZE": 0x00000008,
    "FILE_NOTIFY_CHANGE_LAST_WRITE": 0x00000010,
    "FILE_LIST_DIRECTORY": 0x0001,
    "FILE_SHARE_READ": 0x00000001,
    "FILE_SHARE_WRITE": 0x00000002,
    "FILE_SHARE_DELETE": 0x00000004,
    "OPEN_EXISTING": 3,
    "FILE_FLAG_BACKUP_SEMANTICS": 0x02000000,
    "FILE_FLAG_OVERLAPPED": 0x40000000,
    "WAIT_OBJECT_0": 0,
    "WAIT_TIMEOUT": 0x102,
    "ERROR_ALREADY_EXISTS": 183,
}


@pytest.mark.parametrize("name,value", DOCUMENTED.items())
def test_constant_has_its_documented_value(name, value):
    assert getattr(windows_watch, name) == value


def test_filters_combine_the_expected_flags():
    assert windows_watch.REGISTRY_FILTER == 0x5
    assert windows_watch.APPEARANCE_FILTER == 0x1
    assert windows_watch.FOLDER_FILTER == 0x19
    assert windows_watch.FOLDER_SHARING == 0x7
    assert windows_watch.FOLDER_FLAGS == 0x42000000


def test_notify_roots_cover_every_registry_target():
    from targets import REGISTRY_TARGETS

    assert {target.root for target in REGISTRY_TARGETS} == set(windows_watch.NOTIFY_ROOTS)


@pytest.mark.parametrize("path", sorted(FIM_FOLDER.glob("*.py")), ids=lambda path: path.name)
def test_no_constant_is_read_from_pywin32(path):
    """Catches the crash here instead of in the VM: names can be missing from pywin32."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name == "win32con" for alias in node.names):
            problems.append(f"line {node.lineno}: imports win32con")
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in PYWIN32_MODULES
            and node.attr.isupper()
            and node.attr != "OVERLAPPED"  # a class, not a constant
        ):
            problems.append(f"line {node.lineno}: {node.value.id}.{node.attr}")
    assert problems == []
