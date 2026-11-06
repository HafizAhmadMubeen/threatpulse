"""Enforcement actions for the lab VM (PHASES.md step 3.2). Windows-only code.

Generation: 4th, access control. `policy.decide` plans, this module acts, and every action
here has the same shape:

  1. the VM guard: refuse unless this is Windows and C:\\ThreatPulseLab\\LAB_VM exists
  2. the never-suspend list, re-checked against the LIVE process just before acting
     (full path + a Microsoft-rooted signature, never the name)
  3. a write-ahead journal entry holding what the undo needs
  4. the action, then a check that it took effect
  5. an undo that reads the journal

All operating-system calls live in `WindowsApi`, so the logic above can be unit-tested in
WSL with a fake. Importing this module touches nothing: the real calls import `winreg` and
use `ctypes.windll` only when they run, and each of them refuses on a non-Windows system.

This module never imports from `backend/` and never reads model output (CLAUDE.md design
rule 1). Nothing here is ever run on the host.
"""

import hashlib
import json
import ntpath
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from policy import paths
from policy.engine import protection
from policy.loader import Policy

LAB_DIR = "C:\\ThreatPulseLab"

# Registry value types (winreg's constants don't exist outside Windows).
REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 0, 1, 2, 3, 4, 7, 11

# The persistence zone that `restore` may touch: the same items agent/fim/targets.py
# watches. A test keeps the two lists in step. (root, subkey, subtree)
PERSISTENCE_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", False),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", False),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", False),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", False),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", True),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", False),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", False),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx", True),
)
STARTUP_SUFFIX = r"Microsoft\Windows\Start Menu\Programs\Startup"
HOSTS_SUFFIX = r"System32\drivers\etc\hosts"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
RULE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
PROGRAM_PATH = re.compile(r'^[A-Za-z]:\\[^"<>|*?\r\n\x00]+$')
CFA_MODES = {"0": "Disabled", "1": "Enabled", "2": "AuditMode"}


class Refused(Exception):
    """A safety check said no, so nothing was attempted. Becomes `skipped` (and for a
    request action, which has no skipped status, `failed`) with this text as the reason."""


class ActionFailed(Exception):
    """The action was attempted and did not work. Becomes `failed`."""


class NotWindows(Refused):
    """A real Windows call was made on a system that isn't Windows."""


# ---- where things live ------------------------------------------------------------


@dataclass(frozen=True)
class Layout:
    """The lab's folders. Tests pass another root; the default is the VM's."""

    lab_dir: str = LAB_DIR

    @property
    def marker(self) -> str:
        return ntpath.join(self.lab_dir, "LAB_VM")

    @property
    def fim_dir(self) -> str:
        return ntpath.join(self.lab_dir, "fim")

    @property
    def baseline(self) -> str:
        return ntpath.join(self.fim_dir, "baseline.json")

    @property
    def stored_files(self) -> str:
        return ntpath.join(self.fim_dir, "files")

    @property
    def quarantine(self) -> str:
        return ntpath.join(self.fim_dir, "quarantine")

    @property
    def enforcement_dir(self) -> str:
        return ntpath.join(self.lab_dir, "enforcement")

    @property
    def journal(self) -> str:
        return ntpath.join(self.enforcement_dir, "journal.jsonl")

    @property
    def repo_dir(self) -> str:
        return ntpath.join(self.lab_dir, "threatpulse")

    @property
    def agent_exe(self) -> str:
        return ntpath.join(self.repo_dir, "agent", "build", "Release", "threatpulse_agent.exe")


@dataclass(frozen=True)
class ProcessInfo:
    image: str | None  # None when the live path could not be read
    created: int | None  # creation time as a FILETIME, with the pid it identifies a process


@dataclass(frozen=True)
class RegValue:
    data: Any
    reg_type: int


# ---- the operating system ---------------------------------------------------------


class WindowsApi:
    """Every call that touches the machine. Nothing else in this package may.

    The file helpers are plain stdlib and work anywhere. The process, registry, firewall
    and Defender calls need Windows and refuse with NotWindows otherwise.
    """

    # -- environment

    def is_windows(self) -> bool:
        return sys.platform == "win32"

    def environ(self) -> dict[str, str]:
        return dict(os.environ)

    def own_pid(self) -> int:
        return os.getpid()

    def _need_windows(self) -> None:
        if not self.is_windows():
            raise NotWindows("not Windows: a real enforcement call was refused")

    # -- files (path-agnostic)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def sha256(self, path: str) -> str | None:
        """The file's SHA-256, or None if it doesn't exist."""
        try:
            with open(path, "rb") as file:
                return hashlib.file_digest(file, "sha256").hexdigest()
        except FileNotFoundError:
            return None

    def read_text(self, path: str) -> str:
        with open(path, encoding="utf-8") as file:
            return file.read()

    def write_text(self, path: str, text: str) -> None:
        """Write whole, through a temporary file, so a crash can't leave half a file."""
        partial = path + ".tmp"
        with open(partial, "w", encoding="utf-8", newline="\n") as file:
            file.write(text)
        os.replace(partial, path)

    def append_text(self, path: str, text: str) -> None:
        with open(path, "a", encoding="utf-8", newline="\n") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())

    def mkdir(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

    def copy_file(self, source: str, destination: str) -> None:
        import shutil

        shutil.copyfile(source, destination)

    def move_file(self, source: str, destination: str) -> None:
        import shutil

        shutil.move(source, destination)

    def remove_file(self, path: str) -> None:
        os.remove(path)

    # -- the VM guard

    def marker_exists(self, path: str) -> bool:
        return os.path.isfile(path)

    # -- processes

    def _kernel32(self):
        import ctypes
        from ctypes import wintypes

        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        k.GetProcessTimes.restype = wintypes.BOOL
        k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k.GetExitCodeProcess.restype = wintypes.BOOL
        k.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.TerminateProcess.restype = wintypes.BOOL
        return k

    def _ntdll(self):
        import ctypes
        from ctypes import wintypes

        n = ctypes.WinDLL("ntdll")
        for name in ("NtSuspendProcess", "NtResumeProcess"):
            getattr(n, name).argtypes = [wintypes.HANDLE]
            getattr(n, name).restype = ctypes.c_long  # NTSTATUS, 0 is success
        return n

    def _open(self, pid: int, access: int):
        import ctypes

        k = self._kernel32()
        handle = k.OpenProcess(access, False, pid)
        if not handle:
            return k, None, ctypes.get_last_error()
        return k, handle, 0

    def _created(self, k, handle) -> int:
        import ctypes
        from ctypes import wintypes

        times = [wintypes.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            raise ActionFailed("could not read the process creation time")
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime

    def process_info(self, pid: int) -> ProcessInfo | None:
        """None if there is no running process with this pid."""
        self._need_windows()
        import ctypes
        from ctypes import wintypes

        k, handle, error = self._open(pid, 0x1000)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle is None:
            if error == 87:  # ERROR_INVALID_PARAMETER: no such pid
                return None
            return ProcessInfo(None, None)  # exists, but we may not look at it
        try:
            code = wintypes.DWORD()
            if k.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != 259:  # STILL_ACTIVE
                return None
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            image = buffer.value if k.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)) else None
            return ProcessInfo(image, self._created(k, handle))
        finally:
            k.CloseHandle(handle)

    def _with_process(self, pid: int, created: int, access: int, what: str, operation) -> None:
        """Open the process, check it is still the one we checked, then act on that handle.
        This closes the gap in which a pid could be reused between the check and the act."""
        self._need_windows()
        k, handle, error = self._open(pid, access | 0x1000)
        if handle is None:
            raise ActionFailed(f"{what}: cannot open pid {pid} (Windows error {error})")
        try:
            if self._created(k, handle) != created:
                raise Refused(f"{what}: pid {pid} is now a different process")
            operation(k, handle)
        finally:
            k.CloseHandle(handle)

    def suspend(self, pid: int, created: int) -> None:
        def run(k, handle):
            status = self._ntdll().NtSuspendProcess(handle)
            if status != 0:
                raise ActionFailed(f"NtSuspendProcess failed: 0x{status & 0xFFFFFFFF:08X}")
        self._with_process(pid, created, 0x0800, "suspend", run)  # PROCESS_SUSPEND_RESUME

    def resume(self, pid: int, created: int) -> None:
        def run(k, handle):
            status = self._ntdll().NtResumeProcess(handle)
            if status != 0:
                raise ActionFailed(f"NtResumeProcess failed: 0x{status & 0xFFFFFFFF:08X}")
        self._with_process(pid, created, 0x0800, "resume", run)

    def terminate(self, pid: int, created: int) -> None:
        def run(k, handle):
            if not k.TerminateProcess(handle, 1):
                raise ActionFailed("TerminateProcess failed")
        self._with_process(pid, created, 0x0001, "terminate", run)  # PROCESS_TERMINATE

    def microsoft_root(self, image: str, agent_exe: str) -> bool | None:
        """Ask the agent's own checker whether the file's signature verified and chains to
        a Microsoft root. None means it could not be decided, which callers treat as unknown."""
        self._need_windows()
        try:
            run = subprocess.run([agent_exe, "--check-image", image], capture_output=True,
                                 text=True, timeout=30, check=False, shell=False)
        except (OSError, subprocess.SubprocessError):
            return None
        verified = re.search(r"Verified signature:\s*(yes|no)", run.stdout)
        root = re.search(r"Microsoft root:\s*(yes|no)", run.stdout)
        if run.returncode != 0 or not verified or not root:
            return None
        return verified.group(1) == "yes" and root.group(1) == "yes"

    # -- firewall (netsh, with an argument list and no shell)

    def _run(self, program: str, arguments: list[str], *, allow_failure: bool = False) -> int:
        self._need_windows()
        run = subprocess.run([program, *arguments], capture_output=True, text=True,
                             timeout=60, check=False, shell=False)
        if run.returncode != 0 and not allow_failure:
            detail = (run.stdout + run.stderr).strip().replace("\n", " ")[:300]
            raise ActionFailed(f"{ntpath.basename(program)} exited {run.returncode}: {detail}")
        return run.returncode

    def _netsh(self) -> str:
        return ntpath.join(self.environ().get("SYSTEMROOT", r"C:\Windows"), "System32", "netsh.exe")

    def firewall_exists(self, name: str) -> bool:
        return self._run(self._netsh(), ["advfirewall", "firewall", "show", "rule", f"name={name}"],
                         allow_failure=True) == 0

    def firewall_add(self, name: str, program: str) -> None:
        self._run(self._netsh(), ["advfirewall", "firewall", "add", "rule", f"name={name}",
                                  "dir=out", "action=block", f"program={program}",
                                  "enable=yes", "profile=any"])

    def firewall_remove(self, name: str) -> None:
        self._run(self._netsh(), ["advfirewall", "firewall", "delete", "rule", f"name={name}"])

    # -- registry (64-bit view, like FIM)

    def _hive(self, root: str):
        self._need_windows()
        import winreg

        return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[root]

    def reg_read(self, root: str, subkey: str, name: str) -> RegValue | None:
        self._need_windows()
        import winreg

        try:
            with winreg.OpenKey(self._hive(root), subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                data, reg_type = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return None
        return RegValue(data, reg_type)

    def reg_write(self, root: str, subkey: str, name: str, data: Any, reg_type: int) -> None:
        self._need_windows()
        import winreg

        access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        with winreg.CreateKeyEx(self._hive(root), subkey, 0, access) as key:
            winreg.SetValueEx(key, name, 0, reg_type, data)

    def reg_delete(self, root: str, subkey: str, name: str) -> None:
        self._need_windows()
        import winreg

        try:
            with winreg.OpenKey(self._hive(root), subkey, 0,
                                winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass

    # -- Controlled Folder Access

    def _powershell(self) -> str:
        return ntpath.join(self.environ().get("SYSTEMROOT", r"C:\Windows"),
                           "System32", "WindowsPowerShell", "v1.0", "powershell.exe")

    def cfa_get(self) -> str:
        self._need_windows()
        run = subprocess.run([self._powershell(), "-NoProfile", "-NonInteractive", "-Command",
                              "(Get-MpPreference).EnableControlledFolderAccess"],
                             capture_output=True, text=True, timeout=60, check=False, shell=False)
        mode = CFA_MODES.get(run.stdout.strip())
        if run.returncode != 0 or mode is None:
            raise ActionFailed(f"could not read the Controlled Folder Access setting: {run.stdout.strip()[:100]}")
        return mode

    def cfa_set(self, mode: str) -> None:
        if mode not in CFA_MODES.values():  # the only text that ever reaches the command line
            raise ActionFailed(f"not a Controlled Folder Access mode: {mode!r}")
        self._run(self._powershell(), ["-NoProfile", "-NonInteractive", "-Command",
                                       f"Set-MpPreference -EnableControlledFolderAccess {mode}"])


# ---- registry values <-> the text FIM stores --------------------------------------


def encode_value(data: Any) -> str:
    """The text FIM's baseline keeps for a registry value (agent/fim/baseline.py). A test
    checks that the two stay the same."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        return "\n".join(str(entry) for entry in data)
    return str(data)


def decode_value(text: str, reg_type: int) -> Any:
    """Back from the baseline's text to what winreg wants. A MULTI_SZ with empty strings
    in it does not survive FIM's encoding, which is a limit of the baseline format."""
    if reg_type in (REG_SZ, REG_EXPAND_SZ):
        return text
    if reg_type in (REG_DWORD, REG_QWORD):
        return int(text)
    if reg_type == REG_MULTI_SZ:
        return text.split("\n") if text else []
    return bytes.fromhex(text)


def pack(data: Any) -> dict:
    """A registry value as JSON, in full (the quarantine keeps the whole value)."""
    if isinstance(data, bytes):
        return {"kind": "bytes", "value": data.hex()}
    if isinstance(data, list):
        return {"kind": "list", "value": [str(entry) for entry in data]}
    if isinstance(data, int) and not isinstance(data, bool):
        return {"kind": "int", "value": data}
    return {"kind": "str", "value": "" if data is None else str(data)}


def unpack(packed: dict) -> Any:
    kind, value = packed["kind"], packed["value"]
    return bytes.fromhex(value) if kind == "bytes" else value


# ---- scope and process checks (pure logic) ----------------------------------------


def split_registry_item(item: str) -> tuple[str, str, str] | None:
    """`HKCU\\...\\Run\\Name` -> (root, key, value name), or None if it is not in the
    persistence zone. RunOnceEx keeps its values in numbered subkeys."""
    for root, subkey, subtree in PERSISTENCE_KEYS:
        prefix = f"{root}\\{subkey}\\"
        if not item.lower().startswith(prefix.lower()) or len(item) == len(prefix):
            continue
        rest = item[len(prefix):]
        key = subkey
        if subtree and "\\" in rest:
            *below, rest = rest.split("\\")
            key = subkey + "\\" + "\\".join(below)
        return root, key, "" if rest == "(Default)" else rest
    return None


def file_in_scope(path: str, env: dict[str, str]) -> bool:
    """A file directly in a startup folder, or the hosts file. Nothing else is restorable."""
    actual = paths.normalise(path)
    if actual is None:
        return False
    for variable in ("APPDATA", "PROGRAMDATA"):
        if variable in env:
            folder = paths.normalise(ntpath.join(env[variable], STARTUP_SUFFIX))
            if folder is not None and actual[:-1] == folder:
                return True
    if "SYSTEMROOT" in env:
        return actual == paths.normalise(ntpath.join(env["SYSTEMROOT"], HOSTS_SUFFIX))
    return False


def under(tree: str, path: str) -> bool:
    folder, actual = paths.normalise(tree), paths.normalise(path)
    return folder is not None and actual is not None and actual[:len(folder)] == folder


def same_path(first: str, second: str) -> bool:
    a, b = paths.normalise(first), paths.normalise(second)
    return a is not None and a == b


# ---- the journal ------------------------------------------------------------------


class Journal:
    """An append-only record of what was done and what undoes it. An entry is written
    BEFORE the change (state `started`), then `done`, `failed` or `undone`."""

    def __init__(self, api, layout: Layout):
        self.api, self.layout = api, layout

    def append(self, entry: dict) -> None:
        self.api.mkdir(self.layout.enforcement_dir)
        self.api.append_text(self.layout.journal, json.dumps(entry, sort_keys=True) + "\n")

    def entries(self) -> dict[str, dict]:
        """Each action's first record merged with its latest state."""
        merged: dict[str, dict] = {}
        if not self.api.exists(self.layout.journal):
            return merged
        for number, line in enumerate(self.api.read_text(self.layout.journal).splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ActionFailed(f"{self.layout.journal} line {number} is not valid JSON") from error
            entry = merged.setdefault(record["id"], {})
            entry.update(record)
        return merged

    def active(self, decision_id: str | None = None) -> list[dict]:
        # `failed` stays undoable: a change that broke half-way may have left something behind.
        found = [e for e in self.entries().values() if e["state"] in ("started", "done", "failed")]
        if decision_id is not None:
            found = [e for e in found if e["decision_id"] == decision_id]
        return found

    def suspended(self, pid: int, created: int | None) -> bool:
        return any(e["action"] == "suspend" and e["undo"]["pid"] == pid and e["undo"]["created"] == created
                   for e in self.active())


@dataclass
class Ctx:
    """What one action needs. `begun` tells the caller whether anything was journaled."""

    api: Any
    policy: Policy
    layout: Layout
    alert: dict
    decision_id: str
    index: int
    now: str
    journal: Journal
    begun: bool = False

    @property
    def entry_id(self) -> str:
        return f"{self.decision_id}#{self.index}"

    @property
    def quarantine_dir(self) -> str:
        return ntpath.join(self.layout.quarantine, f"{self.decision_id}-{self.index}")

    def begin(self, action: str, undo: dict) -> None:
        self.journal.append({"id": self.entry_id, "decision_id": self.decision_id, "index": self.index,
                             "action": action, "state": "started", "ts": self.now, "undo": undo})
        self.begun = True

    def finish(self, state: str) -> None:
        self.journal.append({"id": self.entry_id, "decision_id": self.decision_id, "index": self.index,
                             "state": state, "ts": self.now})


def lab_guard(api, layout: Layout) -> str | None:
    """None when this is the lab VM. Otherwise why not."""
    if not api.is_windows():
        return "not in lab VM: this is not Windows"
    if not api.marker_exists(layout.marker):
        return f"not in lab VM: {layout.marker} is missing"
    return None


def require_lab(ctx: Ctx) -> None:
    why = lab_guard(ctx.api, ctx.layout)
    if why:
        raise Refused(why)


def live_process(ctx: Ctx, target: dict, *, must_exist: bool) -> ProcessInfo | None:
    """The process the decision named, as it is now. Refuses a reused pid."""
    pid, image = target["pid"], target["image"]
    if pid <= 4:
        raise Refused(f"pid {pid} is a system process")
    if pid == ctx.api.own_pid():
        raise Refused("that is the enforcement process itself")
    info = ctx.api.process_info(pid)
    if info is None:
        if must_exist:
            raise Refused("process already exited")
        return None
    if info.image is None:
        raise Refused("the live image path can't be read, so it can't be checked against the never-suspend list")
    if not same_path(info.image, image):
        raise Refused(f"pid {pid} now runs {info.image}, not {image}")
    return info


def check_not_critical(ctx: Ctx, pid: int, image: str) -> None:
    """The never-suspend list, against the live file. A path that is not on the list needs
    no signature check. A path that is on it is protected unless the file's signature
    verified AND chains to a Microsoft root and the entry asks only for that; if the check
    can't be done, the process counts as protected."""
    if protection(ctx.policy, image, pid, None) is None:
        return
    try:
        root = ctx.api.microsoft_root(image, ctx.layout.agent_exe)
    except Exception:
        root = None
    why = protection(ctx.policy, image, pid, root)
    if why:
        raise Refused(why)


def program_path(image: str) -> str:
    if not PROGRAM_PATH.match(image) or paths.normalise(image) is None:
        raise Refused(f"not an absolute program path: {image!r}")
    return image


# ---- suspend, block_network, request_kill -----------------------------------------


def need_target(act: dict) -> dict:
    if "target" not in act:
        raise Refused("the action names no process")
    return act["target"]


def do_suspend(ctx: Ctx, act: dict) -> None:
    require_lab(ctx)
    target = need_target(act)
    info = live_process(ctx, target, must_exist=True)
    check_not_critical(ctx, target["pid"], info.image)
    if ctx.journal.suspended(target["pid"], info.created):
        raise Refused("already suspended by ThreatPulse")
    ctx.begin("suspend", {"pid": target["pid"], "image": info.image, "created": info.created})
    ctx.api.suspend(target["pid"], info.created)


def do_block_network(ctx: Ctx, act: dict) -> None:
    require_lab(ctx)
    target = need_target(act)
    info = live_process(ctx, target, must_exist=False)  # the rule is per program: an exited process is fine
    image = program_path(info.image if info else target["image"])
    if not ctx.api.is_file(image):
        raise Refused(f"the program file {image} does not exist")
    check_not_critical(ctx, target["pid"], image)
    name = f"ThreatPulse-Block-{ctx.decision_id}-{ctx.index}"
    if not RULE_NAME.match(name):
        raise Refused(f"unsafe firewall rule name {name!r}")
    if ctx.api.firewall_exists(name):
        raise Refused(f"firewall rule {name} already exists")
    ctx.begin("block_network", {"rule": name, "image": image})
    ctx.api.firewall_add(name, image)
    if not ctx.api.firewall_exists(name):
        raise ActionFailed(f"firewall rule {name} was not found after adding it")


def do_kill(ctx: Ctx, act: dict) -> None:
    """Only reached for an approved request. Terminating can't be undone, so the process
    must be the very one ThreatPulse suspended (same pid and creation time)."""
    require_lab(ctx)
    target = need_target(act)
    info = live_process(ctx, target, must_exist=True)
    check_not_critical(ctx, target["pid"], info.image)
    if not ctx.journal.suspended(target["pid"], info.created):
        raise Refused("the process is not one that ThreatPulse suspended")
    ctx.begin("request_kill", {"pid": target["pid"], "image": info.image, "created": info.created,
                               "irreversible": True})
    ctx.api.terminate(target["pid"], info.created)


# ---- restore ----------------------------------------------------------------------


def load_baseline(ctx: Ctx) -> dict[str, dict]:
    if not ctx.api.exists(ctx.layout.baseline):
        raise ActionFailed(f"no FIM baseline at {ctx.layout.baseline}")
    try:
        items = json.loads(ctx.api.read_text(ctx.layout.baseline))["items"]
    except (ValueError, KeyError) as error:
        raise ActionFailed(f"the FIM baseline can't be read: {error}") from error
    return {name.lower(): {**item, "name": name} for name, item in items.items()}


def write_manifest(ctx: Ctx, manifest: dict) -> str:
    path = ntpath.join(ctx.quarantine_dir, "manifest.json")
    if ctx.api.exists(path):
        raise Refused(f"{ctx.quarantine_dir} already holds a quarantined item for this action")
    ctx.api.mkdir(ctx.quarantine_dir)
    ctx.api.write_text(path, json.dumps(manifest, indent=2, sort_keys=True))
    return path


def restore_registry(ctx: Ctx, item_name: str) -> None:
    location = split_registry_item(item_name)
    if location is None:
        raise Refused(f"{item_name} is not in the persistence zone, so it is not restored")
    root, key, value_name = location
    api = ctx.api
    desired = load_baseline(ctx).get(item_name.lower())
    if desired is not None and (desired["kind"] != "registry" or desired.get("reg_type") is None):
        raise Refused("the baseline item is not a restorable registry value")
    current = api.reg_read(root, key, value_name)
    if desired is None and current is None:
        raise Refused("the value is absent and the baseline has none: nothing to restore")
    if desired is not None and current is not None and current.reg_type == desired["reg_type"] \
            and encode_value(current.data) == desired["value"]:
        raise Refused("the value already matches the baseline")

    before = None if current is None else {"reg_type": current.reg_type, **pack(current.data)}
    manifest_path = write_manifest(ctx, {
        "version": 1, "kind": "registry", "decision_id": ctx.decision_id, "index": ctx.index,
        "item": item_name, "root": root, "key": key, "value_name": value_name,
        "before": before, "made": "baseline value" if desired else "removed (not in the baseline)",
    })
    ctx.begin("restore", {"manifest": manifest_path})
    if desired is None:
        api.reg_delete(root, key, value_name)
        if api.reg_read(root, key, value_name) is not None:
            raise ActionFailed("the value was still there after deleting it")
    else:
        api.reg_write(root, key, value_name, decode_value(desired["value"], desired["reg_type"]), desired["reg_type"])
        again = api.reg_read(root, key, value_name)
        if again is None or again.reg_type != desired["reg_type"] or encode_value(again.data) != desired["value"]:
            raise ActionFailed("the value does not match the baseline after writing it")


def restore_file(ctx: Ctx, path: str) -> None:
    api = ctx.api
    if not file_in_scope(path, api.environ()):
        raise Refused(f"{path} is not a startup-folder file or the hosts file, so it is not restored")
    wanted = paths.normalise(path)
    desired = next((i for i in load_baseline(ctx).values()
                    if i["kind"] == "file" and paths.normalise(i["name"]) == wanted), None)
    if desired is not None and not SHA256.match(desired["value"]):
        raise Refused("the baseline item is not a restorable file")
    current_hash = api.sha256(path)
    if desired is None and current_hash is None:
        raise Refused("the file is absent and the baseline has none: nothing to restore")
    if desired is not None and current_hash == desired["value"]:
        raise Refused("the file already matches the baseline")
    stored = None
    if desired is not None:
        stored = ntpath.join(ctx.layout.stored_files, desired["value"])
        if api.sha256(stored) != desired["value"]:
            raise ActionFailed(f"the baseline copy {stored} is missing or does not match its hash")

    data_path = ntpath.join(ctx.quarantine_dir, "data.bin")
    manifest = {"version": 1, "kind": "file", "decision_id": ctx.decision_id, "index": ctx.index,
                "item": path, "before": None if current_hash is None else {"sha256": current_hash, "stored": data_path},
                "made": "baseline copy" if desired else "removed (not in the baseline)"}
    manifest_path = write_manifest(ctx, manifest)
    ctx.begin("restore", {"manifest": manifest_path})
    if current_hash is not None:
        api.copy_file(path, data_path)
        if api.sha256(data_path) != current_hash:
            raise ActionFailed("the quarantine copy does not match the file, so nothing was changed")
    if desired is None:
        api.remove_file(path)
        if api.exists(path):
            raise ActionFailed("the file was still there after removing it")
    else:
        api.copy_file(stored, path)
        if api.sha256(path) != desired["value"]:
            raise ActionFailed("the file does not match the baseline after restoring it")


def do_restore(ctx: Ctx, act: dict) -> None:
    require_lab(ctx)
    obj = ctx.alert["object"]
    if obj["zone"] != "persistence":
        raise Refused("the alert is not in the persistence zone")
    if obj["registry_key"]:
        restore_registry(ctx, obj["registry_key"])
    elif obj["path"]:
        restore_file(ctx, obj["path"])
    else:
        raise Refused("the alert names no registry value or file")


# ---- request_delete: move to quarantine -------------------------------------------


def do_delete(ctx: Ctx, act: dict) -> None:
    """Only reached for an approved request. The file is moved into quarantine, not erased,
    so the undo can put it back."""
    require_lab(ctx)
    api, obj = ctx.api, ctx.alert["object"]
    path, expected = obj["path"], obj["file_sha256"]
    if not path or program_path(path) != path:
        raise Refused("the alert names no usable file path")
    if expected is None or not SHA256.match(expected):
        raise Refused("the alert has no file_sha256, so the flagged file can't be identified")
    layout = ctx.layout
    env = api.environ()
    for tree in (env.get("SYSTEMROOT", r"C:\Windows"), layout.fim_dir, layout.enforcement_dir, layout.repo_dir):
        if under(tree, path):
            raise Refused(f"{path} is inside {tree}, which is never deleted")
    if same_path(path, layout.marker) or any(
            paths.matches(path, e.path) for e in ctx.policy.never_suspend if not e.system):
        raise Refused("the file is on the never-suspend list")
    actual = api.sha256(path)
    if actual is None:
        raise Refused("the file no longer exists")
    if actual != expected:
        raise Refused("the file has changed since it was flagged (its SHA-256 differs)")

    data_path = ntpath.join(ctx.quarantine_dir, "data.bin")
    manifest_path = write_manifest(ctx, {
        "version": 1, "kind": "delete", "decision_id": ctx.decision_id, "index": ctx.index,
        "item": path, "before": {"sha256": actual, "stored": data_path}})
    ctx.begin("request_delete", {"manifest": manifest_path})
    api.move_file(path, data_path)
    if api.sha256(data_path) != expected or api.exists(path):
        raise ActionFailed("the file did not arrive in quarantine intact")


# ---- Controlled Folder Access (setup, not a decision action) ----------------------


def set_up_controlled_folder_access(api, layout: Layout, policy: Policy, now: str) -> str:
    """Turn Controlled Folder Access on in the lab VM and journal the previous mode, so
    `undo` can put it back. Never called by execute(), and not to be done before taking a
    recording snapshot: it would change what the VM does to every dummy-file test."""
    why = lab_guard(api, layout)
    if why:
        raise Refused(why)
    journal = Journal(api, layout)
    index = sum(1 for e in journal.entries().values() if e["action"] == "controlled_folder_access")
    ctx = Ctx(api, policy, layout, {}, "setup", index, now, journal)
    previous = api.cfa_get()
    if previous == "Enabled":
        raise Refused("Controlled Folder Access is already enabled")
    ctx.begin("controlled_folder_access", {"previous": previous})
    try:
        api.cfa_set("Enabled")
        if api.cfa_get() != "Enabled":
            raise ActionFailed("Controlled Folder Access is not enabled after setting it")
    except Exception:
        ctx.finish("failed")
        raise
    ctx.finish("done")
    return previous


# ---- undo -------------------------------------------------------------------------


def undo_restore_item(ctx: Ctx, manifest: dict) -> None:
    api, before = ctx.api, manifest["before"]
    if manifest["kind"] == "registry":
        root, key, name = manifest["root"], manifest["key"], manifest["value_name"]
        if before is None:
            api.reg_delete(root, key, name)
        else:
            api.reg_write(root, key, name, unpack(before), before["reg_type"])
        return
    item = manifest["item"]
    if before is None:
        if api.exists(item):
            api.remove_file(item)
        return
    if api.sha256(before["stored"]) != before["sha256"]:
        raise ActionFailed("the quarantined copy is missing or does not match its hash")
    if manifest["kind"] == "delete":
        if api.exists(item):
            raise ActionFailed(f"{item} exists again, so the quarantined file is not moved over it")
        api.move_file(before["stored"], item)
    else:
        api.copy_file(before["stored"], item)
    if api.sha256(item) != before["sha256"]:
        raise ActionFailed("the file does not match the quarantined copy after putting it back")


def undo_entry(ctx: Ctx, entry: dict) -> str:
    """Undo one journaled action. Returns a short note. Raises ActionFailed or Refused."""
    require_lab(ctx)
    api, undo = ctx.api, entry["undo"]
    action = entry["action"]
    if action == "suspend":
        info = api.process_info(undo["pid"])
        if info is None:
            return "the process had already exited"
        if info.created != undo["created"]:
            return "the pid belongs to another process now, so nothing was resumed"
        api.resume(undo["pid"], undo["created"])
        return "resumed"
    if action == "block_network":
        if not api.firewall_exists(undo["rule"]):
            return "the firewall rule was already gone"
        api.firewall_remove(undo["rule"])
        if api.firewall_exists(undo["rule"]):
            raise ActionFailed("the firewall rule was still there after removing it")
        return "firewall rule removed"
    if action in ("restore", "request_delete"):
        manifest = json.loads(api.read_text(undo["manifest"]))
        undo_restore_item(ctx, manifest)
        return "put back from quarantine"
    if action == "controlled_folder_access":
        api.cfa_set(undo["previous"])
        return f"set back to {undo['previous']}"
    if action == "request_kill":
        raise Refused("terminating a process can't be undone")
    raise Refused(f"no undo is defined for {action}")
