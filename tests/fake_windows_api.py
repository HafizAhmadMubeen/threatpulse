"""An in-memory stand-in for policy.actions_windows.WindowsApi.

Paths are Windows strings compared without case, so the enforcement logic runs in WSL
exactly as it would in the VM. Nothing here touches the real machine.
"""

import hashlib
import json

from policy.actions_windows import ActionFailed, ProcessInfo, RegValue

LAB = "C:\\ThreatPulseLab"
ENV = {"APPDATA": "C:\\Users\\lab\\AppData\\Roaming", "PROGRAMDATA": "C:\\ProgramData", "SYSTEMROOT": "C:\\Windows"}


def key(path: str) -> str:
    return path.replace("/", "\\").lower()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeApi:
    def __init__(self, *, windows: bool = True, lab: bool = True, lab_dir: str = LAB):
        self.windows, self.lab, self.lab_dir = windows, lab, lab_dir
        self.files: dict[str, bytes] = {}
        self.processes: dict[int, ProcessInfo] = {}
        self.suspended: set[tuple[int, int]] = set()
        self.terminated: list[int] = []
        self.microsoft: dict[str, bool | None] = {}  # image -> the answer of the signature check
        self.verifier_calls: list[str] = []
        self.rules: dict[str, str] = {}
        self.registry: dict[tuple[str, str, str], RegValue] = {}
        self.cfa = "Disabled"
        self.own = 99999
        self.calls: list[tuple] = []
        self.fail_on: set[str] = set()  # method names that raise ActionFailed

    # -- helpers for tests
    def put(self, path: str, data: bytes) -> str:
        self.files[key(path)] = data
        return digest(data)

    def start(self, pid: int, image: str, created: int | None = None, *, microsoft_root: bool | None = False) -> None:
        self.processes[pid] = ProcessInfo(image, created if created is not None else 1000 + pid)
        self.microsoft[key(image)] = microsoft_root

    def set_reg(self, root, subkey, name, data, reg_type) -> None:
        self.registry[(root, subkey.lower(), name.lower())] = RegValue(data, reg_type)

    def get_reg(self, root, subkey, name):
        return self.registry.get((root, subkey.lower(), name.lower()))

    def write_baseline(self, layout, items: dict) -> None:
        self.put(layout.baseline, json.dumps({"created": "2026-11-07T00:00:00+00:00", "items": items}).encode())

    def journal_states(self, layout) -> list[tuple[str, str]]:
        text = self.files.get(key(layout.journal), b"").decode()
        return [(r["id"], r["state"]) for r in map(json.loads, text.splitlines())]

    def _check(self, name: str) -> None:
        self.calls.append((name,))
        if name in self.fail_on:
            raise ActionFailed(f"{name} failed (fake)")

    # -- environment
    def is_windows(self): return self.windows
    def environ(self): return dict(ENV)
    def own_pid(self): return self.own
    def marker_exists(self, path): return self.lab and key(path) == key(self.lab_dir + "\\LAB_VM")

    # -- files
    def exists(self, path):
        prefix = key(path).rstrip("\\") + "\\"
        return key(path) in self.files or any(f.startswith(prefix) for f in self.files)
    def is_file(self, path): return key(path) in self.files
    def sha256(self, path):
        data = self.files.get(key(path))
        return None if data is None else digest(data)
    def read_text(self, path): return self.files[key(path)].decode()
    def write_text(self, path, text): self.files[key(path)] = text.encode()
    def append_text(self, path, text): self.files[key(path)] = self.files.get(key(path), b"") + text.encode()
    def mkdir(self, path): pass
    def copy_file(self, source, destination):
        self._check("copy_file")
        self.files[key(destination)] = self.files[key(source)]
    def move_file(self, source, destination):
        self._check("move_file")
        self.files[key(destination)] = self.files.pop(key(source))
    def remove_file(self, path):
        self._check("remove_file")
        del self.files[key(path)]

    # -- processes
    def process_info(self, pid): return self.processes.get(pid)
    def _same(self, pid, created):
        info = self.processes.get(pid)
        if info is None or info.created != created:
            from policy.actions_windows import Refused
            raise Refused(f"pid {pid} is now a different process")
    def suspend(self, pid, created):
        self._same(pid, created); self._check("suspend"); self.suspended.add((pid, created))
    def resume(self, pid, created):
        self._same(pid, created); self._check("resume"); self.suspended.discard((pid, created))
    def terminate(self, pid, created):
        self._same(pid, created); self._check("terminate"); self.terminated.append(pid); del self.processes[pid]
    def microsoft_root(self, image, agent_exe):
        self.verifier_calls.append(image)
        return self.microsoft.get(key(image))

    # -- firewall
    def firewall_exists(self, name): return name in self.rules
    def firewall_add(self, name, program):
        self._check("firewall_add")
        if "firewall_add_silently_nothing" not in self.fail_on:
            self.rules[name] = program
    def firewall_remove(self, name):
        self._check("firewall_remove"); self.rules.pop(name, None)

    # -- registry
    def reg_read(self, root, subkey, name): return self.get_reg(root, subkey, name)
    def reg_write(self, root, subkey, name, data, reg_type):
        self._check("reg_write"); self.set_reg(root, subkey, name, data, reg_type)
    def reg_delete(self, root, subkey, name):
        self._check("reg_delete"); self.registry.pop((root, subkey.lower(), name.lower()), None)

    # -- Controlled Folder Access
    def cfa_get(self): return self.cfa
    def cfa_set(self, mode):
        self._check("cfa_set"); self.cfa = mode
