"""Builds valid Events for tests, one scenario at a time.

Events come out in the order they're added, which is not always time order, like the
agent's real output.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 11, 5, 9, 30, 0, tzinfo=timezone.utc)
RUN = "20261105T093000"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
DOCS = "C:\\Users\\lab\\Documents\\ThreatPulseTest"
RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test"


def stamp(seconds: float) -> str:
    moment = BASE + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


@dataclass
class P:
    pid: int
    ppid: int
    image: str
    cmdline: str | None = None
    signed: bool = True


class Recording:
    def __init__(self):
        self.events: list[dict] = []
        self.counter = 0
        self.fim_counter = 900000000

    def add(self, proc: P, event_type: str, seconds: float, source: str = "etw", **target) -> dict:
        self.counter += 1
        fields = {
            "path": None, "old_path": None, "registry_key": None, "pid": None,
            "access_mask": None, "access_rights": None, "dest_ip": None, "dest_port": None,
            "change": None,
        }
        fields.update(target)
        event = {
            "event_id": f"e-{RUN}-{self.counter:06d}",
            "ts": stamp(seconds),
            "host": "lab-vm-01",
            "source": source,
            "event_type": event_type,
            "pid": proc.pid,
            "ppid": proc.ppid,
            "process": {
                "image": proc.image,
                "cmdline": proc.cmdline,
                "user": "LAB-VM-01\\lab",
                "sha256": None,
                "signed": proc.signed,
                "signer": "Microsoft Windows" if proc.signed else None,
            },
            "target": fields,
        }
        self.events.append(event)
        return event

    def start(self, proc: P, seconds: float) -> dict:
        return self.add(proc, "process_start", seconds)

    def stop(self, proc: P, seconds: float) -> dict:
        return self.add(proc, "process_stop", seconds)

    def fim(self, seconds: float, kind: str = "added", **target) -> dict:
        self.fim_counter += 1
        fields = {
            "path": None, "old_path": None, "registry_key": None, "pid": None,
            "access_mask": None, "access_rights": None, "dest_ip": None, "dest_port": None,
            "change": {"kind": kind, "old_value": None, "new_value": "value"},
        }
        fields.update(target)
        event = {
            "event_id": f"e-20261105T092955-{self.fim_counter}",
            "ts": stamp(seconds),
            "host": "lab-vm-01",
            "source": "fim",
            "event_type": "fim_change",
            "pid": 0,
            "ppid": 0,
            "process": {
                "image": "unknown", "cmdline": None, "user": None, "sha256": None,
                "signed": False, "signer": None,
            },
            "target": fields,
        }
        self.events.append(event)
        return event
