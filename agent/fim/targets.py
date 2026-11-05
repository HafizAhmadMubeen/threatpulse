"""What FIM watches: the persistence zone from PLANNING.md Section 2."""

import ntpath
from collections.abc import Mapping
from dataclasses import dataclass

_RUN = r"Microsoft\Windows\CurrentVersion"
_STARTUP = r"Microsoft\Windows\Start Menu\Programs\Startup"


@dataclass(frozen=True)
class RegistryTarget:
    root: str  # HKCU or HKLM
    subkey: str

    @property
    def name(self) -> str:
        return f"{self.root}\\{self.subkey}"


@dataclass(frozen=True)
class FolderTarget:
    path: str
    only_file: str | None = None  # lowercase. None means every file in the folder.


# The WOW6432Node keys are where 32-bit programs' Run entries land, and they run at
# logon too. HKCU has no separate copy of these keys.
REGISTRY_TARGETS = (
    RegistryTarget("HKCU", rf"Software\{_RUN}\Run"),
    RegistryTarget("HKCU", rf"Software\{_RUN}\RunOnce"),
    RegistryTarget("HKLM", rf"SOFTWARE\{_RUN}\Run"),
    RegistryTarget("HKLM", rf"SOFTWARE\{_RUN}\RunOnce"),
    RegistryTarget("HKLM", rf"SOFTWARE\WOW6432Node\{_RUN}\Run"),
    RegistryTarget("HKLM", rf"SOFTWARE\WOW6432Node\{_RUN}\RunOnce"),
)


def folder_targets(environ: Mapping[str, str]) -> tuple[FolderTarget, ...]:
    """The folders to watch. APPDATA makes the per-user one depend on who runs FIM."""
    return (
        FolderTarget(ntpath.join(environ["APPDATA"], _STARTUP)),
        FolderTarget(ntpath.join(environ["PROGRAMDATA"], _STARTUP)),
        FolderTarget(ntpath.join(environ["SYSTEMROOT"], r"System32\drivers\etc"), "hosts"),
    )
