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
    subtree: bool = False  # also read and watch every subkey, not only this key's values
    optional: bool = False  # normally missing, so no warning when it can't be watched yet

    @property
    def name(self) -> str:
        return f"{self.root}\\{self.subkey}"


@dataclass(frozen=True)
class FolderTarget:
    path: str
    only_file: str | None = None  # lowercase. None means every file in the folder.


# The WOW6432Node keys are where 32-bit programs' Run entries land, and they run at
# logon too. HKCU has no separate copy of these keys.
#
# RunOnceEx keeps its values in numbered subkeys (RunOnceEx\0001\Depend), so it is read
# and watched as a subtree. It doesn't exist until something creates it. HKCU's RunOnceEx
# is not watched.
REGISTRY_TARGETS = (
    RegistryTarget("HKCU", rf"Software\{_RUN}\Run"),
    RegistryTarget("HKCU", rf"Software\{_RUN}\RunOnce"),
    RegistryTarget("HKLM", rf"SOFTWARE\{_RUN}\Run"),
    RegistryTarget("HKLM", rf"SOFTWARE\{_RUN}\RunOnce"),
    RegistryTarget("HKLM", rf"SOFTWARE\{_RUN}\RunOnceEx", subtree=True, optional=True),
    RegistryTarget("HKLM", rf"SOFTWARE\WOW6432Node\{_RUN}\Run"),
    RegistryTarget("HKLM", rf"SOFTWARE\WOW6432Node\{_RUN}\RunOnce"),
    RegistryTarget("HKLM", rf"SOFTWARE\WOW6432Node\{_RUN}\RunOnceEx", subtree=True, optional=True),
)

# A key that doesn't exist can't be watched. These parents exist, and tell FIM when a
# subkey such as RunOnceEx appears, so that it can start watching it. Nothing in them is
# read: a notification only means "look again".
APPEARANCE_WATCHES = (
    RegistryTarget("HKLM", rf"SOFTWARE\{_RUN}"),
    RegistryTarget("HKLM", rf"SOFTWARE\WOW6432Node\{_RUN}"),
)


def folder_targets(environ: Mapping[str, str]) -> tuple[FolderTarget, ...]:
    """The folders to watch. APPDATA makes the per-user one depend on who runs FIM."""
    return (
        FolderTarget(ntpath.join(environ["APPDATA"], _STARTUP)),
        FolderTarget(ntpath.join(environ["PROGRAMDATA"], _STARTUP)),
        FolderTarget(ntpath.join(environ["SYSTEMROOT"], r"System32\drivers\etc"), "hosts"),
    )
