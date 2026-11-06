"""Static PE heuristics: 2nd generation.

These read a file's structure and never run it. The file is parsed from bytes in memory,
so nothing here loads or executes it.

The score is a capped sum of fixed weights, one per kind of finding, so any result can be
explained by adding up its reasons. The weights are hand-set judgement, not measured. A
heuristic score is about the file, not about what it did: legitimate software is packed
too. It goes in static_analysis, never in risk_score, so it can't trigger enforcement.
"""

import math
from collections import Counter
from dataclasses import dataclass, field

import pefile

MAX_PE_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 96  # a header can claim 65535, and each one costs an entropy calculation
ENTROPY_SAMPLE_BYTES = 1024 * 1024
MIN_ENTROPY_BYTES = 1024  # a tiny section has too little data for entropy to mean anything
HIGH_ENTROPY = 7.2  # 8.0 is random: packed or encrypted code sits near the top
RAW_VIRTUAL_RATIO = 10
MIN_VIRTUAL_BYTES = 0x1000
FEW_IMPORTS = 5
COM_DESCRIPTOR_INDEX = 14  # .NET directory: such files normally import a single function

PACKER_SECTIONS = {
    ".adata", ".aspack", ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".packed", ".petite",
    ".themida", ".vmp0", ".vmp1", ".winlice", "pebundle", "petite",
}
UPX_SECTIONS = {"UPX0", "UPX1", "UPX2", "UPX3", ".UPX0", ".UPX1"}

INJECTION_ALLOCATE = {"VirtualAllocEx", "NtAllocateVirtualMemory"}
INJECTION_WRITE = {"WriteProcessMemory", "NtWriteVirtualMemory"}
INJECTION_RUN = {
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC",
    "RtlCreateUserThread",
}
DUMP_IMPORTS = {"MiniDumpWriteDump"}


@dataclass(frozen=True)
class Check:
    weight: float
    rule_name: str  # becomes rule_id HEUR-<rule_name> when this is the strongest finding
    technique: str | None = None


# Strongest first. Repeats of one kind count once, so 2 UPX sections don't score twice.
CHECKS = {
    "unparseable": Check(0.50, "UNPARSEABLE-PE"),
    "upx": Check(0.40, "UPX-PACKED", "T1027.002"),
    "packer": Check(0.40, "PACKER-SECTION", "T1027.002"),
    "injection": Check(0.30, "INJECTION-IMPORTS", "T1055"),
    "dump": Check(0.30, "DUMP-IMPORTS", "T1003"),
    "entropy": Check(0.25, "HIGH-ENTROPY", "T1027"),
    "size_mismatch": Check(0.15, "SIZE-MISMATCH"),
    "entry_point": Check(0.15, "ENTRY-POINT"),
    "few_imports": Check(0.15, "FEW-IMPORTS"),
}


@dataclass
class HeuristicResult:
    status: str  # parsed, not_pe, unparseable or too_large
    findings: list[tuple[str, str]] = field(default_factory=list)  # (kind, reason)

    def add(self, kind: str, reason: str) -> None:
        self.findings.append((kind, reason))

    @property
    def kinds(self) -> list[str]:
        return [kind for kind in CHECKS if any(found == kind for found, _ in self.findings)]

    @property
    def score(self) -> float:
        return round(min(1.0, sum(CHECKS[kind].weight for kind in self.kinds)), 2)

    @property
    def reasons(self) -> list[str]:
        return [reason for _, reason in self.findings]

    @property
    def rule_name(self) -> str | None:
        return CHECKS[self.kinds[0]].rule_name if self.kinds else None

    @property
    def technique_ids(self) -> list[str]:
        techniques = (CHECKS[kind].technique for kind in self.kinds)
        return list(dict.fromkeys(technique for technique in techniques if technique))


def clean(name: str) -> str:
    """Section names are attacker-controlled, and the reasons reach analysts and the LLM."""
    text = "".join(c if " " <= c <= "~" else "?" for c in name)[:32]
    return text or "(unnamed)"


def section_name(section: pefile.SectionStructure) -> str:
    return section.Name.rstrip(b"\x00").decode("ascii", "replace")


def is_code(section: pefile.SectionStructure) -> bool:
    return bool(section.IMAGE_SCN_MEM_EXECUTE or section.IMAGE_SCN_CNT_CODE)


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0 to 8."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(count / total * math.log2(count / total) for count in Counter(data).values())


def check_sections(sections: list[pefile.SectionStructure], result: HeuristicResult) -> None:
    for section in sections:
        name = section_name(section)
        label = clean(name)
        if name in UPX_SECTIONS:
            result.add("upx", f"Packer section name: {label}")
        elif name.lower() in PACKER_SECTIONS:
            result.add("packer", f"Packer section name: {label}")
        if not is_code(section):
            continue

        raw, virtual = section.SizeOfRawData, section.Misc_VirtualSize
        if virtual >= MIN_VIRTUAL_BYTES and raw * RAW_VIRTUAL_RATIO <= virtual:
            result.add(
                "size_mismatch",
                f"Executable section {label} has {raw} raw bytes but {virtual} virtual bytes",
            )
        sample = section.get_data(length=ENTROPY_SAMPLE_BYTES)
        if len(sample) >= MIN_ENTROPY_BYTES:
            value = entropy(sample)
            if value >= HIGH_ENTROPY:
                result.add("entropy", f"High entropy in executable section {label}: {value:.2f}")


def check_entry_point(
    pe: pefile.PE, sections: list[pefile.SectionStructure], result: HeuristicResult
) -> None:
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if entry == 0:
        return  # normal for a resource-only DLL
    first = next((section for section in sections if is_code(section)), None)
    if first is None:
        result.add("entry_point", "Entry point is set, but no section is marked as code")
        return
    size = max(first.Misc_VirtualSize, first.SizeOfRawData)
    if not first.VirtualAddress <= entry < first.VirtualAddress + size:
        result.add(
            "entry_point",
            f"Entry point is outside the first code section ({clean(section_name(first))})",
        )


def imported_names(pe: pefile.PE) -> tuple[int, set[str]]:
    """Counts ordinal imports too, because they are real imports with no name."""
    count = 0
    names: set[str] = set()
    for library in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for symbol in library.imports:
            count += 1
            if symbol.name:
                names.add(symbol.name.decode("ascii", "replace"))
    return count, names


def is_dotnet(pe: pefile.PE) -> bool:
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return len(directories) > COM_DESCRIPTOR_INDEX and directories[COM_DESCRIPTOR_INDEX].Size > 0


def check_imports(pe: pefile.PE, result: HeuristicResult) -> None:
    count, names = imported_names(pe)
    if count < FEW_IMPORTS and not is_dotnet(pe):
        result.add("few_imports", f"Very few imports: {count}")

    # Together, not one by one: a debugger writes process memory, and that's all it does.
    allocate, write, run = names & INJECTION_ALLOCATE, names & INJECTION_WRITE, names & INJECTION_RUN
    if allocate and write and run:
        found = ", ".join(sorted(allocate | write | run))
        result.add("injection", f"Process injection imports: {found}")
    # Only these fixed names are quoted, so an import name can't inject text into a reason.
    for name in sorted(names & DUMP_IMPORTS):
        result.add("dump", f"Memory dumping import: {name}")


def analyze_pe(data: bytes) -> HeuristicResult:
    """Never raises on bad input. pefile can raise almost anything on a crafted file, and
    the type of the failure is all that's kept from it."""
    if data[:2] != b"MZ":
        return HeuristicResult("not_pe")
    if len(data) > MAX_PE_BYTES:
        return HeuristicResult("too_large")

    result = HeuristicResult("parsed")
    pe = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        sections = pe.sections[:MAX_SECTIONS]
        check_sections(sections, result)
        check_entry_point(pe, sections, result)
        check_imports(pe, result)
    except Exception as error:  # noqa: BLE001 - see the docstring
        result = HeuristicResult("unparseable")
        result.add("unparseable", f"Unparseable PE file ({type(error).__name__})")
    finally:
        if pe is not None:
            pe.close()
    return result
