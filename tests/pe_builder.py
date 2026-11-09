"""Builds small PE files in memory, so tests run real pefile on real headers.

The bytes are structure and filler only. No code in them does anything, nothing here runs
them, and the import tables are just names.
"""

import struct
from dataclasses import dataclass

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
OPTIONAL_HEADER_SIZE = 224
HEADERS_START = 0x40 + 4 + 20 + OPTIONAL_HEADER_SIZE

CODE = 0x60000020  # code, executable, readable
DATA = 0x40000040  # initialised data, readable

IMPORT_DIRECTORY = 1
COM_DIRECTORY = 14

NORMAL_IMPORTS = {
    "KERNEL32.dll": [
        "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "ExitProcess",
    ]
}


@dataclass
class Section:
    name: bytes
    data: bytes = b""
    virtual_size: int | None = None
    flags: int = CODE


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def import_table(imports: dict[str, list[str]], rva: int) -> tuple[bytes, int]:
    """Returns the .idata content and the import directory's size."""
    directory_size = (len(imports) + 1) * 20
    thunks: list[tuple[str, list[str], int, int]] = []
    cursor = directory_size
    for library, names in imports.items():
        table_size = (len(names) + 1) * 4
        thunks.append((library, names, cursor, cursor + table_size))
        cursor += table_size * 2

    strings = bytearray()
    directory = bytearray()
    tables = bytearray()
    for library, names, lookup, address in thunks:
        entries = []
        for name in names:
            entries.append(rva + cursor + len(strings))
            strings += struct.pack("<H", 0) + name.encode() + b"\x00"
            strings += b"\x00" * (len(strings) % 2)
        library_rva = rva + cursor + len(strings)
        strings += library.encode() + b"\x00"
        strings += b"\x00" * (len(strings) % 2)
        table = b"".join(struct.pack("<I", entry) for entry in [*entries, 0])
        tables += table + table
        directory += struct.pack("<IIIII", rva + lookup, 0, 0, library_rva, rva + address)
    directory += b"\x00" * 20
    return bytes(directory + tables + strings), directory_size


def build_pe(
    sections: list[Section],
    entry_point: int | None = None,
    imports: dict[str, list[str]] | None = None,
    dotnet: bool = False,
) -> bytes:
    sections = list(sections)
    imports = NORMAL_IMPORTS if imports is None else imports

    first_rva = align(HEADERS_START + 40 * (len(sections) + 1), SECTION_ALIGN)
    rva = first_rva
    for section in sections:
        rva += align(section.virtual_size or len(section.data) or 1, SECTION_ALIGN)
    import_rva = rva
    import_data, import_size = import_table(imports, import_rva) if imports else (b"", 0)
    if imports:
        sections.append(Section(b".idata", import_data, flags=DATA))

    headers_size = align(HEADERS_START + 40 * len(sections), FILE_ALIGN)
    table = bytearray()
    body = bytearray()
    rva = first_rva
    offset = headers_size
    for section in sections:
        virtual = section.virtual_size if section.virtual_size is not None else len(section.data)
        raw = align(len(section.data), FILE_ALIGN) if section.data else 0
        table += struct.pack(
            "<8sIIIIIIHHI",
            section.name, virtual, rva, raw, offset if raw else 0, 0, 0, 0, 0, section.flags,
        )
        body += section.data.ljust(raw, b"\x00")
        offset += raw
        rva += align(virtual or 1, SECTION_ALIGN)
    image_size = rva

    directories = [(0, 0)] * 16
    if imports:
        directories[IMPORT_DIRECTORY] = (import_rva, import_size)
    if dotnet:
        directories[COM_DIRECTORY] = (first_rva, 72)

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, 0, 0, 0,
        first_rva if entry_point is None else entry_point,
        first_rva, first_rva,
        0x400000, SECTION_ALIGN, FILE_ALIGN,
        6, 0, 0, 0, 6, 0,
        0, image_size, headers_size, 0,
        3, 0,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    ) + b"".join(struct.pack("<II", *directory) for directory in directories)

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, OPTIONAL_HEADER_SIZE, 0x0102)
    headers = dos_header + b"PE\x00\x00" + coff + optional + bytes(table)
    return headers.ljust(headers_size, b"\x00") + bytes(body)
