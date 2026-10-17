#!/usr/bin/env python3
"""HexHound: portable, read-only triage for binaries and common file formats."""

import argparse
import bz2
from contextlib import ExitStack
import gzip
import hashlib
import json
import lzma
import math
import ntpath
import stat
import struct
import sys
import tarfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from pathlib import PurePosixPath
from typing import Literal, TypedDict, Union


MAGIC = (
    (b"\x7fELF", "ELF executable/object"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (little-endian)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (big-endian)"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (little-endian)"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (big-endian)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal/fat binary"),
    (b"\xbe\xba\xfe\xca", "Mach-O universal/fat binary (byte-swapped)"),
    (b"\xca\xfe\xba\xbf", "Mach-O universal/fat 64-bit binary"),
    (b"\xbf\xba\xfe\xca", "Mach-O universal/fat 64-bit binary (byte-swapped)"),
    (b"MZ", "DOS/Windows PE candidate"),
    (b"\x00asm", "WebAssembly module"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"PK\x07\x08", "ZIP archive (spanned)"),
    (b"\x1f\x8b", "gzip-compressed data"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\xfd7zXZ\x00", "XZ-compressed data"),
    (b"BZh", "bzip2-compressed data"),
)

MACHINE_NAMES = {
    3: "x86",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}
ELF_TYPE_NAMES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
PE_MACHINE_NAMES = {
    0x014C: "x86",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0x8664: "x86-64",
    0xAA64: "ARM64",
    0x5064: "RISC-V 64-bit",
}
MACH_CPU_NAMES = {
    7: "x86",
    12: "ARM",
    0x01000007: "x86-64",
    0x0100000C: "ARM64",
}


def identify(data):
    for signature, description in MAGIC:
        if data.startswith(signature):
            return description
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "TAR archive"
    if data.startswith(b"RIFF") and len(data) >= 12:
        riff_type = data[8:12]
        descriptions = {b"WAVE": "WAV audio", b"WEBP": "WebP image", b"AVI ": "AVI video"}
        if riff_type in descriptions:
            return descriptions[riff_type]
    return "Unknown / raw data"


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def printable_strings(data, minimum=4, encoding="ascii"):
    """Yield printable strings and their byte offsets."""
    if encoding == "ascii":
        for start, value in _ascii_strings(data, minimum):
            yield start, value
        return
    if encoding == "utf-16le":
        found = []
        for alignment in (0, 1):
            start = None
            chars = []
            for offset in range(alignment, len(data) - 1, 2):
                value, terminator = data[offset], data[offset + 1]
                if 32 <= value <= 126 and terminator == 0:
                    if start is None:
                        start = offset
                    chars.append(chr(value))
                else:
                    if start is not None and len(chars) >= minimum:
                        found.append((start, "".join(chars)))
                    start, chars = None, []
            if start is not None and len(chars) >= minimum:
                found.append((start, "".join(chars)))
        yield from sorted(found)
        return
    raise ValueError(f"unsupported string encoding: {encoding}")


def _ascii_strings(data, minimum):
    start = None
    chars = bytearray()
    for offset, value in enumerate(data):
        if 32 <= value <= 126:
            if start is None:
                start = offset
            chars.append(value)
        else:
            if start is not None and len(chars) >= minimum:
                yield start, chars.decode("ascii")
            start, chars = None, bytearray()
    if start is not None and len(chars) >= minimum:
        yield start, chars.decode("ascii")


def _unpack(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)


def _cstring(data, offset, limit=256):
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("utf-8", errors="replace")


def _bounded_slice(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        return None
    return data[offset:offset + size]


def _elf_sections(data, bits, endian):
    header = _unpack(endian + ("I" if bits == 32 else "Q"), data,
                     32 if bits == 32 else 40)
    if header is None:
        return None
    section_offset = header[0]
    offsets = (46, 48, 50) if bits == 32 else (58, 60, 62)
    header_values = [_unpack(endian + "H", data, offset) for offset in offsets]
    if any(values is None for values in header_values):
        return None
    section_header_size, section_count, names_index = (values[0] for values in header_values)
    expected_size = 40 if bits == 32 else 64
    if section_count == 0 or section_header_size < expected_size:
        return None
    if section_offset + section_header_size * section_count > len(data):
        return None

    sections = []
    parsed_section_count = min(section_count, 4096)
    for index in range(parsed_section_count):
        offset = section_offset + index * section_header_size
        fmt = endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
        values = _unpack(fmt, data, offset)
        if values is None:
            return None
        if bits == 32:
            name, kind, _, _, file_offset, size, link, _, _, entry_size = values
        else:
            name, kind, _, _, file_offset, size, link, _, _, entry_size = values
        sections.append({
            "name_offset": name,
            "type_id": kind,
            "offset": file_offset,
            "size": size,
            "link": link,
            "entry_size": entry_size,
        })

    names = b""
    if names_index < len(sections):
        names_section = sections[names_index]
        names = _bounded_slice(data, names_section["offset"], names_section["size"]) or b""
    for section in sections:
        section["name"] = _cstring(names, section.pop("name_offset")) if names else ""

    named_sections = [
        {"name": section["name"], "type": section["type_id"],
         "offset": section["offset"], "size": section["size"]}
        for section in sections if section["name"]
    ]
    imports, exports = [], []
    symbols_truncated = False
    symbol_fmt = endian + ("IIIBBH" if bits == 32 else "IBBHQQ")
    symbol_size = struct.calcsize(symbol_fmt)
    for section in sections:
        if section["type_id"] != 11 or section["entry_size"] < symbol_size:
            continue
        strings = b""
        if section["link"] < len(sections):
            linked = sections[section["link"]]
            strings = _bounded_slice(data, linked["offset"], linked["size"]) or b""
        table = _bounded_slice(data, section["offset"], section["size"])
        if table is None or not strings:
            continue
        count = min(len(table) // section["entry_size"], 65536)
        symbols_truncated |= len(table) // section["entry_size"] > count
        for index in range(count):
            values = _unpack(symbol_fmt, table, index * section["entry_size"])
            if values is None:
                break
            if bits == 32:
                name_offset, _, _, info, other, symbol_section = values
            else:
                name_offset, info, other, symbol_section, _, _ = values
            binding = info >> 4
            visibility = other & 0x3
            if binding not in (1, 2) or visibility not in (0, 3):
                continue
            name = _cstring(strings, name_offset)
            if not name:
                continue
            target = imports if symbol_section == 0 else exports
            if name not in target and len(target) < 257:
                target.append(name)
    result = {"sections_detail": named_sections[:256]}
    if section_count > 256 or len(named_sections) > 256:
        result["sections_truncated"] = True
    if symbols_truncated:
        result["symbols_truncated"] = True
    if len(imports) > 256:
        imports = imports[:256]
        result["imports_truncated"] = True
    if len(exports) > 256:
        exports = exports[:256]
        result["exports_truncated"] = True
    if imports:
        result["imports"] = imports
    if exports:
        result["exports"] = exports
    return result


def _pe_details(data, pe_offset, section_count):
    optional_size_values = _unpack("<H", data, pe_offset + 20)
    if optional_size_values is None:
        return None
    optional_size = optional_size_values[0]
    optional_offset = pe_offset + 24
    optional = _bounded_slice(data, optional_offset, optional_size)
    if optional is None or len(optional) < 2:
        return None
    magic = _unpack("<H", optional)
    if magic is None or magic[0] not in (0x10B, 0x20B):
        return None
    directory_offset = 96 if magic[0] == 0x10B else 112
    count_offset = 92 if magic[0] == 0x10B else 108
    directory_count_values = _unpack("<I", optional, count_offset)
    if directory_count_values is None:
        return None
    directory_count = min(directory_count_values[0], 16)
    directories = []
    for index in range(directory_count):
        values = _unpack("<II", optional, directory_offset + 8 * index)
        if values is None:
            break
        directories.append(values)

    section_table = optional_offset + optional_size
    sections = []
    parsed_section_count = min(section_count, 257)
    for index in range(parsed_section_count):
        values = _bounded_slice(data, section_table + index * 40, 40)
        if values is None:
            break
        sections.append({
            "name": values[:8].split(b"\0", 1)[0].decode("ascii", errors="replace"),
            "virtual_size": struct.unpack_from("<I", values, 8)[0],
            "virtual_address": struct.unpack_from("<I", values, 12)[0],
            "raw_size": struct.unpack_from("<I", values, 16)[0],
            "raw_offset": struct.unpack_from("<I", values, 20)[0],
        })

    def rva_offset(rva, size=1):
        if rva == 0:
            return None
        for section in sections:
            start = section["virtual_address"]
            relative = rva - start
            if 0 <= relative < section["raw_size"] and relative + size <= section["raw_size"]:
                offset = section["raw_offset"] + relative
                if _bounded_slice(data, offset, size) is not None:
                    return offset
        return None

    detailed_sections = [
        {"name": section["name"], "virtual_address": section["virtual_address"],
         "virtual_size": section["virtual_size"], "raw_offset": section["raw_offset"],
         "raw_size": section["raw_size"]}
        for section in sections if section["name"]
    ]
    result = {"sections_detail": detailed_sections[:256]}
    if section_count > 256 or len(detailed_sections) > 256:
        result["sections_truncated"] = True
    imports, exports = [], []
    exports_truncated = False
    if len(directories) > 0:
        export_rva, export_size = directories[0]
        export_offset = rva_offset(export_rva, 40)
        if export_offset is not None and export_size >= 40:
            values = _unpack("<IIHHIIIIIII", data, export_offset)
            if values is not None:
                _, _, _, _, _, ordinal_base, function_count, name_count, functions_rva, names_rva, ordinals_rva = values
                exports_truncated = function_count > 65536 or name_count > 65536
                names_offset = rva_offset(names_rva, min(name_count, 65536) * 4)
                named_function_indexes = set()
                if names_offset is not None:
                    for index in range(min(name_count, 65536)):
                        name_rva_values = _unpack("<I", data, names_offset + index * 4)
                        if name_rva_values is None:
                            break
                        ordinal_offset = rva_offset(ordinals_rva + index * 2, 2)
                        ordinal_values = (_unpack("<H", data, ordinal_offset)
                                          if ordinal_offset is not None else None)
                        if ordinal_values is not None and ordinal_values[0] < function_count:
                            named_function_indexes.add(ordinal_values[0])
                        name_offset = rva_offset(name_rva_values[0])
                        name = _cstring(data, name_offset) if name_offset is not None else ""
                        if name and name not in exports and len(exports) < 257:
                            exports.append(name)
                functions_offset = rva_offset(functions_rva, min(function_count, 65536) * 4)
                if functions_offset is not None:
                    for index in range(min(function_count, 65536)):
                        function_rva_values = _unpack("<I", data, functions_offset + index * 4)
                        if function_rva_values is None or not function_rva_values[0]:
                            continue
                        if index not in named_function_indexes:
                            ordinal_name = f"ordinal_{ordinal_base + index}"
                            if ordinal_name not in exports and len(exports) < 257:
                                exports.append(ordinal_name)

    if len(directories) > 1:
        import_rva, _ = directories[1]
        descriptor_offset = rva_offset(import_rva, 20)
        if descriptor_offset is not None:
            for index in range(4096):
                values = _unpack("<IIIII", data, descriptor_offset + index * 20)
                if values is None or not any(values):
                    break
                original_thunk, _, _, name_rva, first_thunk = values
                dll_offset = rva_offset(name_rva)
                dll_name = _cstring(data, dll_offset) if dll_offset is not None else ""
                thunk_rva = original_thunk or first_thunk
                width = 8 if magic[0] == 0x20B else 4
                thunk_offset = rva_offset(thunk_rva, width)
                if thunk_offset is None:
                    continue
                fmt = "<Q" if width == 8 else "<I"
                ordinal_mask = 1 << (width * 8 - 1)
                for thunk_index in range(65536):
                    thunk = _unpack(fmt, data, thunk_offset + thunk_index * width)
                    if thunk is None or thunk[0] == 0:
                        break
                    value = thunk[0]
                    if value & ordinal_mask:
                        symbol = f"{dll_name}!ordinal_{value & 0xffff}"
                    else:
                        hint_name_offset = rva_offset(value, 2)
                        symbol_name = (_cstring(data, hint_name_offset + 2)
                                       if hint_name_offset is not None else "")
                        symbol = f"{dll_name}!{symbol_name}" if symbol_name else ""
                    if symbol and symbol not in imports and len(imports) < 257:
                        imports.append(symbol)
                    if len(imports) >= 257:
                        break
                if len(imports) >= 257:
                    break
    if len(imports) > 256:
        imports = imports[:256]
        result["imports_truncated"] = True
    if len(exports) > 256:
        exports = exports[:256]
        exports_truncated = True
    if exports_truncated:
        result["exports_truncated"] = True
    if imports:
        result["imports"] = imports
    if exports:
        result["exports"] = exports
    return result


def elf_summary(data):
    if not data.startswith(b"\x7fELF"):
        return None
    if len(data) < 20:
        return {"format": "ELF", "error": "truncated ELF header"}
    elf_class, byte_order = data[4], data[5]
    bits = {1: 32, 2: 64}.get(elf_class)
    endian = {1: "<", 2: ">"}.get(byte_order)
    if bits is None or endian is None:
        return {
            "format": "ELF",
            "error": "invalid class or byte order",
            "class": elf_class,
            "byte_order": byte_order,
        }
    values = _unpack(endian + "HH", data, 16)
    if values is None:
        return {"format": "ELF", "error": "truncated ELF header"}
    file_type, machine = values
    result = {
        "format": "ELF",
        "bits": bits,
        "endianness": "little" if endian == "<" else "big",
        "type": ELF_TYPE_NAMES.get(file_type, f"type {file_type}"),
        "machine": MACHINE_NAMES.get(machine, f"machine {machine}"),
    }
    details = _elf_sections(data, bits, endian)
    if details:
        result.update(details)
    return result


def pe_summary(data):
    if not data.startswith(b"MZ"):
        return None
    result = {"format": "PE", "dos_header": True}
    if len(data) < 64:
        result["error"] = "truncated DOS header"
        return result
    pe_offset = _unpack("<I", data, 0x3C)
    if pe_offset is None:
        result["error"] = "truncated DOS header"
        return result
    offset = pe_offset[0]
    result["header_offset"] = offset
    if offset + 4 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        result["error"] = "PE signature not found at DOS header offset"
        return result
    result["pe_signature"] = True
    coff = _unpack("<HH", data, offset + 4)
    if coff is None:
        result["error"] = "truncated COFF header"
        return result
    machine, sections = coff
    result["machine"] = PE_MACHINE_NAMES.get(machine, f"machine 0x{machine:04x}")
    result["sections"] = sections
    details = _pe_details(data, offset, sections)
    if details:
        result.update(details)
    return result


def _macho_details(data, is_64, endian):
    header_size = 32 if is_64 else 28
    header_values = _unpack(endian + "IIIII", data, 4)
    if header_values is None or len(data) < header_size:
        return None
    _, _, _, command_count, command_bytes = header_values
    command_end = header_size + command_bytes
    if command_count > 65536 or command_end > len(data):
        return None

    sections = []
    symbol_table = None
    dynamic_symbols = None
    command_offset = header_size
    for _ in range(command_count):
        command = _unpack(endian + "II", data, command_offset)
        if command is None:
            return None
        command_type, command_size = command
        if command_size < 8 or command_offset + command_size > command_end:
            return None
        if command_type == (0x19 if is_64 else 1):
            segment_header_size = 72 if is_64 else 56
            section_size = 80 if is_64 else 68
            segment = _bounded_slice(data, command_offset, command_size)
            if segment is None or len(segment) < segment_header_size:
                return None
            section_count = struct.unpack_from(endian + "I", segment, 64 if is_64 else 48)[0]
            available = (len(segment) - segment_header_size) // section_size
            section_limit = min(section_count, available, 4096)
            for index in range(section_limit):
                section = segment[segment_header_size + index * section_size:
                                  segment_header_size + (index + 1) * section_size]
                name = section[:16].split(b"\0", 1)[0].decode("ascii", errors="replace")
                segment_name = section[16:32].split(b"\0", 1)[0].decode("ascii", errors="replace")
                if is_64:
                    address, size = struct.unpack_from(endian + "QQ", section, 32)
                    file_offset = struct.unpack_from(endian + "I", section, 48)[0]
                else:
                    address, size, file_offset = struct.unpack_from(endian + "III", section, 32)
                sections.append({
                    "name": name, "segment": segment_name, "address": address,
                    "offset": file_offset, "size": size,
                })
        elif command_type == 2 and command_size >= 24:
            symbol_table = _unpack(endian + "IIII", data, command_offset + 8)
        elif command_type == 0xB and command_size >= 80:
            dynamic_symbols = _unpack(endian + "IIIIIIII", data, command_offset + 8)
        command_offset += command_size

    result = {"sections_detail": sections[:256]}
    if len(sections) > 256:
        result["sections_truncated"] = True
    imports, exports = [], []
    if symbol_table is not None:
        symbol_offset, symbol_count, string_offset, string_size = symbol_table
        strings = _bounded_slice(data, string_offset, string_size)
        symbol_size = 16 if is_64 else 12
        parsed_symbol_count = min(symbol_count, 65536)
        symbols = _bounded_slice(data, symbol_offset, parsed_symbol_count * symbol_size)
        if strings is not None and symbols is not None:
            if dynamic_symbols is not None:
                export_start, export_count = dynamic_symbols[2], dynamic_symbols[3]
                import_start, import_count = dynamic_symbols[4], dynamic_symbols[5]
                export_indexes = range(export_start, min(export_start + export_count, parsed_symbol_count))
                import_indexes = range(import_start, min(import_start + import_count, parsed_symbol_count))
            else:
                export_indexes = range(parsed_symbol_count)
                import_indexes = export_indexes
            export_set, import_set = set(export_indexes), set(import_indexes)
            for index in sorted(export_set | import_set):
                if index >= parsed_symbol_count or index >= len(symbols) // symbol_size:
                    continue
                fmt = endian + ("IBBHQ" if is_64 else "IBBHI")
                values = _unpack(fmt, symbols, index * symbol_size)
                if values is None:
                    continue
                string_index, symbol_type = values[0], values[1]
                if symbol_type & 0xE0 or not symbol_type & 1:
                    continue
                symbol_kind = symbol_type & 0x0E
                name = _cstring(strings, string_index)
                if not name:
                    continue
                if index in import_set and symbol_kind == 0:
                    target = imports
                elif index in export_set and symbol_kind != 0:
                    target = exports
                else:
                    continue
                if name not in target and len(target) < 257:
                    target.append(name)
    if len(imports) > 256:
        imports = imports[:256]
        result["imports_truncated"] = True
    if len(exports) > 256:
        exports = exports[:256]
        result["exports_truncated"] = True
    if symbol_table is not None and symbol_count > parsed_symbol_count:
        result["symbols_truncated"] = True
    if imports:
        result["imports"] = imports
    if exports:
        result["exports"] = exports
    return result


def _fat_macho_summary(data):
    fat_headers = {
        b"\xca\xfe\xba\xbe": (False, ">"),
        b"\xbe\xba\xfe\xca": (False, "<"),
        b"\xca\xfe\xba\xbf": (True, ">"),
        b"\xbf\xba\xfe\xca": (True, "<"),
    }
    header = fat_headers.get(data[:4])
    if header is None:
        return None
    is_64, endian = header
    count_values = _unpack(endian + "I", data, 4)
    if count_values is None:
        return {"format": "Mach-O universal/fat", "error": "truncated fat header"}
    architecture_count = count_values[0]
    arch_size = 32 if is_64 else 20
    parsed_count = min(architecture_count, 64)
    if 8 + parsed_count * arch_size > len(data):
        return {"format": "Mach-O universal/fat", "error": "truncated architecture table"}
    result = {"format": "Mach-O universal/fat", "slices": []}
    if architecture_count > parsed_count:
        result["slices_truncated"] = True
    for index in range(parsed_count):
        arch_offset = 8 + index * arch_size
        fmt = endian + ("iiQQII" if is_64 else "iiIII")
        values = _unpack(fmt, data, arch_offset)
        if values is None:
            result["slices"].append({"error": "truncated architecture entry"})
            continue
        cpu_type, cpu_subtype, slice_offset, slice_size = values[:4]
        entry = {
            "architecture": MACH_CPU_NAMES.get(cpu_type, f"CPU 0x{cpu_type:08x}"),
            "cpu_subtype": cpu_subtype,
            "offset": slice_offset,
            "size": slice_size,
        }
        slice_data = _bounded_slice(data, slice_offset, slice_size)
        if slice_data is None:
            entry["error"] = "slice range outside file"
        elif slice_data[:4] in fat_headers:
            entry["error"] = "nested universal Mach-O slice"
        else:
            summary = macho_summary(slice_data)
            if summary is None:
                entry["error"] = "unrecognized Mach-O slice"
            else:
                entry["summary"] = summary
        result["slices"].append(entry)
    return result


def macho_summary(data):
    if len(data) < 4:
        return None
    fat_summary = _fat_macho_summary(data)
    if fat_summary is not None:
        return fat_summary
    headers = {
        b"\xcf\xfa\xed\xfe": (True, "<"),
        b"\xfe\xed\xfa\xcf": (True, ">"),
        b"\xce\xfa\xed\xfe": (False, "<"),
        b"\xfe\xed\xfa\xce": (False, ">"),
    }
    header = headers.get(data[:4])
    if header is None:
        return None
    is_64, endian = header
    result = {"format": "Mach-O", "bits": 64 if is_64 else 32,
              "endianness": "little" if endian == "<" else "big"}
    values = _unpack(endian + "I", data, 4)
    if values is None:
        result["error"] = "truncated Mach-O header"
        return result
    cpu_type = values[0]
    result["architecture"] = MACH_CPU_NAMES.get(cpu_type, f"CPU 0x{cpu_type:08x}")
    details = _macho_details(data, is_64, endian)
    if details:
        result.update(details)
    return result


def wasm_summary(data):
    if not data.startswith(b"\x00asm"):
        return None
    if len(data) < 8:
        return {"format": "WebAssembly", "error": "truncated module header"}
    version = _unpack("<I", data, 4)[0]
    return {"format": "WebAssembly", "version": version}


def format_summary(data):
    return (elf_summary(data) or pe_summary(data) or macho_summary(data)
            or wasm_summary(data))


def analyze(path, args):
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        return {"file": str(path), "error": str(exc)}

    result = {
        "file": str(path),
        "size": len(data),
        "type": identify(data),
        "entropy": round(entropy(data), 4),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }
    summary = format_summary(data)
    if summary:
        result["summary"] = summary
    if args.strings:
        found = []
        for encoding in args.encoding:
            for offset, value in printable_strings(data, args.min_string, encoding):
                found.append({"offset": offset, "encoding": encoding, "value": value})
                if args.max_strings and len(found) > args.max_strings:
                    break
            if args.max_strings and len(found) > args.max_strings:
                break
        strings_truncated = bool(args.max_strings and len(found) > args.max_strings)
        if strings_truncated:
            found = found[:args.max_strings]
        result["strings"] = found
        result["strings_truncated"] = strings_truncated
    if args.hex is not None:
        result["hex"] = data[:args.hex].hex()
        result["hex_bytes_shown"] = min(args.hex, len(data))
    return result


def print_text(result):
    if "error" in result:
        print(f"{result['file']}: {result['error']}", file=sys.stderr)
        return
    print(f"File:       {result['file']}")
    print(f"Size:       {result['size']} bytes")
    print(f"Type:       {result['type']}")
    print(f"Entropy:    {result['entropy']:.4f} bits/byte")
    print(f"SHA-256:    {result['sha256']}")
    print(f"MD5:        {result['md5']} (identification only; not secure)")
    if "summary" in result:
        for key, value in result["summary"].items():
            if key in ("sections_truncated", "imports_truncated", "exports_truncated",
                       "slices_truncated"):
                continue
            if key == "slices":
                print(f"Slices: {len(value)}")
                for item in value:
                    if "error" in item:
                        print(f"  {item.get('architecture', '<unknown>')}: {item['error']}")
                        continue
                    slice_summary = item["summary"]
                    print(
                        f"  {item['architecture']}: {slice_summary.get('bits', '?')}-bit, "
                        f"{len(slice_summary.get('sections_detail', []))} sections, "
                        f"{len(slice_summary.get('imports', []))} imports, "
                        f"{len(slice_summary.get('exports', []))} exports"
                    )
                if result["summary"].get("slices_truncated"):
                    print("  ... output truncated at 64 slices")
                continue
            if key in ("sections_detail", "imports", "exports"):
                print(f"{key.replace('_', ' ').title()}: {len(value)}")
                for item in value:
                    if isinstance(item, dict):
                        name = item.get("name", "<unnamed>")
                        details = ", ".join(
                            f"{detail}={detail_value}"
                            for detail, detail_value in item.items() if detail != "name"
                        )
                        print(f"  {name}: {details}" if details else f"  {name}")
                    else:
                        print(f"  {item}")
                truncated_key = key.replace("_detail", "") + "_truncated"
                if result["summary"].get(truncated_key):
                    print("  ... output truncated at 256 entries")
            else:
                print(f"{key.replace('_', ' ').title()}: {value}")
    if "strings" in result:
        print("\nPrintable strings:")
        if result["strings"]:
            for item in result["strings"]:
                print(f"{item['offset']:08x} [{item['encoding']}]: {item['value']}")
        else:
            print("(none found)")
        if result["strings_truncated"]:
            print("... output limit reached")
    if "hex" in result:
        print("\nHex dump:")
        raw = bytes.fromhex(result["hex"])
        for offset in range(0, len(raw), 16):
            row = raw[offset:offset + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in row)
            ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in row)
            print(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
        omitted = result["size"] - result["hex_bytes_shown"]
        if omitted:
            print(f"... {omitted} bytes omitted")


def _infer_architecture(data):
    summary = format_summary(data)
    if summary is None:
        return None
    if summary.get("format") == "Mach-O universal/fat":
        return None
    architecture = summary.get("architecture", summary.get("machine"))
    if not isinstance(architecture, str):
        return None
    return {
        "x86": "x86",
        "x86-64": "x86-64",
        "ARM": "arm",
        "ARMv7": "arm",
        "ARM64": "arm64",
        "AArch64": "arm64",
        "RISC-V": f"riscv{summary.get('bits')}",
    }.get(architecture)


def _capstone_decoder(architecture, endian):
    try:
        import capstone
    except ImportError as exc:
        raise RuntimeError(
            "disassembly requires the optional Capstone dependency; "
            "install it with `python3 -m pip install -r requirements-disasm.txt`"
        ) from exc

    modes = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x86-64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_ARM | (
                capstone.CS_MODE_BIG_ENDIAN if endian == "big"
                else capstone.CS_MODE_LITTLE_ENDIAN
            ),
        ),
        "arm-thumb": (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB | (
                capstone.CS_MODE_BIG_ENDIAN if endian == "big"
                else capstone.CS_MODE_LITTLE_ENDIAN
            ),
        ),
        "arm64": (
            capstone.CS_ARCH_ARM64,
            capstone.CS_MODE_BIG_ENDIAN if endian == "big"
            else capstone.CS_MODE_LITTLE_ENDIAN,
        ),
        "riscv32": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32),
        "riscv64": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64),
    }
    if architecture not in modes:
        raise ValueError(f"unsupported disassembly architecture: {architecture}")
    if architecture.startswith("riscv") and endian == "big":
        raise ValueError("Capstone RISC-V decoding currently supports little-endian code only")
    arch, mode = modes[architecture]
    return capstone.Cs(arch, mode)


class InstructionRecord(TypedDict):
    address: int
    offset: int
    bytes: str
    mnemonic: str
    operands: str


class DisassemblySuccess(TypedDict):
    ok: Literal[True]
    file: str
    architecture: str
    offset: int
    size: int
    instructions: list[InstructionRecord]
    instructions_truncated: bool


class DisassemblyError(TypedDict):
    ok: Literal[False]
    file: str
    error: str


DisassemblyResult = Union[DisassemblySuccess, DisassemblyError]


def disassemble_file(path, range_spec, architecture=None, base_address=0,
                     max_instructions=500) -> DisassemblyResult:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        return {"ok": False, "file": str(path), "error": str(exc)}
    try:
        offset_text, size_text = range_spec.split(":", 1)
        offset, size = int(offset_text, 0), int(size_text, 0)
    except (ValueError, AttributeError):
        return {
            "ok": False, "file": str(path),
            "error": "range must be OFFSET:SIZE in decimal or 0x-prefixed form",
        }
    if offset < 0 or size <= 0 or size > 1024 * 1024:
        return {
            "ok": False, "file": str(path),
            "error": "offset must be non-negative and size must be 1..1048576 bytes",
        }
    if offset + size > len(data):
        return {
            "ok": False, "file": str(path),
            "error": "requested range extends beyond end of file",
        }
    detected = architecture or _infer_architecture(data)
    if detected is None:
        return {
            "ok": False,
            "file": str(path),
            "error": "could not infer architecture; specify --arch (universal Mach-O needs an explicit architecture)",
        }
    summary = format_summary(data) or {}
    endian = summary.get("endianness", "little")
    try:
        decoder = _capstone_decoder(detected, endian)
    except (RuntimeError, ValueError) as exc:
        return {"ok": False, "file": str(path), "error": str(exc)}
    instructions: list[InstructionRecord] = []
    instructions_truncated = False
    for instruction in decoder.disasm(data[offset:offset + size], base_address + offset):
        if len(instructions) >= max_instructions:
            instructions_truncated = True
            break
        instructions.append({
            "address": instruction.address,
            "offset": instruction.address - base_address,
            "bytes": instruction.bytes.hex(),
            "mnemonic": instruction.mnemonic,
            "operands": instruction.op_str,
        })
    return {
        "ok": True,
        "file": str(path),
        "architecture": detected,
        "offset": offset,
        "size": size,
        "instructions": instructions,
        "instructions_truncated": instructions_truncated,
    }


def _archive_kind(path):
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    with open(path, "rb") as source:
        signature = source.read(6)
    suffix = Path(path).name.lower()
    if signature.startswith(b"\x1f\x8b") or suffix.endswith(".gz"):
        return "gzip"
    if signature.startswith(b"BZh") or suffix.endswith(".bz2"):
        return "bzip2"
    if signature.startswith(b"\xfd7zXZ\x00") or suffix.endswith(".xz"):
        return "xz"
    raise ValueError("unsupported archive/container; supported: ZIP, TAR, gzip, bzip2, xz")


def _safe_member_path(name):
    if not name or "\0" in name or "\\" in name or ":" in name:
        raise ValueError(f"unsafe archive member path: {name!r}")
    if name.startswith("/") or ntpath.splitdrive(name)[0]:
        raise ValueError(f"unsafe archive member path: {name!r}")
    parts = PurePosixPath(name).parts
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10))
    if not parts or any(
        part in ("", ".", "..")
        or part.endswith((" ", "."))
        or any(character in part for character in '<>"|?*')
        or part.split(".", 1)[0].upper() in reserved
        for part in parts
    ):
        raise ValueError(f"unsafe archive member path: {name!r}")
    return Path(*parts)


def _archive_members(path, kind, max_entries):
    if kind == "zip":
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > max_entries:
                raise ValueError(f"archive contains more than {max_entries} entries")
            members = []
            for info in infos:
                mode = info.external_attr >> 16
                member_kind = stat.S_IFMT(mode)
                members.append({
                    "name": info.filename,
                    "path": info.filename.rstrip("/") or None,
                    "size": info.file_size,
                    "directory": info.is_dir(),
                    "encrypted": bool(info.flag_bits & 1),
                    "member_type": (
                        "directory" if info.is_dir()
                        else "file" if member_kind in (0, stat.S_IFREG)
                        else "symlink" if member_kind == stat.S_IFLNK
                        else "special"
                    ),
                    "compression": info.compress_type,
                    "source": info,
                })
            return members
    if kind == "tar":
        members = []
        with tarfile.open(path, mode="r:*") as archive:
            for index, info in enumerate(archive):
                if index >= max_entries:
                    raise ValueError(f"archive contains more than {max_entries} entries")
                members.append({
                    "name": info.name,
                    "path": info.name.rstrip("/") or None,
                    "size": info.size,
                    "directory": info.isdir(),
                    "encrypted": False,
                    "member_type": (
                        "directory" if info.isdir()
                        else "file" if info.isfile()
                        else "symlink" if info.issym()
                        else "hardlink" if info.islnk()
                        else "special"
                    ),
                    "compression": None,
                    "source": info,
                })
        return members
    if kind in ("gzip", "bzip2", "xz"):
        output_name = Path(path).name
        for suffix in (".gz", ".bz2", ".xz"):
            if output_name.lower().endswith(suffix):
                output_name = output_name[:-len(suffix)]
                break
        if not output_name:
            output_name = "decompressed.bin"
        return [{
            "name": output_name,
            "path": output_name,
            "size": None,
            "directory": False,
            "encrypted": False,
            "member_type": "file",
            "compression": None,
            "source": None,
        }]
    raise ValueError(f"unsupported archive type: {kind}")


def _check_destination(root, relative_path):
    current = root
    for index, part in enumerate(relative_path.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"refusing to follow existing symbolic link: {current}")
        if index < len(relative_path.parts) - 1 and not stat.S_ISDIR(mode):
            raise ValueError(f"archive path conflicts with existing non-directory: {current}")
    target = root / relative_path
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing path: {target}")


def _prepare_destination(root, relative_path):
    parent = root
    for part in relative_path.parts[:-1]:
        parent = parent / part
        try:
            parent.mkdir()
        except FileExistsError:
            pass
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError(f"unsafe extraction directory: {parent}")
    return root / relative_path


def list_archive(path, max_entries=10000):
    kind = _archive_kind(path)
    members = _archive_members(path, kind, max_entries)
    return {
        "archive": str(path),
        "format": kind,
        "entries": [
            {"name": member["name"], "size": member["size"],
             "type": member["member_type"]}
            for member in members
        ],
    }


def extract_archive(path, destination, max_bytes=1024 * 1024 * 1024,
                    max_entries=10000):
    if max_bytes <= 0 or max_entries <= 0:
        raise ValueError("extraction limits must be positive")
    kind = _archive_kind(path)
    members = _archive_members(path, kind, max_entries)
    total_declared = sum(member["size"] or 0 for member in members)
    if total_declared > max_bytes:
        raise ValueError(f"archive exceeds extraction limit of {max_bytes} bytes")
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"destination must be a real directory: {root}")
    resolved_root = root.resolve()
    for member in members:
        if member["member_type"] not in ("file", "directory"):
            raise ValueError(f"unsupported or unsafe archive entry type: {member['name']!r}")
        if member["encrypted"]:
            raise ValueError(f"encrypted archive entries are not supported: {member['name']!r}")
        if member["compression"] not in (
            None, zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA,
        ):
            raise ValueError(f"unsupported ZIP compression method: {member['name']!r}")
        if member["path"] is not None:
            member["path"] = _safe_member_path(member["path"])
    unique = set()
    path_kinds = {}
    for member in members:
        relative = member["path"]
        if relative is None:
            continue
        if relative in unique:
            raise ValueError(f"duplicate archive member path: {member['name']!r}")
        unique.add(relative)
        path_kinds[relative] = member["directory"]
    for relative in path_kinds:
        for parent in relative.parents:
            if parent != Path(".") and path_kinds.get(parent) is False:
                raise ValueError(f"archive file is also used as a directory: {parent}")
    for member in members:
        if member["path"] is not None:
            _check_destination(resolved_root, member["path"])

    created_files = []
    total_written = 0
    try:
        for member in members:
            relative = member["path"]
            if relative is None:
                continue
            if member["directory"]:
                directory = resolved_root / relative
                directory.mkdir(parents=True, exist_ok=True)
                if directory.is_symlink() or not directory.is_dir():
                    raise ValueError(f"unsafe extraction directory: {directory}")
                continue
            target = _prepare_destination(resolved_root, relative)
            if target.is_symlink():
                raise ValueError(f"refusing to overwrite symbolic link: {target}")
            with ExitStack() as stack:
                if kind == "zip":
                    archive = stack.enter_context(zipfile.ZipFile(path))
                    source = stack.enter_context(archive.open(member["source"], "r"))
                elif kind == "tar":
                    archive = stack.enter_context(tarfile.open(path, mode="r:*"))
                    source = archive.extractfile(member["source"])
                    if source is None:
                        raise ValueError(f"could not read archive member: {member['name']!r}")
                    stack.enter_context(source)
                elif kind == "gzip":
                    source = stack.enter_context(gzip.open(path, "rb"))
                elif kind == "bzip2":
                    source = stack.enter_context(bz2.open(path, "rb"))
                else:
                    source = stack.enter_context(lzma.open(path, "rb"))
                output = stack.enter_context(open(target, "xb"))
                created_files.append(target)
                while chunk := source.read(1024 * 1024):
                    if not isinstance(chunk, bytes):
                        raise ValueError("archive decoder returned non-binary data")
                    total_written += len(chunk)
                    if total_written > max_bytes:
                        raise ValueError(f"archive exceeds extraction limit of {max_bytes} bytes")
                    output.write(chunk)
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile,
            lzma.LZMAError, ValueError, zlib.error, NotImplementedError):
        for file_path in created_files:
            try:
                file_path.unlink()
            except FileNotFoundError:
                pass
        raise
    return {
        "archive": str(path),
        "destination": str(resolved_root),
        "files_extracted": len(created_files),
        "bytes_extracted": total_written,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "HexHound: cross-platform binary triage, optional disassembly, and bounded "
            "archive inspection/extraction. Input files are never executed."
        )
    )
    parser.add_argument("files", nargs="*", help="files to inspect")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--disassemble-range", metavar="OFFSET:SIZE",
                        help="disassemble a byte range from one file using optional Capstone")
    action.add_argument("--list-archive", metavar="FILE",
                        help="list entries in a ZIP, TAR, gzip, bzip2, or xz file")
    action.add_argument("--extract-archive", metavar="FILE",
                        help="safely extract a supported archive to --to")
    parser.add_argument("--to", metavar="DIRECTORY",
                        help="destination directory for --extract-archive")
    parser.add_argument("--max-extract-bytes", type=int, default=1024 * 1024 * 1024,
                        help="maximum total expanded bytes (default: 1 GiB)")
    parser.add_argument("--max-archive-entries", type=int, default=10000,
                        help="maximum archive entries (default: 10000)")
    parser.add_argument("--arch", choices=(
        "x86", "x86-64", "arm", "arm-thumb", "arm64", "riscv32", "riscv64",
    ),
                        help="override architecture detection for disassembly")
    parser.add_argument("--base-address", type=lambda value: int(value, 0), default=0,
                        help="address assigned to file offset zero (default: 0)")
    parser.add_argument("--max-instructions", type=int, default=500,
                        help="maximum disassembled instructions (default: 500)")
    parser.add_argument("-s", "--strings", action="store_true",
                        help="extract printable strings")
    parser.add_argument("--encoding", choices=("ascii", "utf-16le"), action="append",
                        help="string encoding to scan (repeatable; default: ascii)")
    parser.add_argument("--min-string", type=int, default=4,
                        help="minimum string length (default: 4)")
    parser.add_argument("--max-strings", type=int, default=500,
                        help="maximum strings per file; 0 means unlimited")
    parser.add_argument("--hex", type=int, metavar="BYTES",
                        help="show a hex/ASCII view of the first BYTES")
    parser.add_argument("--json", action="store_true",
                        help="write results as JSON")
    args = parser.parse_args(argv)
    if (args.min_string < 1 or args.max_strings < 0
            or (args.hex is not None and args.hex < 0)):
        parser.error("min-string must be positive; hex and max-strings must be non-negative")
    if args.max_extract_bytes <= 0 or args.max_archive_entries <= 0:
        parser.error("archive limits must be positive")
    if args.max_instructions <= 0:
        parser.error("max-instructions must be positive")
    archive_action = args.list_archive is not None or args.extract_archive is not None
    if args.extract_archive is not None and args.to is None:
        parser.error("--extract-archive requires --to DIRECTORY")
    if args.to is not None and args.extract_archive is None:
        parser.error("--to can only be used with --extract-archive")
    if args.arch is not None and args.disassemble_range is None:
        parser.error("--arch can only be used with --disassemble-range")
    if args.disassemble_range is not None and len(args.files) != 1:
        parser.error("--disassemble-range requires exactly one input file")
    if archive_action and args.files:
        parser.error("archive actions do not accept positional input files")
    if not archive_action and args.disassemble_range is None and not args.files:
        parser.error("provide files to inspect or select an archive/disassembly action")
    if args.encoding is None:
        args.encoding = ["ascii"]

    if args.disassemble_range is not None:
        result = disassemble_file(
            args.files[0], args.disassemble_range, args.arch,
            args.base_address, args.max_instructions,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        elif result["ok"] is False:
            print(f"{result['file']}: {result['error']}", file=sys.stderr)
            return 1
        else:
            print(f"File: {result['file']}")
            print(f"Architecture: {result['architecture']}")
            print(f"Range: 0x{result['offset']:x} ({result['size']} bytes)")
            for instruction in result["instructions"]:
                print(
                    f"{instruction['address']:016x}  {instruction['bytes']:<16} "
                    f"{instruction['mnemonic']} {instruction['operands']}".rstrip()
                )
            if result["instructions_truncated"]:
                print("... instruction output limit reached")
        return 0 if result["ok"] else 1

    if archive_action:
        try:
            if args.list_archive is not None:
                result = list_archive(args.list_archive, args.max_archive_entries)
            else:
                result = extract_archive(
                    args.extract_archive, args.to, args.max_extract_bytes,
                    args.max_archive_entries,
                )
        except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile,
                lzma.LZMAError, ValueError, zlib.error, NotImplementedError) as exc:
            print(f"archive error: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(result, indent=2))
        elif "entries" in result:
            print(f"Archive: {result['archive']} ({result['format']})")
            for entry in result["entries"]:
                size = "unknown" if entry["size"] is None else str(entry["size"])
                print(f"{entry['type']:9} {size:>12}  {entry['name']}")
        else:
            print(f"Extracted {result['files_extracted']} files "
                  f"({result['bytes_extracted']} bytes) to {result['destination']}")
        return 0

    results = [analyze(path, args) for path in args.files]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for index, result in enumerate(results):
            if index:
                print()
            print_text(result)
    return 1 if any("error" in result for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
