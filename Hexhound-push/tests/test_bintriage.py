import argparse
import bz2
import gzip
import importlib.util
import io
import lzma
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import bintriage


CAPSTONE_AVAILABLE = importlib.util.find_spec("capstone") is not None


class IdentifyTests(unittest.TestCase):
    def test_identifies_supported_signatures(self):
        cases = (
            (b"\x7fELF", "ELF executable/object"),
            (b"MZ", "DOS/Windows PE candidate"),
            (b"\x00asm", "WebAssembly module"),
            (b"%PDF-", "PDF document"),
            (b"RIFF\x00\x00\x00\x00WAVE", "WAV audio"),
            (b"x" * 257 + b"ustar", "TAR archive"),
        )
        for data, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(bintriage.identify(data), expected)

    def test_empty_entropy(self):
        self.assertEqual(bintriage.entropy(b""), 0.0)

    def test_entropy_of_uniform_bytes(self):
        self.assertEqual(bintriage.entropy(bytes(range(256))), 8.0)


class FormatSummaryTests(unittest.TestCase):
    def test_elf_summary(self):
        data = bytearray(20)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", data, 16, 2, 62)
        self.assertEqual(bintriage.elf_summary(bytes(data)), {
            "format": "ELF",
            "bits": 64,
            "endianness": "little",
            "type": "executable",
            "machine": "x86-64",
        })

    def test_elf_sections(self):
        names = b"\0.shstrtab\0.text\0"
        section_table = 52
        names_offset = section_table + 3 * 40
        text_offset = names_offset + len(names)
        data = bytearray(text_offset + 4)
        data[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into(
            "<HHIIIIIHHHHHH", data, 16,
            2, 3, 1, 0, 0, section_table, 0, 52, 0, 0, 40, 3, 1,
        )
        struct.pack_into("<IIIIIIIIII", data, section_table + 40,
                         1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
        struct.pack_into("<IIIIIIIIII", data, section_table + 80,
                         11, 1, 6, 0, text_offset, 4, 0, 0, 4, 0)
        data[names_offset:text_offset] = names
        data[text_offset:] = b"code"

        summary = bintriage.elf_summary(bytes(data))
        self.assertEqual([section["name"] for section in summary["sections_detail"]], [
            ".shstrtab", ".text",
        ])
        self.assertEqual(summary["sections_detail"][-1]["size"], 4)

    def test_elf_dynamic_imports_and_exports(self):
        section_names = b"\0.shstrtab\0.dynstr\0.dynsym\0.text\0"
        dynamic_strings = b"\0puts\0main\0"
        section_table = 52
        names_offset = section_table + 5 * 40
        dynamic_strings_offset = names_offset + len(section_names)
        symbols_offset = dynamic_strings_offset + len(dynamic_strings)
        text_offset = symbols_offset + 3 * 16
        data = bytearray(text_offset + 4)
        data[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into(
            "<HHIIIIIHHHHHH", data, 16,
            3, 3, 1, 0, 0, section_table, 0, 52, 0, 0, 40, 5, 1,
        )
        section_headers = (
            (1, 3, 0, 0, names_offset, len(section_names), 0, 0, 1, 0),
            (11, 3, 0, 0, dynamic_strings_offset, len(dynamic_strings), 0, 0, 1, 0),
            (19, 11, 0, 0, symbols_offset, 48, 2, 0, 4, 16),
            (27, 1, 6, 0, text_offset, 4, 0, 0, 4, 0),
        )
        for index, values in enumerate(section_headers, start=1):
            struct.pack_into("<IIIIIIIIII", data, section_table + index * 40, *values)
        data[names_offset:dynamic_strings_offset] = section_names
        data[dynamic_strings_offset:symbols_offset] = dynamic_strings
        struct.pack_into("<IIIBBH", data, symbols_offset + 16, 1, 0, 0, 0x12, 0, 0)
        struct.pack_into("<IIIBBH", data, symbols_offset + 32, 6, 0, 0, 0x12, 0, 4)

        summary = bintriage.elf_summary(bytes(data))
        self.assertEqual(summary["imports"], ["puts"])
        self.assertEqual(summary["exports"], ["main"])

    def test_truncated_elf_is_reported(self):
        self.assertEqual(bintriage.elf_summary(b"\x7fELF"), {
            "format": "ELF",
            "error": "truncated ELF header",
        })

    def test_pe_signature_and_machine(self):
        data = bytearray(90)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<HH", data, 68, 0x8664, 3)
        self.assertEqual(bintriage.pe_summary(bytes(data)), {
            "format": "PE",
            "dos_header": True,
            "header_offset": 64,
            "pe_signature": True,
            "machine": "x86-64",
            "sections": 3,
        })

    def test_pe_sections_imports_and_exports(self):
        data = bytearray(0x400)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", data, 0x84,
                         0x8664, 1, 0, 0, 0, 224, 0x2022)
        optional = 0x98
        struct.pack_into("<H", data, optional, 0x10B)
        struct.pack_into("<I", data, optional + 92, 16)
        struct.pack_into("<II", data, optional + 96, 0x1040, 40)
        struct.pack_into("<II", data, optional + 104, 0x1000, 40)
        section = optional + 224
        data[section:section + 8] = b".rdata\0\0"
        struct.pack_into("<IIII", data, section + 8,
                         0x200, 0x1000, 0x200, 0x200)

        struct.pack_into("<IIHHIIIIIII", data, 0x240,
                         0, 0, 0, 0, 0, 1, 2, 1,
                         0x10B0, 0x10C0, 0x10D0)
        struct.pack_into("<IIIII", data, 0x200,
                         0x1080, 0, 0, 0x1070, 0x1090)
        data[0x270:0x27D] = b"KERNEL32.dll\0"
        struct.pack_into("<II", data, 0x280, 0x10A0, 0)
        struct.pack_into("<H", data, 0x2A0, 0)
        data[0x2A2:0x2AE] = b"ExitProcess\0"
        struct.pack_into("<II", data, 0x2B0, 0x1100, 0x1110)
        struct.pack_into("<I", data, 0x2C0, 0x10E0)
        struct.pack_into("<H", data, 0x2D0, 0)
        data[0x2E0:0x2E8] = b"DoThing\0"

        summary = bintriage.pe_summary(bytes(data))
        self.assertEqual(summary["sections_detail"][0]["name"], ".rdata")
        self.assertEqual(summary["imports"], ["KERNEL32.dll!ExitProcess"])
        self.assertEqual(summary["exports"], ["DoThing", "ordinal_2"])

    def test_macho_and_wasm_summaries(self):
        macho = b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x01000007)
        self.assertEqual(bintriage.macho_summary(macho), {
            "format": "Mach-O",
            "bits": 64,
            "endianness": "little",
            "architecture": "x86-64",
        })
        self.assertEqual(bintriage.wasm_summary(b"\x00asm\x01\x00\x00\x00"), {
            "format": "WebAssembly",
            "version": 1,
        })

    def test_macho_section_details(self):
        command_size = 72 + 80
        data = bytearray(32 + command_size)
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<IIIIIII", data, 4,
                         0x01000007, 3, 2, 1, command_size, 0, 0)
        struct.pack_into("<II16sQQQQIIII", data, 32,
                         0x19, command_size, b"__TEXT", 0, 0, 0, 0, 7, 5, 1, 0)
        struct.pack_into("<16s16sQQIIIIIIII", data, 32 + 72,
                         b"__text", b"__TEXT", 0, 4, 0, 2, 0, 0, 0x80000400, 0, 0, 0)

        summary = bintriage.macho_summary(bytes(data))
        self.assertEqual(summary["sections_detail"], [{
            "name": "__text", "segment": "__TEXT", "address": 0,
            "offset": 0, "size": 4,
        }])

    def test_universal_macho_analyzes_slices(self):
        thin = bytearray(32)
        thin[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<IIIIIII", thin, 4,
                         0x01000007, 3, 2, 0, 0, 0, 0)
        fat = bytearray(8 + 20 + len(thin))
        fat[:4] = b"\xca\xfe\xba\xbe"
        struct.pack_into(">I", fat, 4, 1)
        struct.pack_into(">iiIII", fat, 8,
                         0x01000007, 3, 28, len(thin), 0)
        fat[28:] = thin

        summary = bintriage.macho_summary(bytes(fat))
        self.assertEqual(summary["format"], "Mach-O universal/fat")
        self.assertEqual(summary["slices"][0]["architecture"], "x86-64")
        self.assertEqual(summary["slices"][0]["summary"]["format"], "Mach-O")


class StringTests(unittest.TestCase):
    def test_ascii_strings_include_offsets(self):
        self.assertEqual(
            list(bintriage.printable_strings(b"\x00hello\x00world", minimum=4)),
            [(1, "hello"), (7, "world")],
        )

    def test_utf16le_strings_include_byte_offsets(self):
        data = b"\x00" + "world".encode("utf-16le")
        self.assertEqual(
            list(bintriage.printable_strings(data, minimum=4, encoding="utf-16le")),
            [(1, "world")],
        )


class DisassemblyTests(unittest.TestCase):
    @unittest.skipUnless(
        CAPSTONE_AVAILABLE, "optional Capstone dependency is not installed",
    )
    def test_disassemble_x86_range(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code.bin"
            path.write_bytes(b"\x90\xc3")
            result = bintriage.disassemble_file(
                path, "0:2", architecture="x86-64", base_address=0x1000,
            )
        self.assertIn("instructions", result)
        if "instructions" in result:
            self.assertEqual(result["architecture"], "x86-64")
            self.assertEqual(result["instructions"][0]["address"], 0x1000)
            self.assertEqual(result["instructions"][0]["mnemonic"], "nop")
            self.assertFalse(result["instructions_truncated"])

    @unittest.skipUnless(
        CAPSTONE_AVAILABLE, "optional Capstone dependency is not installed",
    )
    def test_infers_elf_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code.elf"
            data = bytearray(22)
            data[:7] = b"\x7fELF\x02\x01\x01"
            struct.pack_into("<HH", data, 16, 2, 62)
            data[20:] = b"\x90\xc3"
            path.write_bytes(data)
            result = bintriage.disassemble_file(path, "20:2")
        self.assertIn("instructions", result)
        if "instructions" in result:
            self.assertEqual(result["architecture"], "x86-64")
            self.assertEqual(result["instructions"][0]["mnemonic"], "nop")

    @unittest.skipUnless(
        CAPSTONE_AVAILABLE, "optional Capstone dependency is not installed",
    )
    def test_instruction_limit_reports_only_real_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code.bin"
            path.write_bytes(b"\x90\xc3")
            result = bintriage.disassemble_file(
                path, "0:2", architecture="x86-64", max_instructions=1,
            )
            path.write_bytes(b"\x90")
            one_instruction = bintriage.disassemble_file(
                path, "0:1", architecture="x86-64", max_instructions=1,
            )
        self.assertIn("instructions_truncated", result)
        self.assertIn("instructions_truncated", one_instruction)
        if ("instructions_truncated" in result
                and "instructions_truncated" in one_instruction):
            self.assertTrue(result["instructions_truncated"])
            self.assertFalse(one_instruction["instructions_truncated"])

    def test_disassembly_rejects_out_of_bounds_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code.bin"
            path.write_bytes(b"\x90")
            result = bintriage.disassemble_file(path, "0:2", architecture="x86-64")
        self.assertIn("error", result)
        if "error" in result:
            self.assertIn("extends beyond", result["error"])

    @unittest.skipUnless(
        CAPSTONE_AVAILABLE, "optional Capstone dependency is not installed",
    )
    def test_disassembles_riscv(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "riscv.bin"
            path.write_bytes(b"\x13\x05\x10\x00")
            result = bintriage.disassemble_file(path, "0:4", architecture="riscv32")
        self.assertIn("instructions", result)
        if "instructions" in result:
            self.assertEqual(result["instructions"][0]["mnemonic"], "addi")

    @unittest.skipIf(CAPSTONE_AVAILABLE, "requires Capstone to be absent")
    def test_missing_capstone_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code.bin"
            path.write_bytes(b"\x90")
            result = bintriage.disassemble_file(
                path, "0:1", architecture="x86-64",
            )
        self.assertIn("optional Capstone dependency", result["error"])


class ArchiveTests(unittest.TestCase):
    def test_lists_and_extracts_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("folder/data.txt", b"safe data")
            listing = bintriage.list_archive(archive_path)
            destination = root / "output"
            result = bintriage.extract_archive(archive_path, destination)
            self.assertEqual(listing["entries"][0]["name"], "folder/data.txt")
            self.assertEqual(result["files_extracted"], 1)
            self.assertEqual((destination / "folder/data.txt").read_bytes(), b"safe data")

    def test_rejects_zip_path_traversal_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("safe.txt", b"safe")
                archive.writestr("../outside.txt", b"unsafe")
            self.assertEqual(
                bintriage.list_archive(archive_path)["entries"][1]["name"],
                "../outside.txt",
            )
            destination = root / "output"
            with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                bintriage.extract_archive(archive_path, destination)
            self.assertEqual(list(destination.iterdir()), [])
            self.assertFalse((root / "outside.txt").exists())

    def test_rejects_zip_links_and_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "link.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("safe.txt", b"safe")
                link = zipfile.ZipInfo("link")
                link.create_system = 3
                link.external_attr = (0o120777 << 16)
                archive.writestr(link, "target")
            destination = root / "output"
            with self.assertRaisesRegex(ValueError, "unsafe archive entry type"):
                bintriage.extract_archive(archive_path, destination)
            self.assertEqual(list(destination.iterdir()), [])
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("safe.txt", b"new")
            (destination / "safe.txt").write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                bintriage.extract_archive(archive_path, destination)
            self.assertEqual((destination / "safe.txt").read_bytes(), b"existing")

    def test_extracts_bzip2_and_xz_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ("payload.bin.bz2", bz2.open),
                ("payload.bin.xz", lzma.open),
            )
            for filename, opener in cases:
                archive_path = root / filename
                with opener(archive_path, "wb") as compressed:
                    compressed.write(b"compressed payload")
                destination = root / f"{filename}.out"
                result = bintriage.extract_archive(archive_path, destination)
                self.assertEqual(result["files_extracted"], 1)
                self.assertEqual(
                    (destination / "payload.bin").read_bytes(),
                    b"compressed payload",
                )

    def test_rejects_tar_symbolic_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "link.tar"
            with tarfile.open(archive_path, "w") as archive:
                link = tarfile.TarInfo("link")
                link.type = tarfile.SYMTYPE
                link.linkname = "target"
                archive.addfile(link)
            self.assertEqual(
                bintriage.list_archive(archive_path)["entries"][0]["type"],
                "symlink",
            )
            with self.assertRaisesRegex(ValueError, "unsafe archive entry type"):
                bintriage.extract_archive(archive_path, root / "output")

    def test_rejects_existing_symlink_in_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("nested/file.txt", b"payload")
            destination = root / "output"
            destination.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (destination / "nested").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                bintriage.extract_archive(archive_path, destination)
            self.assertEqual(list(outside.iterdir()), [])

    def test_rejects_windows_device_and_path_names(self):
        for name in ("C:/outside", r"..\\outside", "NUL.txt", "folder/CON"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                    bintriage._safe_member_path(name)

    def test_gzip_expansion_limit_removes_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "payload.bin.gz"
            with gzip.open(archive_path, "wb") as compressed:
                compressed.write(b"x" * 4096)
            destination = root / "output"
            with self.assertRaisesRegex(ValueError, "extraction limit"):
                bintriage.extract_archive(archive_path, destination, max_bytes=128)
            self.assertEqual(list(destination.iterdir()), [])

    def test_lists_tar_and_extracts_without_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sample.tar"
            content = b"tar payload"
            with tarfile.open(archive_path, "w") as archive:
                info = tarfile.TarInfo("data.bin")
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            listing = bintriage.list_archive(archive_path)
            destination = root / "output"
            bintriage.extract_archive(archive_path, destination)
            self.assertEqual(listing["format"], "tar")
            self.assertEqual((destination / "data.bin").read_bytes(), content)


class AnalysisTests(unittest.TestCase):
    def test_analysis_flags_are_optional(self):
        args = argparse.Namespace(
            strings=False, encoding=["ascii"], min_string=4,
            max_strings=500, hex=None,
        )
        result = bintriage.analyze(__file__, args)
        self.assertIn("sha256", result)
        self.assertNotIn("strings", result)
        self.assertNotIn("hex", result)

    def test_string_limit_only_reports_truncation_when_needed(self):
        args = argparse.Namespace(
            strings=True, encoding=["ascii"], min_string=4,
            max_strings=1, hex=None,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"hello")
            result = bintriage.analyze(path, args)
            self.assertEqual(len(result["strings"]), 1)
            self.assertFalse(result["strings_truncated"])

            path.write_bytes(b"hello\x00world")
            result = bintriage.analyze(path, args)
            self.assertEqual(len(result["strings"]), 1)
            self.assertTrue(result["strings_truncated"])


if __name__ == "__main__":
    unittest.main()
