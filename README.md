# HexHound
Cross-platform binary triage with file-format summaries, hashes, strings, and hex views, plus optional static disassembly and bounded archive inspection and extraction.
BinTriage

BinTriage is a portable command-line kit for binary and file-format triage, static disassembly, and cautious archive inspection. Core analysis uses the Python standard library and runs on macOS, Linux, and Windows.

It identifies common executable, archive, document, image, audio, and database signatures; summarizes ELF, PE, Mach-O (including universal slices), and WebAssembly headers; and reports ELF/PE/Mach-O sections plus import/export symbols when their tables are available. It can also report hashes, byte entropy, printable strings, and a bounded hex view. Optional Capstone support decodes a selected byte range without executing it.

Archive listing supports ZIP, TAR, gzip, bzip2, and xz. Extraction is explicit and bounded (1 GiB and 10,000 entries by default), rejects traversal, links, special files, and overwrites, and writes only into a destination you choose. Archive data can still be malformed or exploit bugs in Python's standard library parsers; analyze untrusted samples in an isolated environment.

Usage

python3 bintriage.py sample.bin
python3 bintriage.py --strings --encoding ascii --encoding utf-16le sample.bin
python3 bintriage.py --hex 256 --json sample.bin another-file
python3 bintriage.py --disassemble-range 0x1000:128 program
python3 bintriage.py --disassemble-range 0:64 --arch x86-64 --base-address 0x401000 program
python3 bintriage.py --list-archive sample.zip
python3 bintriage.py --extract-archive sample.tar.gz --to ./unpacked
Install optional disassembly support with python3 -m pip install -r requirements-disasm.txt. Executable architecture is inferred when supported; use --arch when detection is ambiguous or analyzing a raw code blob. Capstone decoding supports x86, x86-64, ARM/Thumb, AArch64, and RISC-V 32/64. Disassembly offsets refer to the input file, not virtual addresses. Use --base-address to set the displayed addresses. The selected range is limited to 1 MiB and output to 500 instructions by default; adjust the instruction limit with --max-instructions.

--max-strings defaults to 500 per file; use --max-strings 0 for no limit. String extraction is opt-in. UTF-16LE scanning can be requested by repeating --encoding. bintriage_legacy.py is a compatibility launcher; new usage should call bintriage.py.

MD5 is included only to help match legacy file-identification databases; use SHA-256 for integrity checks. Entropy is a heuristic, not proof of encryption or packing. File signatures, section tables, symbol summaries, and disassembly are best-effort and do not validate a file's complete structure; they do not replace a full disassembler or dynamic analysis. Extraction writes files, so use it only with a dedicated destination. Treat untrusted inputs cautiously and use an isolated analysis environment for malware samples.

Tests

python3 -m unittest discover -s tests
