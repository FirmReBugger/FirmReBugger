#!/usr/bin/env python3
"""Compare ELF function names and sizes without depending on host binutils."""

from collections import Counter
from pathlib import Path
import re
import struct
import sys


def functions(path: Path) -> Counter[tuple[str, int]]:
    data = path.read_bytes()
    if data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError(f"{path}: expected a 32-bit little-endian ELF")

    shoff = struct.unpack_from("<I", data, 32)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 46)
    sections = [
        struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize)
        for i in range(shnum)
    ]

    result: Counter[tuple[str, int]] = Counter()
    for section in sections:
        section_type, offset, size = section[1], section[4], section[5]
        link, entsize = section[6], section[9]
        if section_type != 2:  # SHT_SYMTAB
            continue
        strings = sections[link]
        strtab = data[strings[4] : strings[4] + strings[5]]
        for pos in range(offset, offset + size, entsize or 16):
            name_at, _, symbol_size, info, _, shndx = struct.unpack_from(
                "<IIIBBH", data, pos
            )
            if info & 0x0F != 2 or shndx == 0 or symbol_size == 0:  # STT_FUNC
                continue
            end = strtab.find(b"\0", name_at)
            name = strtab[name_at:end].decode("utf-8", errors="replace")
            name = re.sub(r"\.lto_priv\.\d+$", "", name)
            result[(name, symbol_size)] += 1
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: compare_functions.py BUILT.elf REFERENCE.elf", file=sys.stderr)
        return 2
    built_path, reference_path = map(Path, sys.argv[1:])
    built, reference = functions(built_path), functions(reference_path)
    if built != reference:
        missing = list((reference - built).elements())
        extra = list((built - reference).elements())
        print(
            f"function inventory differs: missing={missing[:5]!r}, extra={extra[:5]!r}",
            file=sys.stderr,
        )
        return 1
    print(f"function inventory matches {reference_path} ({sum(reference.values())} functions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
