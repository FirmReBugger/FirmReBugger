#!/usr/bin/env python3
"""Compare the bytes loaded into memory by two ELF32 files."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def image(path: Path) -> dict[int, int]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError(f"{path}: expected a 32-bit little-endian ELF")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", data, 0)
    phoff, phentsize, phnum = header[5], header[9], header[10]
    result = {}
    for index in range(phnum):
        p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = struct.unpack_from(
            "<IIIIIIII", data, phoff + index * phentsize
        )
        if p_type == 1:
            result.update(enumerate(data[p_offset : p_offset + p_filesz], p_vaddr))
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ACTUAL.elf REFERENCE.elf", file=sys.stderr)
        return 2
    actual_path, reference_path = map(Path, sys.argv[1:])
    actual, reference = image(actual_path), image(reference_path)
    addresses = sorted(set(actual) | set(reference))
    mismatches = [address for address in addresses if actual.get(address) != reference.get(address)]
    if mismatches:
        first = mismatches[0]
        print(
            f"loadable image differs: {len(mismatches)} byte(s); first at 0x{first:08x} "
            f"(built={actual.get(first)!r}, reference={reference.get(first)!r})",
            file=sys.stderr,
        )
        return 1
    print(f"loadable image matches {reference_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
