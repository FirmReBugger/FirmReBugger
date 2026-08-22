#!/usr/bin/env python3
"""Compare the file-backed PT_LOAD bytes of two ELF32 files."""

import struct
import sys
from pathlib import Path


def image(path: Path) -> dict[int, int]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x01\x01":
        raise ValueError(f"{path}: expected a 32-bit little-endian ELF")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    phoff, phentsize, phnum = header[5], header[9], header[10]
    result = {}
    for index in range(phnum):
        fields = struct.unpack_from("<IIIIIIII", data, phoff + index * phentsize)
        p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = fields
        if p_type == 1:
            result.update(enumerate(data[p_offset:p_offset + p_filesz], p_vaddr))
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ACTUAL.elf REFERENCE.elf", file=sys.stderr)
        return 2
    actual_path, reference_path = map(Path, sys.argv[1:])
    actual, reference = image(actual_path), image(reference_path)
    mismatches = [a for a in sorted(set(actual) | set(reference))
                  if actual.get(a) != reference.get(a)]
    if mismatches:
        first = mismatches[0]
        print(f"loadable image differs: {len(mismatches)} byte(s); first at "
              f"0x{first:08x}", file=sys.stderr)
        return 1
    print(f"loadable image matches {reference_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
