#!/usr/bin/env python3
"""Replace selected ARM Thumb function entries with ``bx lr``.

FirmReBugger's ordinary Zephyr targets use these post-link patches to avoid
logging, sleeps, and terminal halt loops. Patching by symbol keeps the recipe
stable when source-level patches move function addresses.
"""

import shutil
import struct
import subprocess
import sys
from pathlib import Path

BX_LR = b"\x70\x47"
PT_LOAD = 1


def load_segments(data):
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("expected a 32-bit little-endian ELF")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", data, 0)
    phoff, phentsize, phnum = header[5], header[9], header[10]
    segments = []
    for index in range(phnum):
        values = struct.unpack_from("<IIIIIIII", data, phoff + index * phentsize)
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, _memsz, p_flags, _align = values
        if p_type == PT_LOAD and p_filesz:
            segments.append((p_offset, p_vaddr, p_paddr, p_filesz, p_flags))
    return segments


def symbols(elf):
    nm = shutil.which("arm-none-eabi-nm") or shutil.which("nm")
    if not nm:
        raise RuntimeError("arm-none-eabi-nm is required")
    output = subprocess.check_output(
        [nm, "-P", "--defined-only", str(elf)], universal_newlines=True
    )
    result = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            try:
                result[fields[0]] = int(fields[2], 16) & ~1
            except ValueError:
                pass
    return result


def main():
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} ELF BIN SYMBOL...", file=sys.stderr)
        return 2
    elf_path, bin_path = Path(sys.argv[1]), Path(sys.argv[2])
    wanted = sys.argv[3:]
    elf = bytearray(elf_path.read_bytes())
    binary = bytearray(bin_path.read_bytes())
    segments = load_segments(elf)
    names = symbols(elf_path)
    rom_base = min(paddr for _, _, paddr, _, flags in segments if flags & 1)

    patched = 0
    for name in wanted:
        candidates = [name] if name in names else sorted(
            candidate for candidate in names if candidate.startswith(name + ".")
        )
        if not candidates:
            print(f"skip absent symbol: {name}")
            continue
        if len(candidates) > 1:
            raise RuntimeError(f"{name}: ambiguous compiler-generated symbols: {candidates}")
        resolved_name = candidates[0]
        address = names[resolved_name]
        segment = next(
            (item for item in segments if item[1] <= address < item[1] + item[3]),
            None,
        )
        if segment is None:
            raise RuntimeError(f"{name}: address 0x{address:x} is not file-backed")
        offset, vaddr, paddr, _size, _flags = segment
        elf_offset = offset + address - vaddr
        bin_offset = paddr + address - vaddr - rom_base
        elf[elf_offset : elf_offset + 2] = BX_LR
        if not 0 <= bin_offset <= len(binary) - 2:
            raise RuntimeError(f"{name}: binary offset 0x{bin_offset:x} is out of range")
        binary[bin_offset : bin_offset + 2] = BX_LR
        patched += 1
        print(f"patched {resolved_name} at 0x{address:08x}")

    if not patched:
        raise RuntimeError("none of the requested early-return symbols were present")
    elf_path.write_bytes(elf)
    bin_path.write_bytes(binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
