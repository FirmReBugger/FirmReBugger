import os
import subprocess
import sys


def run_gen_symbols(elf_path, output_path):
    elf_path = os.path.abspath(elf_path)

    if not os.path.isfile(elf_path):
        print(f"Error: ELF file not found: {elf_path}")
        sys.exit(1)

    # Resolve output path — default to symbols.txt next to the ELF
    if output_path is None:
        output_path = os.path.join(os.path.dirname(elf_path), "symbols.txt")
    output_path = os.path.abspath(output_path)

    # Try arm-none-eabi-nm first, fall back to nm
    nm_candidates = ["arm-none-eabi-nm", "nm"]
    nm_bin = None
    for candidate in nm_candidates:
        try:
            subprocess.run(
                [candidate, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            nm_bin = candidate
            break
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    if nm_bin is None:
        print("Error: neither arm-none-eabi-nm nor nm found on PATH.")
        sys.exit(1)

    print(f"Using: {nm_bin}")
    print(f"ELF:   {elf_path}")
    print(f"Out:   {output_path}")

    result = subprocess.run(
        [
            nm_bin,
            "--defined-only",  # skip undefined/external refs
            "--numeric-sort",  # sort by address for determinism
            elf_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        print(f"Error: nm failed:\n{result.stderr.strip()}")
        sys.exit(1)

    entries = []
    for line in result.stdout.splitlines():
        parts = line.split()
        # nm bsd format: <addr> <type> <name>
        if len(parts) != 3:
            continue
        addr_str, sym_type, name = parts

        # Skip ARM mapping symbols ($a, $d, $t, $x and variants like $d.N)
        if name.startswith("$"):
            continue

        # Skip linker-internal symbols
        if name.startswith("__aeabi_unwind_cpp_pr"):
            continue

        try:
            addr = int(addr_str, 16)
        except ValueError:
            continue

        entries.append((name, addr))

    if not entries:
        print("Warning: no symbols extracted — is this a stripped ELF?")

    entries.sort(key=lambda e: e[0].lower())

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        for name, addr in entries:
            f.write(f"{name} 0x{addr:08x}\n")

    print(f"Wrote {len(entries)} symbols to {output_path}")
