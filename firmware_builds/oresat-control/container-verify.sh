#!/usr/bin/env bash
set -euo pipefail

built="/out/${OUTPUT_ELF:?missing OUTPUT_ELF}"
reference=/reference.elf

size_triplet() {
    arm-none-eabi-size "$1" | awk 'NR == 2 {print $1, $2, $3}'
}

symbol_size() {
    local elf=$1 symbol=$2
    arm-none-eabi-nm -S --defined-only "$elf" |
        awk -v symbol="$symbol" '$4 == symbol && !found {size=tolower($2); found=1} END {print found ? size : "absent"}'
}

expected_sizes=$(size_triplet "$reference")
built_sizes=$(size_triplet "$built")
[[ "$built_sizes" == "$expected_sizes" ]] || {
    echo "section totals differ: built=[$built_sizes] reference=[$expected_sizes]" >&2
    exit 1
}

if [[ "$VARIANT_KIND" == firmbench ]]; then
    symbols=(chVTDoTickI ax5043GetStatus ax5043Exchange)
else
    symbols=(chVTDoTickI ax5043SPIExchange ax5043GetStatus ax5043Exchange)
fi

for symbol in "${symbols[@]}"; do
    expected=$(symbol_size "$reference" "$symbol")
    actual=$(symbol_size "$built" "$symbol")
    [[ "$actual" == "$expected" ]] || {
        echo "$symbol size differs: built=$actual reference=$expected" >&2
        exit 1
    }
done

echo "structural verification passed: text/data/bss and recovered patch functions match"
echo "note: strict loadable-byte identity is a separate --strict check; see SOURCES.md"
