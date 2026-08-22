import glob
import os
import re
from collections import defaultdict

import yaml

from firmrebugger.common import get_frb_base_dir, get_fuzzer_meta

BENCHMARKS = ["FirmBench", "FirmBenchX", "FirmBenchDMA"]
VALID_STATUSES = {"confirmed", "false_positive", "needs_triage"}

# Attribution labels for bug-ID prefixes that don't correspond to an
# integrated fuzzer folder (manual FirmReBugger patches, or tools referenced
# in the modification table but not wired into `Fuzzers/`). Every other
# prefix is read from `Fuzzers/<fuzzer>/fuzzer.yml`'s `bug_prefix` field.
EXTRA_PREFIX_SOURCES = {
    "FRB": "FirmReBugger",
    "HAL": "HALucinator",
}


def _load_prefix_sources(base_dir):
    sources = dict(EXTRA_PREFIX_SOURCES)
    fuzzers_dir = os.path.join(base_dir, "Fuzzers")
    if not os.path.isdir(fuzzers_dir):
        return sources
    for fuzzer in sorted(os.listdir(fuzzers_dir)):
        prefix = get_fuzzer_meta(base_dir, fuzzer).get("bug_prefix")
        if prefix:
            sources[str(prefix).upper()] = fuzzer
    return sources

_ID_LITERAL_RE = re.compile(
    r'report_(?:detected_triggered|reached)\(\s*"(?:FP_)?([A-Z]+)(\d+)"\s*\)'
)
_ID_RE = re.compile(r"^([A-Za-z]+)(\d+)$")
_CWE_RE = re.compile(r"^CWE-[1-9]\d*$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _scan_bug_descriptor_ids(base_dir):
    """Scan every bug_descriptor.c for bug-id literals actually reported at runtime.

    Returns {(prefix, number): [(benchmark, binary), ...]}
    """
    found = defaultdict(list)
    for benchmark in BENCHMARKS:
        pattern = os.path.join(base_dir, benchmark, "*", "bug_descriptor.c")
        for path in glob.glob(pattern):
            binary = os.path.basename(os.path.dirname(path))
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read()
            except OSError:
                continue
            for prefix, number in set(_ID_LITERAL_RE.findall(content)):
                found[(prefix, int(number))].append((benchmark, binary))
    return found


def _parse_detail_file(path):
    with open(path, "r", errors="replace") as f:
        content = f.read()

    if not content.startswith("---"):
        return None, f"missing frontmatter: {path}"

    parts = content.split("---", 2)
    if len(parts) < 3:
        return None, f"malformed frontmatter: {path}"

    try:
        frontmatter = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as e:
        return None, f"invalid YAML frontmatter in {path}: {e}"

    body = parts[2].strip()

    required = ["bug_id", "binary", "mcu", "cwes", "benchmarks", "status"]
    missing = [k for k in required if k not in frontmatter]
    if missing:
        return None, f"{path} missing required field(s): {', '.join(missing)}"

    if not frontmatter["mcu"] or not isinstance(frontmatter["mcu"], str):
        return None, f"{path} 'mcu' must be a non-empty string"

    cwes = frontmatter["cwes"]
    if not isinstance(cwes, list) or not cwes:
        return None, f"{path} 'cwes' must be a non-empty list"

    invalid_cwes = [
        cwe for cwe in cwes if not isinstance(cwe, str) or not _CWE_RE.match(cwe)
    ]
    if invalid_cwes:
        return None, (
            f"{path} has invalid CWE value(s) {invalid_cwes} "
            "(expected strings such as CWE-787)"
        )

    if len(cwes) != len(set(cwes)):
        return None, f"{path} 'cwes' contains duplicate values"

    cves = frontmatter.get("cves", [])
    if not isinstance(cves, list):
        return None, f"{path} 'cves' must be a list when present"

    invalid_cves = [
        cve for cve in cves if not isinstance(cve, str) or not _CVE_RE.match(cve)
    ]
    if invalid_cves:
        return None, (
            f"{path} has invalid CVE value(s) {invalid_cves} "
            "(expected strings such as CVE-2022-3806)"
        )

    if len(cves) != len(set(cves)):
        return None, f"{path} 'cves' contains duplicate values"

    benchmarks = frontmatter["benchmarks"]
    if not isinstance(benchmarks, list) or not benchmarks:
        return None, f"{path} 'benchmarks' must be a non-empty list"

    invalid_benchmarks = [b for b in benchmarks if b not in BENCHMARKS]
    if invalid_benchmarks:
        return None, (
            f"{path} has unknown benchmark(s) {invalid_benchmarks} "
            f"(expected some subset of {BENCHMARKS})"
        )

    benchmark_binaries = frontmatter.get("benchmark_binaries", {})
    if not isinstance(benchmark_binaries, dict):
        return None, f"{path} 'benchmark_binaries' must be a mapping when present"

    invalid_aliases = [
        (benchmark, binary)
        for benchmark, binary in benchmark_binaries.items()
        if benchmark not in benchmarks or not isinstance(binary, str) or not binary
    ]
    if invalid_aliases:
        return None, (
            f"{path} has invalid benchmark_binaries value(s) {invalid_aliases}; "
            "keys must be listed benchmarks and values non-empty directory names"
        )

    additional_locations = frontmatter.get("additional_locations", [])
    if not isinstance(additional_locations, list):
        return None, f"{path} 'additional_locations' must be a list when present"

    normalized_locations = []
    for location in additional_locations:
        if not isinstance(location, dict):
            return None, (
                f"{path} has invalid additional location {location!r}; "
                "each location must be a mapping"
            )
        benchmark = location.get("benchmark")
        binary = location.get("binary")
        mcu = location.get("mcu")
        if (
            benchmark not in BENCHMARKS
            or not isinstance(binary, str)
            or not binary
            or (mcu is not None and (not isinstance(mcu, str) or not mcu))
        ):
            return None, (
                f"{path} has invalid additional location {location!r}; "
                f"benchmark must be one of {BENCHMARKS}, binary must be a "
                "non-empty string, and mcu (when present) must be a non-empty string"
            )
        normalized_locations.append(
            {"benchmark": benchmark, "binary": binary, "mcu": mcu}
        )

    location_keys = [
        (location["benchmark"], location["binary"])
        for location in normalized_locations
    ]
    if len(location_keys) != len(set(location_keys)):
        return None, f"{path} 'additional_locations' contains duplicate locations"

    if frontmatter["status"] not in VALID_STATUSES:
        return None, (
            f"{path} has invalid status '{frontmatter['status']}' "
            f"(expected one of {sorted(VALID_STATUSES)})"
        )

    return {
        "bug_id": str(frontmatter["bug_id"]),
        "binary": frontmatter["binary"],
        "mcu": frontmatter["mcu"],
        "cwes": cwes,
        "cves": cves,
        "benchmarks": benchmarks,
        "benchmark_binaries": benchmark_binaries,
        "additional_locations": normalized_locations,
        "status": frontmatter["status"],
        "summary": frontmatter.get("summary", ""),
        "body": body,
        "path": path,
    }, None


def scan_detail_files(base_dir):
    """Scan bug_analysis/bugs/<BUG_ID>.md detail files.

    Returns (entries, errors) where entries is a list of parsed dicts.
    """
    entries = []
    errors = []

    pattern = os.path.join(base_dir, "bug_analysis", "bugs", "*.md")
    for path in sorted(glob.glob(pattern)):
        entry, error = _parse_detail_file(path)
        if error:
            errors.append(error)
            continue

        expected_id = os.path.splitext(os.path.basename(path))[0]
        if entry["bug_id"] != expected_id:
            errors.append(
                f"{path}: frontmatter bug_id '{entry['bug_id']}' "
                f"does not match filename '{expected_id}.md'"
            )

        entries.append(entry)

    return entries, errors


def build_registry_report(base_dir):
    """Cross-reference documented detail files against live bug_descriptor.c literals."""
    entries, parse_errors = scan_detail_files(base_dir)
    code_ids = _scan_bug_descriptor_ids(base_dir)

    documented_ids = defaultdict(list)
    for entry in entries:
        match = _ID_RE.match(entry["bug_id"])
        if not match:
            continue
        prefix, number = match.group(1), int(match.group(2))
        documented_ids[(prefix, number)].append(entry)

    def claimed_locations(entry):
        aliases = entry["benchmark_binaries"]
        primary = {
            (benchmark, aliases.get(benchmark, entry["binary"]))
            for benchmark in entry["benchmarks"]
        }
        additional = {
            (location["benchmark"], location["binary"])
            for location in entry["additional_locations"]
        }
        return primary | additional

    # Duplicate bug IDs used by more than one *distinct* binary in bug_descriptor.c.
    # The same binary appearing under multiple benchmark suites (e.g. Gateway in
    # both FirmBench and FirmBenchX) is the same underlying target, not a clash.
    def canonical_binary(key, benchmark, binary):
        for entry in documented_ids.get(key, []):
            if (benchmark, binary) in claimed_locations(entry):
                return entry["binary"]
        return binary

    collisions = {
        key: locations
        for key, locations in code_ids.items()
        if len(
            {
                canonical_binary(key, benchmark, binary)
                for benchmark, binary in locations
            }
        )
        > 1
    }

    # IDs live in code with no matching detail file yet.
    undocumented = sorted(
        (f"{prefix}{number:02d}", locations)
        for (prefix, number), locations in code_ids.items()
        if (prefix, number) not in documented_ids
    )

    # Detail files describing an ID that no longer appears in any bug_descriptor.c.
    orphaned = [
        entry
        for key, entries_for_key in documented_ids.items()
        if key not in code_ids
        for entry in entries_for_key
    ]

    # Detail files whose binary/benchmarks frontmatter doesn't match where the
    # ID actually shows up in bug_descriptor.c.
    mismatched = []
    for entry in entries:
        match = _ID_RE.match(entry["bug_id"])
        if not match:
            continue
        key = (match.group(1), int(match.group(2)))
        code_locations = set(code_ids.get(key, []))
        extra = claimed_locations(entry) - code_locations
        if extra:
            mismatched.append((entry, sorted(extra)))

    # Next free number per prefix, considering both code and documented IDs.
    all_numbers_by_prefix = defaultdict(set)
    for prefix, number in code_ids:
        all_numbers_by_prefix[prefix].add(number)
    for prefix, number in documented_ids:
        all_numbers_by_prefix[prefix].add(number)

    next_free = {
        prefix: max(numbers) + 1 for prefix, numbers in all_numbers_by_prefix.items()
    }

    return {
        "entries": entries,
        "parse_errors": parse_errors,
        "collisions": collisions,
        "undocumented": undocumented,
        "orphaned": orphaned,
        "mismatched": mismatched,
        "next_free": next_free,
        "prefix_sources": _load_prefix_sources(base_dir),
    }


def _format_locations(locations):
    return ", ".join(f"{b}/{n}" for b, n in locations)


def _generate_table_lines(entries, link_prefix="bugs/"):
    entries = sorted(entries, key=lambda e: (e["binary"], e["bug_id"]))

    if not entries:
        return ["_No documented bugs yet._"]

    lines = [
        "| Bug ID | Binary | MCU | CWEs | Benchmarks | Status | Summary |",
        "|---|---|---|---|---|---|---|",
    ]
    for entry in entries:
        rel_path = f"{link_prefix}{entry['bug_id']}.md"
        locations = [
            {
                "benchmark": benchmark,
                "binary": entry["benchmark_binaries"].get(
                    benchmark, entry["binary"]
                ),
                "mcu": entry["mcu"],
            }
            for benchmark in entry["benchmarks"]
        ] + entry["additional_locations"]
        binaries = ", ".join(dict.fromkeys(location["binary"] for location in locations))
        mcus = ", ".join(
            dict.fromkeys(
                location["mcu"] or entry["mcu"] for location in locations
            )
        )
        benchmarks = ", ".join(
            dict.fromkeys(location["benchmark"] for location in locations)
        )
        cwes = ", ".join(entry["cwes"])
        lines.append(
            f"| [{entry['bug_id']}]({rel_path}) | {binaries} | {mcus} | "
            f"{cwes} | {benchmarks} | {entry['status']} | {entry['summary']} |"
        )
    return lines


def generate_registry_report_markdown(report):
    lines = [
        *_generate_table_lines(report["entries"]),
        "",
    ]

    if report["undocumented"]:
        lines.append("## Undocumented (live in bug_descriptor.c, no detail file)")
        lines.append("")
        for bug_id, locations in report["undocumented"]:
            lines.append(f"- `{bug_id}` — {_format_locations(locations)}")
        lines.append("")

    if report["collisions"]:
        lines.append("## ID collisions (same number reused across binaries)")
        lines.append("")
        for (prefix, number), locations in sorted(report["collisions"].items()):
            lines.append(f"- `{prefix}{number:02d}` — {_format_locations(locations)}")
        lines.append("")

    if report["mismatched"]:
        lines.append(
            "## Mismatched (detail file claims a benchmark/binary not seen in code)"
        )
        lines.append("")
        for entry, extra in report["mismatched"]:
            lines.append(
                f"- `{entry['bug_id']}` ({entry['path']}) — claims {_format_locations(extra)}"
            )
        lines.append("")

    if report["next_free"]:
        lines.append("## Next free ID per prefix")
        lines.append("")
        lines.append("| Prefix | Fuzzer / source | Next free ID |")
        lines.append("|---|---|---|")
        for prefix, number in sorted(report["next_free"].items()):
            source = report["prefix_sources"].get(prefix, "?")
            lines.append(f"| `{prefix}` | {source} | `{prefix}{number:02d}` |")
        lines.append("")

    return "\n".join(lines)


README_SECTION_START = (
    "<!-- BEGIN bug-registry (generated by `frb bug-registry`; do not hand-edit) -->"
)
README_SECTION_END = "<!-- END bug-registry -->"


def _update_readme_registry(base_dir, report_markdown):
    readme_path = os.path.join(base_dir, "bug_analysis", "README.md")
    with open(readme_path, "r") as f:
        content = f.read()

    block = f"{README_SECTION_START}\n\n{report_markdown}\n{README_SECTION_END}"

    if README_SECTION_START in content and README_SECTION_END in content:
        pattern = re.compile(
            re.escape(README_SECTION_START) + r".*?" + re.escape(README_SECTION_END),
            re.DOTALL,
        )
        content = pattern.sub(block, content, count=1)
    else:
        content = content.rstrip("\n") + "\n\n## Bug registry\n\n" + block + "\n"

    with open(readme_path, "w") as f:
        f.write(content)
    return readme_path


def run_bug_registry(next_prefix=None):
    base_dir = get_frb_base_dir()
    report = build_registry_report(base_dir)

    if next_prefix:
        prefix = next_prefix.upper()
        next_number = report["next_free"].get(prefix, 1)
        print(f"{prefix}{next_number:02d}")
        return

    readme_path = _update_readme_registry(
        base_dir, generate_registry_report_markdown(report)
    )
    print(f"Wrote {readme_path}")

    if report["parse_errors"]:
        print("\nParse errors:")
        for error in report["parse_errors"]:
            print(f"  - {error}")

    if report["undocumented"]:
        print(
            f"\n{len(report['undocumented'])} undocumented bug ID(s) found in bug_descriptor.c:"
        )
        for bug_id, locations in report["undocumented"]:
            print(f"  - {bug_id} ({_format_locations(locations)})")

    if report["collisions"]:
        print(f"\n{len(report['collisions'])} ID collision(s):")
        for (prefix, number), locations in sorted(report["collisions"].items()):
            print(f"  - {prefix}{number:02d} used by {_format_locations(locations)}")

    if report["orphaned"]:
        print(
            f"\n{len(report['orphaned'])} orphaned detail file(s) (ID no longer in any bug_descriptor.c):"
        )
        for entry in report["orphaned"]:
            print(f"  - {entry['path']}")

    if report["mismatched"]:
        print(f"\n{len(report['mismatched'])} mismatched detail file(s):")
        for entry, extra in report["mismatched"]:
            print(
                f"  - {entry['bug_id']} ({entry['path']}) claims {_format_locations(extra)}"
            )

    print("\nNext free ID per prefix:")
    for prefix, number in sorted(report["next_free"].items()):
        print(f"  - {prefix} -> {prefix}{number:02d}")
