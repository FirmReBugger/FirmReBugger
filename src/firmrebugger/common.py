import curses
import glob
import os
import re

import yaml


def parse_fuzzing_time(time_str):
    time_str = time_str.strip().lower()
    match = re.match(r"^(\d+)([hms])$", time_str)
    if not match:
        raise ValueError(
            "Time format must include a unit: 'h' for hours, 'm' for minutes, 's' for seconds. Example: '24h', '3600m', '86400s'"
        )
    value, unit = match.groups()
    value = int(value)

    if unit == "h":
        return str(value * 3600)
    elif unit == "m":
        return str(value * 60)
    elif unit == "s":
        return str(value)
    else:
        return None


def menu(title, options):
    options = sorted(options)

    def menu(stdscr):
        curses.curs_set(0)
        stdscr.clear()
        selected = []
        current_selection = 0
        select_all = False

        height, width = stdscr.getmaxyx()
        required_height = len(options) + 3

        if height < required_height or width < 80:
            stdscr.clear()
            error_msg = f"Terminal too small! Need at least {required_height} rows and 80 columns."
            current_msg = f"Current size: {height} rows x {width} columns"
            try:
                stdscr.addstr(0, 0, error_msg, curses.A_BOLD)
                stdscr.addstr(1, 0, current_msg)
                stdscr.addstr(2, 0, "Please resize your terminal and try again.")
                stdscr.addstr(3, 0, "Press any key to exit...")
                stdscr.getch()
            except curses.error:
                pass
            raise RuntimeError(
                f"Terminal too small. Need at least {required_height} rows and 80 columns (current: {height}x{width})"
            )

        while True:
            try:
                stdscr.clear()
                stdscr.addstr(0, 0, title, curses.A_BOLD)
                stdscr.addstr(
                    1,
                    0,
                    "Use ↑ and ↓ to navigate. Space to toggle. Enter to finish. 'a' to (de)select all. Press 'q' to quit.",
                )
                for idx, option in enumerate(options):
                    selected_marker = "[X]" if option in selected else "[ ]"
                    if idx == current_selection:
                        stdscr.addstr(
                            idx + 3,
                            0,
                            f"> {selected_marker} {option}",
                            curses.A_REVERSE,
                        )
                    else:
                        stdscr.addstr(idx + 3, 0, f"  {selected_marker} {option}")
            except curses.error:
                height, width = stdscr.getmaxyx()
                raise RuntimeError(
                    f"Terminal too small or rendering error. Need at least {required_height} rows and 80 columns (current: {height}x{width})"
                )

            key = stdscr.getch()

            if key == curses.KEY_UP and current_selection > 0:
                current_selection -= 1
            elif key == curses.KEY_DOWN and current_selection < len(options) - 1:
                current_selection += 1
            elif key == ord(" "):
                if current_selection < len(options):
                    option = options[current_selection]
                    if option in selected:
                        selected.remove(option)
                    else:
                        selected.append(option)
            elif key == ord("a"):
                if select_all:
                    selected = []
                else:
                    selected = options[:]
                select_all = not select_all
            elif key in (ord("\n"), curses.KEY_ENTER, 10, 13):
                return selected
            elif key == ord("q"):
                return None

    try:
        return curses.wrapper(menu)
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(
            f"Error displaying menu: {e}. This may be due to terminal size constraints."
        )


# Bumped whenever the on-disk folder layout changes in a way old checkouts
# can't just pick up via `git pull` (i.e. it touches gitignored user data
# like `outputs/`). Written to `LEGACY_LAYOUT_MARKER` in the base dir once
# we've confirmed (or migrated) that the layout is current, so we don't
# re-scan the filesystem on every call.
CURRENT_LAYOUT_VERSION = "2"
LEGACY_LAYOUT_MARKER = ".frb_layout_version"

_layout_checked_dirs = set()


def detect_legacy_layout(base_dir):
    """Return pre-restructure paths still present under `base_dir`, if any.

    The old layout nested a binary's ELF under a `binary/` subfolder and its
    fuzzer configs + fuzzing output under `fuzzers/<fuzzer>/fuzzing_out/`:

        <Benchmark>/<Binary>/binary/<elf>
        <Benchmark>/<Binary>/fuzzers/<Fuzzer>/fuzzing_out/<run_name>/

    The current layout is flat, with run output living under a top-level
    `outputs/` tree instead:

        <Benchmark>/<Binary>/<elf>
        <Benchmark>/<Binary>/<Fuzzer>/
        outputs/<run_name>/<Benchmark>-<Binary>-<Fuzzer>/

    Used both to gate startup (see `get_frb_base_dir`) and by
    `frb port-layout`, which migrates whatever this finds.
    """
    legacy = []
    for pattern in ("*/*/binary", "*/*/fuzzers"):
        for path in glob.glob(os.path.join(base_dir, pattern)):
            if os.path.isdir(path):
                legacy.append(os.path.relpath(path, base_dir))
    return sorted(legacy)


def _ensure_layout_is_current(base_dir):
    if base_dir in _layout_checked_dirs:
        return

    marker_path = os.path.join(base_dir, LEGACY_LAYOUT_MARKER)
    try:
        with open(marker_path) as f:
            if f.read().strip() == CURRENT_LAYOUT_VERSION:
                _layout_checked_dirs.add(base_dir)
                return
    except OSError:
        pass

    legacy_paths = detect_legacy_layout(base_dir)
    if legacy_paths:
        example = legacy_paths[0]
        raise RuntimeError(
            "FirmReBugger's folder layout has changed and this checkout at "
            f"{base_dir} still has {len(legacy_paths)} folder(s) in the old "
            f"layout (e.g. '{example}').\n"
            "Binaries/fuzzer configs are now flat and run output lives "
            "under a top-level outputs/ tree - see the README's 'Folder "
            "Structure' section.\n\n"
            "Run the migration script before starting FirmReBugger again:\n\n"
            "    uv run frb port-layout\n\n"
            "(add --dry-run first to preview what it will move)."
        )

    # Nothing legacy found - fresh checkout, or already migrated by hand.
    # Stamp the marker so future startups skip the filesystem scan.
    try:
        with open(marker_path, "w") as f:
            f.write(CURRENT_LAYOUT_VERSION)
    except OSError:
        pass
    _layout_checked_dirs.add(base_dir)


def get_frb_base_dir(check_layout=True):
    base_dir = os.environ.get("FIRMREBUGGER_BASE_DIR")
    if not base_dir:
        raise EnvironmentError("FIRMREBUGGER_BASE_DIR environment variable is not set.")
    # Check if 'firmrebugger' folder exists in base_dir
    base_dir = os.path.abspath(base_dir)
    firmrebugger_path = os.path.join(base_dir, "src", "firmrebugger")
    if not os.path.isdir(firmrebugger_path):
        raise FileNotFoundError(
            f"'firmrebugger' folder not found in {base_dir}. check FIRMREBUGGER_BASE_DIR is set correctly."
        )
    if check_layout:
        _ensure_layout_is_current(base_dir)
    return base_dir


def get_binary_dir(base_dir, benchmark, binary):
    """<base_dir>/<benchmark>/<binary>"""
    return os.path.join(base_dir, benchmark, binary)


def get_target_fuzzer_dir(base_dir, benchmark, binary, fuzzer):
    """<base_dir>/<benchmark>/<binary>/<fuzzer>"""
    return os.path.join(base_dir, benchmark, binary, fuzzer)


def get_run_output_dir(base_dir, run_name, benchmark, binary, fuzzer):
    """<base_dir>/outputs/<run_name>/<benchmark>-<binary>-<fuzzer>"""
    return os.path.join(
        base_dir, "outputs", run_name, f"{benchmark}-{binary}-{fuzzer}"
    )


def get_fuzzer_meta(base_dir, fuzzer):
    """Load Fuzzers/<fuzzer>/fuzzer.yml, if present.

    Optional per-fuzzer metadata (e.g. `bug_prefix`, `bind_mount`) that lets
    the rest of FirmReBugger avoid hardcoding fuzzer names. Fuzzers that
    don't need any of these knobs can simply omit the file.
    """
    meta_path = os.path.join(base_dir, "Fuzzers", fuzzer, "fuzzer.yml")
    if not os.path.isfile(meta_path):
        return {}
    with open(meta_path, "r") as f:
        return yaml.safe_load(f) or {}


def get_working_dirs(folder_path):
    if not os.path.isdir(folder_path):
        return f"The directory '{folder_path}' does not exist."

    folders = [
        os.path.abspath(os.path.join(folder_path, item))
        for item in os.listdir(folder_path)
        if os.path.isdir(os.path.join(folder_path, item)) and item.startswith("output-")
    ]
    folders.sort()
    if not folders:
        return f"No output directories found in '{folder_path}'."
    return folders
