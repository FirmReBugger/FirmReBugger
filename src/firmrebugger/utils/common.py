import curses
import os
import re


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
        while True:
            stdscr.clear()
            stdscr.addstr(0, 0, title, curses.A_BOLD)
            stdscr.addstr(
                1,
                0,
                "Use ↑ and ↓ to navigate. Space to toggle. Enter to finish. 'a' to (de)select all.",
                curses.A_BOLD,
            )
            stdscr.addstr(2, 0, "Press 'q' to quit.")
            for idx, option in enumerate(options):
                selected_marker = "[X]" if option in selected else "[ ]"
                if idx == current_selection:
                    stdscr.addstr(
                        idx + 3, 0, f"> {selected_marker} {option}", curses.A_REVERSE
                    )
                else:
                    stdscr.addstr(idx + 3, 0, f"  {selected_marker} {option}")

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

    return curses.wrapper(menu)


def get_frb_base_dir():
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
    return base_dir


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
