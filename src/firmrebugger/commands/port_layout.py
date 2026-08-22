"""Migrate a FirmReBugger checkout from the old folder layout to the current one.

Old layout:
    <Benchmark>/<Binary>/binary/<elf>
    <Benchmark>/<Binary>/fuzzers/<Fuzzer>/fuzzing_out/<run_name>/

New layout:
    <Benchmark>/<Binary>/<elf>
    <Benchmark>/<Binary>/<Fuzzer>/
    outputs/<run_name>/<Benchmark>-<Binary>-<Fuzzer>/

`FirmBench*`/`Fuzzers/` themselves are tracked in git, so `git pull` handles
those on its own. What it *can't* fix is gitignored, purely-local data: old
`fuzzing_out/` run results, and any custom binaries/fuzzer overrides a user
added locally under the old convention. That's what this script moves.
"""

import glob
import json
import os
import shutil

from firmrebugger.common import (
    CURRENT_LAYOUT_VERSION,
    LEGACY_LAYOUT_MARKER,
    detect_legacy_layout,
    get_frb_base_dir,
)


def _log(msg):
    print(msg)


def _iter_legacy_dirs(base_dir, name):
    """Yield (benchmark, binary, path) for every legacy `<name>/` wrapper dir."""
    for path in sorted(glob.glob(os.path.join(base_dir, "*", "*", name))):
        if not os.path.isdir(path):
            continue
        binary = os.path.basename(os.path.dirname(path))
        benchmark = os.path.basename(os.path.dirname(os.path.dirname(path)))
        yield benchmark, binary, path


def _move_contents(src_dir, dst_dir, dry_run, skip=()):
    """Move every item directly under src_dir into dst_dir (skipping conflicts).

    `skip` names are handled elsewhere (e.g. `fuzzing_out/`, which gets its
    own relocation logic) - in a real run they're already gone by the time
    this runs, but in `--dry-run` nothing was actually removed, so they'd
    otherwise show up here too as a misleading plain move.
    """
    if not dry_run:
        os.makedirs(dst_dir, exist_ok=True)
    for item in sorted(os.listdir(src_dir)):
        if item in skip:
            continue
        src_item = os.path.join(src_dir, item)
        dst_item = os.path.join(dst_dir, item)
        if os.path.exists(dst_item):
            _log(f"  [skip] {dst_item} already exists, leaving {src_item} in place")
            continue
        _log(f"  [move] {src_item} -> {dst_item}")
        if not dry_run:
            shutil.move(src_item, dst_item)


def _rmdir_if_empty(path, dry_run):
    if not dry_run and os.path.isdir(path) and not os.listdir(path):
        os.rmdir(path)


def _fix_frb_info_run_name(run_dir, run_name, dry_run):
    """Old frb_info.json files use the key `output_dir` instead of `run_name`.

    `list_finished_jobs()` can already recover `run_name` from the output
    path itself, so this isn't strictly required for the app to work - but
    it keeps the on-disk data consistent with what current code writes.
    """
    info_path = os.path.join(run_dir, "frb_info.json")
    if not os.path.isfile(info_path):
        return
    try:
        with open(info_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        _log(f"  [warn] could not read {info_path}: {e}")
        return

    changed = False
    if not data.get("run_name"):
        data["run_name"] = data.get("output_dir") or run_name
        changed = True
    if "output_dir" in data:
        del data["output_dir"]
        changed = True

    if changed:
        _log(f"  [fix]  {info_path}: run_name={data['run_name']!r}")
        if not dry_run:
            with open(info_path, "w") as f:
                json.dump(data, f, indent=2)


def _port_fuzzing_out(benchmark, binary, fuzzer, fuzzing_out_dir, base_dir, dry_run):
    for run_name in sorted(os.listdir(fuzzing_out_dir)):
        run_src = os.path.join(fuzzing_out_dir, run_name)
        if not os.path.isdir(run_src):
            continue
        run_dst = os.path.join(
            base_dir, "outputs", run_name, f"{benchmark}-{binary}-{fuzzer}"
        )
        if os.path.exists(run_dst):
            _log(f"  [skip] {run_dst} already exists, leaving {run_src} in place")
            continue
        _log(f"  [move] {run_src} -> {run_dst}")
        if not dry_run:
            os.makedirs(os.path.dirname(run_dst), exist_ok=True)
            shutil.move(run_src, run_dst)
            _fix_frb_info_run_name(run_dst, run_name, dry_run)
        else:
            _fix_frb_info_run_name(run_src, run_name, dry_run)


def _stamp_marker(base_dir):
    marker_path = os.path.join(base_dir, LEGACY_LAYOUT_MARKER)
    try:
        with open(marker_path, "w") as f:
            f.write(CURRENT_LAYOUT_VERSION)
    except OSError as e:
        _log(f"[warn] could not write layout marker {marker_path}: {e}")


def run_port_layout(dry_run=False, assume_yes=False):
    # Bypass the startup guard - this command is exactly how you're supposed
    # to escape it.
    base_dir = get_frb_base_dir(check_layout=False)
    legacy = detect_legacy_layout(base_dir)

    if not legacy:
        print(f"No legacy layout detected under {base_dir}. Nothing to do.")
        if not dry_run:
            _stamp_marker(base_dir)
        return

    print(f"Found {len(legacy)} legacy folder(s) under {base_dir}:")
    for path in legacy:
        print(f"  - {path}")

    if dry_run:
        print("\n[dry run] previewing changes, nothing will be moved:\n")
    elif not assume_yes:
        answer = input(
            "\nThis will move the folders above into the new FirmReBugger "
            "layout. Continue? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return
        print()

    # 1. Flatten `<Benchmark>/<Binary>/binary/` -> `<Benchmark>/<Binary>/`.
    for benchmark, binary, binary_dir in _iter_legacy_dirs(base_dir, "binary"):
        print(f"[{benchmark}/{binary}] flattening binary/ ...")
        target_dir = os.path.join(base_dir, benchmark, binary)
        _move_contents(binary_dir, target_dir, dry_run)
        _rmdir_if_empty(binary_dir, dry_run)

    # 2. Flatten `<Benchmark>/<Binary>/fuzzers/<Fuzzer>/` -> `<Benchmark>/<Binary>/<Fuzzer>/`,
    #    relocating `fuzzing_out/<run_name>/` -> `outputs/<run_name>/<Benchmark>-<Binary>-<Fuzzer>/`.
    for benchmark, binary, fuzzers_dir in _iter_legacy_dirs(base_dir, "fuzzers"):
        print(f"[{benchmark}/{binary}] flattening fuzzers/ ...")
        for fuzzer in sorted(os.listdir(fuzzers_dir)):
            fuzzer_src = os.path.join(fuzzers_dir, fuzzer)
            if not os.path.isdir(fuzzer_src):
                continue

            fuzzing_out_dir = os.path.join(fuzzer_src, "fuzzing_out")
            if os.path.isdir(fuzzing_out_dir):
                _port_fuzzing_out(
                    benchmark, binary, fuzzer, fuzzing_out_dir, base_dir, dry_run
                )
                _rmdir_if_empty(fuzzing_out_dir, dry_run)

            # Old per-target runner overrides were named `<fuzzer>-run.sh`.
            old_runner = os.path.join(fuzzer_src, f"{fuzzer}-run.sh")
            if os.path.isfile(old_runner):
                new_runner = os.path.join(fuzzer_src, "runner.sh")
                _log(f"  [rename] {old_runner} -> {new_runner}")
                if not dry_run:
                    shutil.move(old_runner, new_runner)

            fuzzer_dst = os.path.join(base_dir, benchmark, binary, fuzzer)
            _move_contents(fuzzer_src, fuzzer_dst, dry_run, skip={"fuzzing_out"})
            _rmdir_if_empty(fuzzer_src, dry_run)

        _rmdir_if_empty(fuzzers_dir, dry_run)

    # 3. Recover any custom default runners left at the old location.
    old_runners_dir = os.path.join(base_dir, "src", "firmrebugger", "fuzzer_runners")
    if os.path.isdir(old_runners_dir):
        print("[Fuzzers/] recovering custom default runners ...")
        for filename in sorted(os.listdir(old_runners_dir)):
            if not filename.endswith("-run.sh"):
                continue
            fuzzer = filename[: -len("-run.sh")]
            src = os.path.join(old_runners_dir, filename)
            dst_dir = os.path.join(base_dir, "Fuzzers", fuzzer)
            dst = os.path.join(dst_dir, "runner.sh")
            if os.path.exists(dst):
                _log(f"  [skip] {dst} already exists")
                continue
            _log(f"  [move] {src} -> {dst}")
            if not dry_run:
                os.makedirs(dst_dir, exist_ok=True)
                shutil.move(src, dst)
        _rmdir_if_empty(old_runners_dir, dry_run)

    if dry_run:
        print("\n[dry run] no changes were made. Re-run without --dry-run to apply.")
        return

    remaining = detect_legacy_layout(base_dir)
    if remaining:
        print(
            f"\nDone, but {len(remaining)} legacy folder(s) could not be fully "
            "migrated (see the [skip] lines above for conflicts to resolve by hand):"
        )
        for path in remaining:
            print(f"  - {path}")
        print("Re-run `uv run frb port-layout` after resolving the conflicts.")
        return

    _stamp_marker(base_dir)
    print(f"\nMigration complete. {base_dir} is now on the current layout.")
