"""Install the Fuzzware native persistent replay hooks during image build."""

from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one match in {path}, found {count}")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    root = Path(sys.argv[1])
    native_c = root / "harness/fuzzware_harness/native/native_hooks.c"
    native_h = root / "harness/fuzzware_harness/native/native_hooks.h"
    native_py = root / "harness/fuzzware_harness/native.py"

    replace_once(
        native_h,
        "uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path);\n#endif\n",
        "uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path);\n"
        "uc_err reset_session(uc_engine *uc);\n#endif\n",
    )

    replace_once(
        native_c,
        "uc_err custom_exit_reason = UC_ERR_OK;\n",
        "uc_err custom_exit_reason = UC_ERR_OK;\n"
        "extern int firmrebugger_reset_session(uc_engine *uc);\n"
        "static int persistent_snapshot_ready = 0;\n",
    )
    replace_once(
        native_c,
        """    custom_exit_reason = UC_ERR_OK;
}

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path) {
""",
        """    custom_exit_reason = UC_ERR_OK;
}

uc_err reset_session(uc_engine *uc) {
    if (persistent_snapshot_ready) {
        restore_snapshot(uc);
    }
    if (firmrebugger_reset_session(uc) != UC_ERR_OK) {
        return UC_ERR_EXCEPTION;
    }
    return UC_ERR_OK;
}

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path) {
""",
    )
    replace_once(
        native_c,
        """    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    init_bitmap(uc);

    /*
""",
        """    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    init_bitmap(uc);

    if (getenv("FRB_REPLAY_WORKER") && persistent_snapshot_ready) {
        int sig;
        input_path = p_input_path;
        input_already_given = 0;
        duplicate_exit = false;
        custom_exit_reason = UC_ERR_OK;
        sig = run_single(uc);
        restore_snapshot(uc);
        if (do_print_exit_info) {
            if (sig) {
                printf("Emulation crashed with signal %d\\n", sig);
            } else {
                uint32_t current_pc;
                uc_reg_read(uc, UC_ARM_REG_PC, &current_pc);
                printf("Exited without crash at 0x%08x - If no other reason, we ran into one of the limits\\n", current_pc);
            }
        }
        return UC_ERR_OK;
    }

    /*
""",
    )
    replace_once(
        native_c,
        """        }
    } else {
        puts("Running without a fork server");
""",
        """        }
    } else if (getenv("FRB_REPLAY_WORKER")) {
        int sig;
        uc_fuzzer_reset_cov(uc, 1);
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        trigger_snapshotting(uc);
        persistent_snapshot_ready = 1;
        duplicate_exit = false;
        sig = run_single(uc);
        restore_snapshot(uc);
        if (do_print_exit_info) {
            if (sig) {
                printf("Emulation crashed with signal %d\\n", sig);
            } else {
                uint32_t current_pc;
                uc_reg_read(uc, UC_ARM_REG_PC, &current_pc);
                printf("Exited without crash at 0x%08x - If no other reason, we ran into one of the limits\\n", current_pc);
            }
        }
    } else {
        puts("Running without a fork server");
""",
    )

    replace_once(
        native_py,
        """def emulate(uc, fuzz_file_path, prefix_input_file_path=None):
""",
        """def reset_session(uc):
    return native_lib.reset_session(uc._uch)

def emulate(uc, fuzz_file_path, prefix_input_file_path=None):
""",
    )
    replace_once(
        native_py,
        '    _setup_prototype(native_lib, "load_fuzz", ctypes.c_int, ctypes.c_char_p)\n',
        '    _setup_prototype(native_lib, "load_fuzz", ctypes.c_int, ctypes.c_char_p)\n'
        '    _setup_prototype(native_lib, "reset_session", ctypes.c_int, uc_engine)\n',
    )


if __name__ == "__main__":
    main()
