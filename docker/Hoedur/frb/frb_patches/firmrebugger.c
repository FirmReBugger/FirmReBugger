#include <stdbool.h>

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <ctype.h>
#include <stdbool.h>
#include <limits.h>

#include "tcg/firmrebugger.h"
#include "/home/user/hoedur/tinycc/libtcc.h"

static TCCState *tcc_state;
uint32_t reg_state[16];
static FILE *firmrebugger_log_file;

#define FRB_MAX_SYMBOLS 131072
#define FRB_MAX_SYMBOL_NAME 256

typedef struct {
    char name[FRB_MAX_SYMBOL_NAME];
    uint32_t addr;
} frb_symbol_entry;

static frb_symbol_entry g_symbols[FRB_MAX_SYMBOLS];
static size_t g_symbol_count = 0;
static bool g_symbols_loaded = false;

#define FRB_MAX_REFLECTION_POINTS 256

typedef struct {
    context_struct entry;
} frb_reflection_point_registration;

static frb_reflection_point_registration g_pending_reflection_points[FRB_MAX_REFLECTION_POINTS];
static size_t g_pending_reflection_point_count = 0;

/* Registered reflection points installed after register_reflection_points() is called */
static frb_reflection_point_registration g_reflection_points[FRB_MAX_REFLECTION_POINTS];
static size_t g_reflection_point_count = 0;

static void populate_reg_state(uint32_t *reg_state, CPUArchState *env, uint64_t curr_addr) {
    for (int i = 0; i < 16; i++) {
        if (i == 15) {
            reg_state[i] = curr_addr;
        } else {
            reg_state[i] = env->regs[i];
        }
    }
}

uint32_t frb_mem_read(uint32_t read_addr, size_t size) {
    uint32_t mem_value = 0;
    cpu_physical_memory_read(read_addr, &mem_value, size);
    return mem_value;
}

void frb_mem_write(uint32_t write_addr, uint32_t value, size_t size) {
    cpu_physical_memory_write(write_addr, &value, size);
}

char* reached_bug_ids[100];
int reached_bug_count = 0;
char* triggered_bug_ids[100];
int triggered_bug_count = 0;

void frb_report_reached(const char* bug_id) {
    for (int i = 0; i < reached_bug_count; i++) {
        if (strcmp(reached_bug_ids[i], bug_id) == 0) {
            return;
        }
    }
    reached_bug_ids[reached_bug_count] = strdup(bug_id);
    reached_bug_count++;
    printf("REACHED: %s\n", bug_id);
}

void frb_report_detected_triggered(const char* bug_id) {
    for (int i = 0; i < triggered_bug_count; i++) {
        if (strcmp(triggered_bug_ids[i], bug_id) == 0) {
            return;
        }
    }
    if (triggered_bug_count < 100) {
        triggered_bug_ids[triggered_bug_count] = strdup(bug_id);
        triggered_bug_count++;
    }
    printf("TRIGGERED: %s\n", bug_id);
}

void frb_print_reg_state(uint32_t *reg_state) {
    printf("Register State:\n");
    printf("r0:  0x%08X\n", reg_state[0]);
    printf("r1:  0x%08X\n", reg_state[1]);
    printf("r2:  0x%08X\n", reg_state[2]);
    printf("r3:  0x%08X\n", reg_state[3]);
    printf("r4:  0x%08X\n", reg_state[4]);
    printf("r5:  0x%08X\n", reg_state[5]);
    printf("r6:  0x%08X\n", reg_state[6]);
    printf("r7:  0x%08X\n", reg_state[7]);
    printf("r8:  0x%08X\n", reg_state[8]);
    printf("r9:  0x%08X\n", reg_state[9]);
    printf("r10: 0x%08X\n", reg_state[10]);
    printf("r11: 0x%08X\n", reg_state[11]);
    printf("r12: 0x%08X\n", reg_state[12]);
    printf("sp:  0x%08X\n", reg_state[13]);
    printf("lr:  0x%08X\n", reg_state[14]);
    printf("pc:  0x%08X\n", reg_state[15]);
}

void frb_print_regs(void) {
    frb_print_reg_state(reg_state);
}

static char* read_bug_context(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = (size_t)ftell(file);
    rewind(file);

    char* buffer = (char*)malloc(file_size + 1);
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != file_size) {
        if (feof(file)) {
            printf("Warning: End of file reached before reading all data.\n");
        } else if (ferror(file)) {
            perror("Error reading file");
        }
        free(buffer);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    buffer[file_size] = '\0';
    fclose(file);
    return buffer;
}

static void handle_error(void *opaque, const char *msg) {
    fprintf(opaque, "%s\n", msg);
}

/* Resolve symbols.txt path via FIRMREBUGGER_SYMBOLS env var (set by the Python
   bug-analyzer which walks upward from the results directory to find it). */
static bool frb_get_symbols_path(char *out_path, size_t out_len) {
    const char *sym = getenv("FIRMREBUGGER_SYMBOLS");
    if (!sym || sym[0] == '\0') {
        return false;
    }

    if (strlen(sym) >= out_len) {
        return false;
    }

    strncpy(out_path, sym, out_len - 1);
    out_path[out_len - 1] = '\0';
    return true;
}

static int frb_load_symbols_file(void) {
    if (g_symbols_loaded) {
        return 0;
    }

    char symbols_path[PATH_MAX];
    if (!frb_get_symbols_path(symbols_path, sizeof(symbols_path))) {
        printf("FirmReBugger: FIRMREBUGGER_SYMBOLS is not set - symbols.txt could not be located\n");
        g_symbols_loaded = true;
        g_symbol_count = 0;
        return -1;
    }

    FILE *f = fopen(symbols_path, "r");
    if (!f) {
        printf("FirmReBugger: symbols file not found: %s\n", symbols_path);
        g_symbols_loaded = true;
        g_symbol_count = 0;
        return -1;
    }

    char line[1024];
    g_symbol_count = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#') continue;

        char sym_name[FRB_MAX_SYMBOL_NAME];
        char addr_str[128];

        if (sscanf(p, "%255s %127s", sym_name, addr_str) != 2) {
            continue;
        }

        errno = 0;
        unsigned long parsed = strtoul(addr_str, NULL, 0);
        if (errno != 0 || parsed > 0xFFFFFFFFUL) {
            continue;
        }

        if (g_symbol_count < FRB_MAX_SYMBOLS) {
            strncpy(g_symbols[g_symbol_count].name, sym_name, FRB_MAX_SYMBOL_NAME - 1);
            g_symbols[g_symbol_count].name[FRB_MAX_SYMBOL_NAME - 1] = '\0';
            g_symbols[g_symbol_count].addr = (uint32_t)parsed;
            g_symbol_count++;
        } else {
            break;
        }
    }

    fclose(f);
    g_symbols_loaded = true;
    printf("FirmReBugger: loaded %zu symbols from %s\n", g_symbol_count, symbols_path);
    return 0;
}

static bool frb_lookup_symbol_addr(const char *symbol, uint32_t *addr_out) {
    if (!symbol || !addr_out) return false;
    if (!g_symbols_loaded) frb_load_symbols_file();

    for (size_t i = 0; i < g_symbol_count; i++) {
        if (strcmp(g_symbols[i].name, symbol) == 0) {
            *addr_out = g_symbols[i].addr;
            return true;
        }
    }
    return false;
}

uint32_t frb_symbolize(const char *symbol_name, uint32_t offset) {
    if (!g_symbols_loaded) frb_load_symbols_file();
    uint32_t base = 0;
    if (!frb_lookup_symbol_addr(symbol_name, &base)) {
        printf("FirmReBugger: frb_symbolize failed to resolve symbol '%s'\n", symbol_name);
        exit(1);
    }
    uint32_t resolved = (base & ~1u) + offset;
    printf("FirmReBugger: frb_symbolize('%s', 0x%X) -> 0x%X\n", symbol_name, offset, resolved);
    return resolved;
}

void frb_add_reflection_point(uint32_t address, func_ptr_t introspection_point) {
    if (g_pending_reflection_point_count >= FRB_MAX_REFLECTION_POINTS) {
        printf("FirmReBugger: frb_add_reflection_point exceeded max reflection points (%d), skipping 0x%X\n",
               FRB_MAX_REFLECTION_POINTS, address);
        return;
    }
    g_pending_reflection_points[g_pending_reflection_point_count].entry.address          = address;
    g_pending_reflection_points[g_pending_reflection_point_count].entry.introspection_point = introspection_point;
    g_pending_reflection_point_count++;
    printf("FirmReBugger: reflection point registered at 0x%X\n", address);
}

void firmrebugger_hook(CPUArchState *env, uint64_t address) {
    for (size_t i = 0; i < g_reflection_point_count; i++) {
        if (g_reflection_points[i].entry.address == address) {
            populate_reg_state(reg_state, env, address);
            g_reflection_points[i].entry.introspection_point();
        }
    }
}

int config_done = 0;

void firmrebugger_init_config(CPUArchState *env, target_ulong address) {
    if (config_done == 0) {
        printf("FirmReBugger Initilisation\n");

        char *firmrebugger_config_path = getenv("FIRMREBUGGER_CONFIG");
        char *bug_context = read_bug_context(firmrebugger_config_path);

        tcc_state = tcc_new();
        if (!tcc_state) {
            fprintf(stderr, "Could not create tcc state\n");
            exit(1);
        }

        tcc_set_error_func(tcc_state, stderr, handle_error);
        tcc_add_include_path(tcc_state, "/home/user/hoedur/tinycc/");
        tcc_set_lib_path(tcc_state, "/home/user/hoedur/tinycc/");
        tcc_set_output_type(tcc_state, TCC_OUTPUT_MEMORY);

        if (tcc_compile_string(tcc_state, bug_context) == -1)
            exit(1);

        tcc_add_symbol(tcc_state, "reg_state",                    reg_state);
        tcc_add_symbol(tcc_state, "frb_mem_read",                  frb_mem_read);
        tcc_add_symbol(tcc_state, "frb_mem_write",                 frb_mem_write);
        tcc_add_symbol(tcc_state, "frb_report_detected_triggered", frb_report_detected_triggered);
        tcc_add_symbol(tcc_state, "frb_report_reached",            frb_report_reached);
        tcc_add_symbol(tcc_state, "frb_print_reg_state",           frb_print_reg_state);
        tcc_add_symbol(tcc_state, "frb_print_regs",                frb_print_regs);
        tcc_add_symbol(tcc_state, "frb_symbolize",                 frb_symbolize);
        tcc_add_symbol(tcc_state, "frb_add_reflection_point",      frb_add_reflection_point);

        if (tcc_relocate(tcc_state) < 0)
            exit(1);

        void (*register_reflection_points)(void) = tcc_get_symbol(tcc_state, "register_reflection_points");
        if (!register_reflection_points) {
            fprintf(stderr, "FirmReBugger: register_reflection_points not found in bug descriptor\n");
            exit(1);
        }

        frb_load_symbols_file();
        g_pending_reflection_point_count = 0;
        register_reflection_points();

        /* Move pending into active table */
        g_reflection_point_count = g_pending_reflection_point_count;
        for (size_t i = 0; i < g_reflection_point_count; i++) {
            g_reflection_points[i] = g_pending_reflection_points[i];
            printf("FirmReBugger: installing reflection point[%zu] at 0x%X\n",
                   i, g_reflection_points[i].entry.address);
        }

        config_done = 1;
    } else {
        firmrebugger_hook(env, address);
    }
}

int firmrebugger_reset_session(void)
{
    for (int i = 0; i < reached_bug_count; i++) free(reached_bug_ids[i]);
    for (int i = 0; i < triggered_bug_count; i++) free(triggered_bug_ids[i]);
    reached_bug_count = 0;
    triggered_bug_count = 0;
    g_reflection_point_count = 0;
    g_pending_reflection_point_count = 0;
    memset(reg_state, 0, sizeof(reg_state));
    if (tcc_state) {
        /* The persistent worker resets in a fork child.  TinyCC's destructor
         * is not fork-safe because it may tear down allocator/loader state
         * inherited while QEMU is idle.  The child exits after one replay,
         * so dropping the handle is the safe equivalent there. */
        if (getenv("FRB_REPLAY_FORK_CHILD") == NULL) {
            tcc_delete(tcc_state);
        }
        tcc_state = NULL;
    }
    config_done = 0;
    return 0;
}
