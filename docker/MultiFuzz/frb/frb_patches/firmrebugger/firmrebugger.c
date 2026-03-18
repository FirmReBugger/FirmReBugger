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

#include "firmrebugger.h"
#include "/home/user/multifuzz/tinycc/libtcc.h"

int init_hook_addr();
static CrashLoggerEmu *emu_current_state;
static TCCState *tcc_state;

#define FRB_MAX_SYMBOLS 131072
#define FRB_MAX_SYMBOL_NAME 256

typedef struct {
    char name[FRB_MAX_SYMBOL_NAME];
    uint32_t addr;
} frb_symbol_entry;

static frb_symbol_entry g_symbols[FRB_MAX_SYMBOLS];
static size_t g_symbol_count = 0;
static bool g_symbols_loaded = false;

void firmrebugger_init_config(void* vm, CrashLoggerEmu *emu)
{

    char *firmrebugger_config_path = getenv("FIRMREBUGGER_CONFIG");
    FILE *file = fopen(firmrebugger_config_path, "r");
    if (!file)
    {
        printf("Please set FIRMREBUGGER_CONFIG path.\n");
        exit(1);
    }
    printf("Initilise FirmReBugger Config\n");
    emu_current_state = emu;
    init_hook_addr(vm, emu);

    fclose(file);
}

void handle_error(void *opaque, const char *msg)
{
    fprintf(opaque, "%s\n", msg);
}

char* reached_bug_ids[100];
int reached_bug_count = 0;
char* triggered_bug_ids[100];
int triggered_bug_count = 0;

void frb_report_reached(const char* bug_id) {
  for (int i = 0; i < reached_bug_count; i++) {
    if (strcmp(reached_bug_ids[i], bug_id) == 0) {
      return; // Bug already reported
    }
  }
  reached_bug_ids[reached_bug_count] = strdup(bug_id);
  reached_bug_count++;
  printf("REACHED: %s\n", bug_id);
}

void frb_report_detected_triggered(const char* bug_id) {
  for (int i = 0; i < triggered_bug_count; i++) {
    if (strcmp(triggered_bug_ids[i], bug_id) == 0) {
      return; // Bug already reported
    }
  }
  if (triggered_bug_count < 100) {
    triggered_bug_ids[triggered_bug_count] = strdup(bug_id);
    triggered_bug_count++;
  }
  printf("TRIGGERED: %s\n", bug_id);
}


void frb_print_reg_state(uint32_t *reg_state){
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

uint32_t reg_state[16];

void frb_print_regs(void) {
    frb_print_reg_state(reg_state);
}

char* read_bug_context(const char* filename) {
    FILE* file = fopen(filename, "rb");  
    if (file == NULL) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    // Find the size of the file
    fseek(file, 0, SEEK_END);
    size_t file_size = (size_t)ftell(file); 
    rewind(file);

    // Allocate memory for the file content
    char* buffer = (char*)malloc(file_size + 1);  
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        fclose(file);  
        exit(EXIT_FAILURE);
    }

    // Read the file content into the buffer
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

    // Null-terminate the string
    buffer[file_size] = '\0';

    fclose(file);
    return buffer;
}


static void populate_reg_state(uint32_t *reg_state, CrashLoggerEmu *emu) {
    reg_state[0] = emu->reg_read(emu->cpu, "r0");
    reg_state[1] = emu->reg_read(emu->cpu, "r1");
    reg_state[2] = emu->reg_read(emu->cpu, "r2");
    reg_state[3] = emu->reg_read(emu->cpu, "r3");
    reg_state[4] = emu->reg_read(emu->cpu, "r4");
    reg_state[5] = emu->reg_read(emu->cpu, "r5");
    reg_state[6] = emu->reg_read(emu->cpu, "r6");
    reg_state[7] = emu->reg_read(emu->cpu, "r7");
    reg_state[8] = emu->reg_read(emu->cpu, "r8");
    reg_state[9] = emu->reg_read(emu->cpu, "r9");
    reg_state[10] = emu->reg_read(emu->cpu, "r10");
    reg_state[11] = emu->reg_read(emu->cpu, "r11");
    reg_state[12] = emu->reg_read(emu->cpu, "r12");
    reg_state[13] = emu->reg_read(emu->cpu, "sp");
    reg_state[14] = emu->reg_read(emu->cpu, "lr");
    reg_state[15] = emu->reg_read(emu->cpu, "pc");
}

uint32_t frb_mem_read(uint32_t read_addr, size_t size) {
    uint32_t mem_value = 0;
    emu_current_state->mem_read(emu_current_state->cpu, read_addr, (uint8_t *)&mem_value, size);
    printf("Reading at address %x returned: %x\n", read_addr, mem_value);
    return mem_value;
}

void frb_mem_write(uint32_t write_addr, uint32_t write_value, size_t size) {
    emu_current_state->mem_write(emu_current_state->cpu, write_addr, (uint8_t *)&write_value, size);
    printf("Writing %x at address %x\n", write_value, write_addr);
}

void frb_force_crash() {
    printf("Forcing Crash\n");
    emu_current_state->force_crash(emu_current_state->cpu);
}

// //Context Struct
// typedef void (*func_ptr_t)(void);
// typedef struct {
//     uint32_t address;
//     func_ptr_t introspection_point;
// } context_struct;

//This is a pre-hook
static void firmrebugger_hook(CrashLoggerEmu *emu, context_struct context)
{
    emu_current_state = emu;
    populate_reg_state(reg_state, emu_current_state);

    context.introspection_point();
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

#define FRB_MAX_REFLECTION_POINTS 256

typedef struct {
    context_struct entry;
} frb_reflection_point_registration;

static frb_reflection_point_registration g_pending_reflection_points[FRB_MAX_REFLECTION_POINTS];
static size_t g_pending_reflection_point_count = 0;

/* frb_add_reflection_point - registers a reflection point (hook address) paired
 * with an introspection point (the function that fires at that address).
 */
void frb_add_reflection_point(uint32_t address, func_ptr_t introspection_point) {
    if (g_pending_reflection_point_count >= FRB_MAX_REFLECTION_POINTS) {
        printf("FirmReBugger: frb_add_reflection_point exceeded max reflection points (%d), skipping 0x%X\n", FRB_MAX_REFLECTION_POINTS, address);
        return;
    }
    g_pending_reflection_points[g_pending_reflection_point_count].entry.address  = address;
    g_pending_reflection_points[g_pending_reflection_point_count].entry.introspection_point = introspection_point;
    g_pending_reflection_point_count++;
    printf("FirmReBugger: reflection point registered at 0x%X\n", address);
}

int init_hook_addr(void* vm)
{

    char *firmrebugger_config_path = getenv("FIRMREBUGGER_CONFIG");
    
    if (firmrebugger_config_path == NULL) {
        return 0;
    }
    
    char *bug_context = read_bug_context(firmrebugger_config_path);

    tcc_state = tcc_new();
    if (!tcc_state) {
        fprintf(stderr, "Could not create tcc state\n");
        exit(1);
    }

    populate_reg_state(reg_state, emu_current_state);
    /* set custom error/warning printer */
    tcc_set_error_func(tcc_state, stderr, handle_error);

    // /* if tcclib.h and libtcc1.a are not installed, where can we find them */
    tcc_add_include_path(tcc_state, "/home/user/multifuzz/tinycc");
    tcc_set_lib_path(tcc_state, "/home/user/multifuzz/tinycc");
    /* MUST BE CALLED before any compilation */
    tcc_set_output_type(tcc_state, TCC_OUTPUT_MEMORY);

    if (tcc_compile_string(tcc_state, bug_context) == -1)
        return 1;

    /* as a test, we add symbols that the compiled program can use.
       You may also open a dll with tcc_add_dll() and use symbols from that */
    tcc_add_symbol(tcc_state, "reg_state", reg_state);
    tcc_add_symbol(tcc_state, "frb_mem_read", frb_mem_read);
    tcc_add_symbol(tcc_state, "frb_mem_write", frb_mem_write);
    tcc_add_symbol(tcc_state, "frb_force_crash", frb_force_crash);
    tcc_add_symbol(tcc_state, "frb_report_detected_triggered", frb_report_detected_triggered);
    tcc_add_symbol(tcc_state, "frb_report_reached", frb_report_reached);
    tcc_add_symbol(tcc_state, "frb_print_reg_state", frb_print_reg_state);
    tcc_add_symbol(tcc_state, "frb_print_regs", frb_print_regs);
    tcc_add_symbol(tcc_state, "frb_symbolize", frb_symbolize);
    tcc_add_symbol(tcc_state, "frb_add_reflection_point", frb_add_reflection_point);

    /* relocate the code */
    if (tcc_relocate(tcc_state) < 0)
        return 1;

    void (*register_reflection_points)(void) = tcc_get_symbol(tcc_state, "register_reflection_points");
    if (!register_reflection_points) {
        fprintf(stderr, "FirmReBugger: register_reflection_points not found in bug descriptor\n");
        exit(1);
    }

    frb_load_symbols_file();
    g_pending_reflection_point_count = 0;
    register_reflection_points();

    for (size_t i = 0; i < g_pending_reflection_point_count; ++i) {
        printf("FirmReBugger: installing reflection point[%zu] at 0x%X\n", i, g_pending_reflection_points[i].entry.address);
        emu_current_state->add_hook(vm, emu_current_state, g_pending_reflection_points[i].entry, firmrebugger_hook);
    }
    return 0;
}
