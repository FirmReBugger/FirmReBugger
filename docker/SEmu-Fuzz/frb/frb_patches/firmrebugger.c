#include <stdbool.h>

#include <unicorn/unicorn.h>

#include <unistd.h>
#include <stdint.h>
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

#include "firmrebugger.h"
#include "/home/user/SEmu-Fuzz/tinycc/libtcc.h"

static TCCState *tcc_state;
uint32_t reg_state[16];
static size_t global_hook_num;
static uc_engine *uc_state;

//Context Struct
typedef void (*func_ptr_t)(void);
typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;
static const context_struct *bug_struct;

static void populate_reg_state(uint32_t *reg_state, uc_engine *uc, uint64_t curr_addr) {
  uc_reg_read(uc, UC_ARM_REG_R0, &reg_state[0]);
  uc_reg_read(uc, UC_ARM_REG_R1, &reg_state[1]);
  uc_reg_read(uc, UC_ARM_REG_R2, &reg_state[2]);
  uc_reg_read(uc, UC_ARM_REG_R3, &reg_state[3]);
  uc_reg_read(uc, UC_ARM_REG_R4, &reg_state[4]);
  uc_reg_read(uc, UC_ARM_REG_R5, &reg_state[5]);
  uc_reg_read(uc, UC_ARM_REG_R6, &reg_state[6]);
  uc_reg_read(uc, UC_ARM_REG_R7, &reg_state[7]);
  uc_reg_read(uc, UC_ARM_REG_R8, &reg_state[8]);
  uc_reg_read(uc, UC_ARM_REG_R9, &reg_state[9]);
  uc_reg_read(uc, UC_ARM_REG_R10, &reg_state[10]);
  uc_reg_read(uc, UC_ARM_REG_R11, &reg_state[11]);
  uc_reg_read(uc, UC_ARM_REG_R12, &reg_state[12]);
  uc_reg_read(uc, UC_ARM_REG_R13, &reg_state[13]);
  uc_reg_read(uc, UC_ARM_REG_R14, &reg_state[14]);
  uc_reg_read(uc, UC_ARM_REG_R15, &reg_state[15]);
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

uint32_t frb_mem_read(uint32_t read_addr, size_t size) {
    uint32_t mem_value = 0;
    uc_mem_read(uc_state, read_addr, &mem_value, size);
    printf("Reading at address %x with value %x\n", read_addr, mem_value);
    return mem_value;
}

void frb_mem_write(uint32_t write_addr, uint32_t value, size_t size) {
    uc_mem_write(uc_state, write_addr, &value, size);
    printf("Writing %x at address %x\n", value, write_addr);
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

void handle_error(void *opaque, const char *msg) {
    fprintf(opaque, "%s\n", msg);
}

static void firmrebugger_hook(uc_engine *uc, uc_mem_type oracle_address, uint64_t addr, int size, int64_t value, void *user_data) 
{
  uc_state = uc;
  for (size_t i = 0; i < global_hook_num; ++i) {
      if (bug_struct[i].address == oracle_address) {
        populate_reg_state(reg_state, uc_state, oracle_address);
        bug_struct[i].bug_func();
      }
  }
}

void firmrebugger_init_config(uc_engine *uc)
{
    printf("Initilising firmrebugger\n");
    char *firmrebugger_config_path = getenv("FIRMREBUGGER_CONFIG");
    char *bug_context = read_bug_context(firmrebugger_config_path);
    if (!bug_context)
    {
        printf("Please set FIRMREBUGGER_CONFIG path.\n");
        exit(1);
    }

    tcc_state = tcc_new();
    if (!tcc_state) {
        fprintf(stderr, "Could not create tcc state\n");
        exit(1);
    }
    tcc_set_error_func(tcc_state, stderr, handle_error);

     // /* if tcclib.h and libtcc1.a are not installed, where can we find them */
    tcc_add_include_path(tcc_state, "/home/user/SEmu-Fuzz/tinycc");
    tcc_set_lib_path(tcc_state, "/home/user/SEmu-Fuzz/tinycc");
    /* MUST BE CALLED before any compilation */
    tcc_set_output_type(tcc_state, TCC_OUTPUT_MEMORY);

    if (tcc_compile_string(tcc_state, bug_context) == -1)
        exit(1);

    /* as a test, we add symbols that the compiled program can use.
       You may also open a dll with tcc_add_dll() and use symbols from that */
    tcc_add_symbol(tcc_state, "reg_state", reg_state);
    tcc_add_symbol(tcc_state, "frb_mem_read", frb_mem_read);
    tcc_add_symbol(tcc_state, "frb_mem_write", frb_mem_write);
    tcc_add_symbol(tcc_state, "frb_report_detected_triggered", frb_report_detected_triggered);
    tcc_add_symbol(tcc_state, "frb_report_reached", frb_report_reached);
    tcc_add_symbol(tcc_state, "frb_print_reg_state", frb_print_reg_state);

        /* relocate the code */
    if (tcc_relocate(tcc_state) < 0)
        exit(1);

    void (*send_context_struct)(const context_struct **arr, size_t *size) = tcc_get_symbol(tcc_state, "send_context_struct");
    if (!send_context_struct)
      exit(1);
    send_context_struct(&bug_struct, &global_hook_num);
    uc_hook tmp;
    for (size_t i = 0; i < global_hook_num; ++i) {
        printf("Hooking: %x \n", bug_struct[i].address );
        uc_hook_add(uc, &tmp, UC_HOOK_CODE, firmrebugger_hook, NULL, (bug_struct[i].address
                             & 0xfffffffe), (bug_struct[i].address | 0x1));
    }
}
