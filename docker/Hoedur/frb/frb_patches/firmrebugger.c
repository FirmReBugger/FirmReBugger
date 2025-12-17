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

#include "tcg/firmrebugger.h"
#include "/home/user/hoedur/tinycc/libtcc.h"

static TCCState *tcc_state;
uint32_t reg_state[16];
static size_t global_hook_num;
static FILE *firmrebugger_log_file;
static const context_struct *bug_struct;

static void populate_reg_state(uint32_t *reg_state, CPUArchState *env, uint64_t curr_addr) {
  //printf("Populating reg state: \n");
  for (int i = 0; i < 16; i ++) {
    if (i == 15) {
      reg_state[i] = curr_addr;
    }else {
      reg_state[i] = env->regs[i];
    }
  }
}

uint32_t frb_mem_read(uint32_t read_addr, size_t size) {
    uint32_t mem_value = 0;
    cpu_physical_memory_read(read_addr, &mem_value, size);
    //printf("Reading address %x returned: %x\n", read_addr, mem_value);
    return mem_value;
}

void frb_mem_write(uint32_t write_addr, uint32_t value ,size_t size) {
    cpu_physical_memory_write(write_addr, &value, size);
    //printf("Writing %x at address %x\n", write_addr, value);
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

static char* read_bug_context(const char* filename) {
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

static void handle_error(void *opaque, const char *msg) {
    fprintf(opaque, "%s\n", msg);
}

void firmrebugger_hook(CPUArchState *env, uint64_t address) {
  for (size_t i = 0; i < global_hook_num; ++i) {
      if (bug_struct[i].address == address) {
        //printf("Hooked at [%zu] = 0x%X\n", i, bug_struct[i].address);
        populate_reg_state(reg_state, env, address);
        bug_struct[i].bug_func();
      }
  }
}
int config_done = 0;
void firmrebugger_init_config(CPUArchState *env, target_ulong address) {
  if (config_done == 0 ){
    printf("FirmReBugger Initilisation\n");
    char *firmrebugger_config_path = getenv("FIRMREBUGGER_CONFIG");
    char *bug_context = read_bug_context(firmrebugger_config_path);

    tcc_state = tcc_new();
    if (!tcc_state) {
        fprintf(stderr, "Could not create tcc state\n");
        exit(1);
    }

    /* set custom error/warning printer */
    tcc_set_error_func(tcc_state, stderr, handle_error);

      // /* if tcclib.h and libtcc1.a are not installed, where can we find them */
    tcc_add_include_path(tcc_state, "/home/user/hoedur/tinycc/");
    tcc_set_lib_path(tcc_state, "/home/user/hoedur/tinycc/");
    /* MUST BE CALLED before any compilation */
    tcc_set_output_type(tcc_state, TCC_OUTPUT_MEMORY);

    if (tcc_compile_string(tcc_state, bug_context) == -1)
        exit(1);

    tcc_add_symbol(tcc_state, "reg_state", reg_state);
    tcc_add_symbol(tcc_state, "frb_mem_read", frb_mem_read);
    tcc_add_symbol(tcc_state, "frb_mem_write", frb_mem_write);
    tcc_add_symbol(tcc_state, "frb_report_detected_triggered", frb_report_detected_triggered);
    tcc_add_symbol(tcc_state, "frb_report_reached", frb_report_reached);
    
    /* relocate the code */
    if (tcc_relocate(tcc_state) < 0)
        exit(1);

    void (*send_context_struct)(const context_struct **arr, size_t *size) = tcc_get_symbol(tcc_state, "send_context_struct");

    if (!send_context_struct)
      exit(1);
    send_context_struct(&bug_struct, &global_hook_num);
    config_done = 1;
  } else {
    firmrebugger_hook(env,address);
  }
}
