#ifndef FIRMREBUGGER_H
#define FIRMREBUGGER_H
#include <stdbool.h>

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "exec/log.h"
#include "tcg/tcg.h"

//Context Struct
typedef void (*func_ptr_t)(void);
typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;

// void crash_logger_hook(CPUArchState *env, target_ulong pc_next);
void firmrebugger_init_config(CPUArchState *env, target_ulong pc_next);
uint32_t frb_mem_read(uint32_t read_addr, size_t size);
void frb_mem_write(uint32_t write_addr, uint32_t value ,size_t size);
void frb_report_reached(const char* bug_id);
void frb_report_detected_triggered(const char* bug_id);

#endif