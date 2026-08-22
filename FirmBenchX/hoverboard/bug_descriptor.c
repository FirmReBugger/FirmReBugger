#include <tcclib.h>
#include <stdint.h>
#include <stdbool.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_mem_write(uint32_t write_addr, uint32_t write_value, size_t size);
extern void frb_report_detected_triggered(const char* bug_id);
extern void frb_report_reached(const char* bug_id);
extern uint32_t frb_symbolize(const char *symbol_name, uint32_t offset);
extern void frb_add_reflection_point(uint32_t address, void (*introspection_point)(void));
extern void frb_print_regs(void);

static void report_detected_triggered(const char* bug_id) {
    frb_report_detected_triggered(bug_id);
}

static void report_reached(const char* bug_id) {
    frb_report_reached(bug_id);
}

void FRB38() {
    report_reached("FRB38");
    if ((int32_t)reg_state[0] < 1) {
        // sscanf converted no address, but line_read_memory ignores the result.
        report_detected_triggered("FRB38");
    }
}

void FRB39() {
    report_reached("FRB39");
    uint32_t new_msg = reg_state[3];
    uint32_t param = reg_state[1];
    if (frb_mem_read(new_msg + 4, 1) != frb_mem_read(param, 1)) {
        // line_generic_var failed to copy param->code into newMsg.code.
        report_detected_triggered("FRB39");
    }
}

void FP_FRB46() {
    report_reached("FP_FRB46");
    // The STM32F103RC aliases its 256 KiB boot Flash at 0x00000000.
    if (reg_state[3] < 0x00040000) {
        report_detected_triggered("FP_FRB46");
    }
}

void FP_FRB70() {
    report_reached("FP_FRB70");
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB70");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0800babc, FRB38);
    frb_add_reflection_point(0x0800b7a4, FRB39);
    frb_add_reflection_point(0x0800b7de, FRB39);
    frb_add_reflection_point(0x0800bb14, FP_FRB46);
    frb_add_reflection_point(0x080096e6, FP_FRB70);
}
