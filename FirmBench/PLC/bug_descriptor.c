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

void BUG_FW14() {
    report_reached("FW14");
    // Buffer overflow in process_FC1
    uint32_t u16Coilno = reg_state[0];
    int ADD_LOW = 0x3;
    if (((u16Coilno / 8) + ADD_LOW) > 64) {
        report_detected_triggered("FW14");
    }
}

void BUG_FW15() {
    report_reached("FW15");
    // Buffer overflow in process_FC3
    uint32_t offset = reg_state[6];
    uint32_t len = reg_state[0];
    if ((offset+len) > 64) {
        report_detected_triggered("FW15");
    }
}

void BUG_FW16() {
    report_reached("FW16");
    // Buffer overflow in process_FC15
    uint32_t offset = reg_state[6];
    uint32_t len = reg_state[0];
    if ((offset+len) > 16) {
        report_detected_triggered("FW16");
    }
}

void BUG_FW17() {
    report_reached("FW17");
    // Buffer overflow in process_FC16
    uint32_t offset = reg_state[7];
    uint32_t len = reg_state[6];
    if ((offset+len) > 16) {
        report_detected_triggered("FW17");
    }
}

void BUG_FP_FW25 () {
    report_reached("FP_FW25");
    // (FP) Initialization race in HAL_UART_TxCpltCallback
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FW25");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x080008da, BUG_FW14);
    frb_add_reflection_point(0x08000990, BUG_FW15);
    frb_add_reflection_point(0x08000a72, BUG_FW16);
    frb_add_reflection_point(0x08000af0, BUG_FW17);
    frb_add_reflection_point(0x08003f30, BUG_FP_FW25);
}
