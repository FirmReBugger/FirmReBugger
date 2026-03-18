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

void BUG_FP_FW27() {
    report_reached("FP_FW27");
    //(FP) Buffer overflow in fnExtractFIFO
    if (reg_state[3] > 64) {
        report_detected_triggered("FP_FW27");
    }
}

void  BUG_FP_FW45() {
    report_reached("FP_FW45");
    //(FP) Out-of-bounds access in fnUSB_handle_frame from GRXSTSPR.CHNUM value
    if (reg_state[2] > 1) {
        report_detected_triggered("FP_FW45");
    }
}

void BUG_MF04() {
    report_reached("MF04");
    // Out-of-bounds access from interface index in control_callback
    if (reg_state[1] > 1) {
        report_detected_triggered("MF04");
    }
}

void BUG_FP_MF05() {
    report_reached("FP_MF05");
    // (FP) Uninitialized usage of SerialHandle
    if (frb_mem_read(0x20000948,1) == 0) {
        report_detected_triggered("FP_MF05");
    }
    if (frb_mem_read(0x20000948 + 1,1) == 0) {
        report_detected_triggered("FP_MF05");
    }
}

void BUG_S04() {
    report_reached("S04");
    // Direct manipulation of memory using I/O menu
    if (reg_state[1] > 1) {
        report_detected_triggered("S04");
    }
}

void BUG_FP_FRB06() {
    // (FP) fnRead 
    report_reached("FP_FRB06");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB06");
    }
}

void BUG_FP_FRB07() {
    // (FP) fnMsgs
    report_reached("FP_FRB07");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB07");
    }
}

void BUG_FP_FRB08() {
    // (FP) fndriver 
    report_reached("FP_FRB08");
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FRB08");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0800d65e, BUG_FP_FW27);
    frb_add_reflection_point(0x0800fc2c, BUG_FP_FW45);
    frb_add_reflection_point(0x08011c10, BUG_MF04);
    frb_add_reflection_point(0x0800f0c2, BUG_FP_MF05);
    frb_add_reflection_point(0x0800efea, BUG_FP_MF05);
    frb_add_reflection_point(0x080127c4, BUG_S04);
    frb_add_reflection_point(0x0800f29c, BUG_FP_FRB06);
    frb_add_reflection_point(0x0800f2d4, BUG_FP_FRB07);
    frb_add_reflection_point(0x0800f1f2, BUG_FP_FRB08);
}
