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

void BUG_FP_FW36() {
    report_reached("FP_FW36");
    //Unchecked error handler in spi_init causing Null Pointer Dereference
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FW36");
    }
}

void BUG_FP_FW36_2() {
    report_reached("FP_FW36");
    //Unchecked error handler in spi_init causing Null Pointer Dereference
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FW36");
    }
}

void BUG_FP_E04() {
    report_reached("FP_E04");
    //SERCOM0 intilialization race (FP)
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_E04");
    }
}

void BUG_MF17() {
    report_reached("MF17");
    // Fragment offset plus payload length is not bounds-checked in
    // sicslowpan::input. At 0x4806 r0 is the byte offset and r2 is the
    // payload length; each sicslowpan buffer slot is 400 bytes.
    if (reg_state[0] > 400 || reg_state[2] > 400 - reg_state[0]) {
        report_detected_triggered("MF17");
    }
}

void BUG_FP_MF18() {
    report_reached("FP_MF18");
    //(FP) Unbounded recursion when obtaining clock rate
    if (reg_state[13] > 0x2000518F || reg_state[13] < 0x20003190 ) {
        report_detected_triggered("FP_MF18");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x000012f8, BUG_FP_FW36);
    frb_add_reflection_point(0x00001356, BUG_FP_FW36_2);
    frb_add_reflection_point(0x000011e6, BUG_FP_E04);
    frb_add_reflection_point(0x00004806, BUG_MF17);
    frb_add_reflection_point(0x00001c06, BUG_FP_MF18);
}
