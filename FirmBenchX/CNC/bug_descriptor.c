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

void BUG_FW11() {
    report_reached("FW11");
    //Stack buffer Overflow in printFloat
    if (reg_state[2] > 9) {
        report_detected_triggered("FW11");
    }
}

void  BUG_FW18() {
    report_reached("FW18");
    //Validation issue in planner_recalculate_trapezoids
    if (reg_state[3] == 0) {
        report_detected_triggered("FW18");
    }
}

void BUG_FP_E02() {
    report_reached("FP_E02");
    // (FP) Data race in st_cycle_reinitialize
    if (frb_mem_read(0x20000ec4,4) == 0) {
        report_detected_triggered("FP_E02");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0800503a, BUG_FW11);
    frb_add_reflection_point(0x08002f14, BUG_FW18);
    frb_add_reflection_point(0x08005906, BUG_FP_E02);
}
