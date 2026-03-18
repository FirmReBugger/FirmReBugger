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

void BUG_S06() {
    report_reached("S06");
    if (reg_state[0] == 0) {
        report_detected_triggered("S06");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0020761c, BUG_S06);
}
