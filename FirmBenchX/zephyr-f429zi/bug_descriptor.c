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

void BUG_H31() {
    // CVE-2022-3806
    report_reached("H31");
    if (reg_state[4] != 0) {
        report_detected_triggered("H31");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08006b14, BUG_H31);
    // FRB44/FRB45 were downstream crash-site checks. Live proof showed both
    // manifestations originate from H31's premature error-path net_buf_unref.
}
