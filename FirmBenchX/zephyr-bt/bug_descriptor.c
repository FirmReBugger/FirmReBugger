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


void BUG_FW48() {
  // CVE-2020-10066
  report_reached("FW48");
  if (reg_state[1] == 0) {
    report_detected_triggered("FW48");
  }
}

void arch_system_halt() {
  // supposed to exit here
  report_reached("ERROR-FP_FRB13");
  report_detected_triggered("ERROR-FP_FRB13");
}

void register_reflection_points() {
    // FW47 is absent here: this build clamps both event and ACL lengths to
    // net_buf_simple_tailroom before appending them.
    frb_add_reflection_point(0x080025b4, BUG_FW48);
    frb_add_reflection_point(0x0800accc, arch_system_halt);
    // The former FP_FRB41 hook duplicated FW48's NULL-buffer condition.
}
