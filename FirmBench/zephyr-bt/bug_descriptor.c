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


void BUG_FW47() {
  // CVE-2020-10065
  report_reached("FW47");
  uint32_t buf = reg_state[0];
  uint32_t len = reg_state[2];
  uint32_t buf_len = frb_mem_read(buf + 4, 2);
  uint32_t buf_size = frb_mem_read(buf + 6, 2);
  if (buf_len + len > buf_size) {
    if (reg_state[14] == 0x08001355) {
      report_detected_triggered("FW47");
    }
  }
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
    frb_add_reflection_point(0x0800a3d6, BUG_FW47);
    frb_add_reflection_point(0x08002598, BUG_FW48);
    frb_add_reflection_point(0x0800accc, arch_system_halt);
}
