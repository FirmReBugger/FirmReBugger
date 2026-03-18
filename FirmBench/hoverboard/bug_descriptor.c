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
  uint32_t addr_ptr = reg_state[2];
  if (frb_mem_read(addr_ptr, 4) == 0) {
    //*addr == NULL
    report_detected_triggered("FRB38");
  }
}

void FRB39() {
  report_reached("FRB39");
  if (reg_state[14] == 0) {
    // newMsg->code == NULL
    report_detected_triggered("FRB39");
  }
}

void test() {
  report_reached("FRB46");
  if (reg_state[3] == 0) {
    report_detected_triggered("FRB46");
  }
}

void on_protocol_process_ReadValue() {
  report_reached("FP_FRB52");
  if (reg_state[3] == 0) {
    report_detected_triggered("FP_FRB52");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08009494, FRB38);
    frb_add_reflection_point(0x08006f36, FRB39);
    frb_add_reflection_point(0x080094b4, test);
    frb_add_reflection_point(0x08006f40, on_protocol_process_ReadValue);
}
