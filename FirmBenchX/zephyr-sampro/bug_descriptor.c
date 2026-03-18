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


void on_CVE_2020_10064() {
  report_reached("FW46");
  uint32_t lr = reg_state[14];
  frb_print_regs();

  if (reg_state[2] > 0xf0000000 && lr == 0x00407987) {
    report_detected_triggered("FW46");
  }
}

void on_CVE_2021_3320() {
  report_reached("FW50");
  if (reg_state[3] == 2) {
    report_detected_triggered("FW50");
  }
}

void on_CVE_2021_3322() {
  report_reached("FW52");
  uint32_t frags = frb_mem_read(reg_state[0] + 0x10, 4);
  if (frags == 0) {
    report_detected_triggered("FW52");
  }
}

void on_CVE_2021_3321() {
  // Check for size underflow in memmove call from ieee802154_reassemble
  report_reached("FW51");
  if (reg_state[2] > 0xf0000000 && reg_state[14] == 0x00403c78) {
    report_detected_triggered("FW51");
  }
}

void on_z_handle_obj_poll_events() {
  report_reached("FP_FRB30");
  if (reg_state[0] == 0) {
    report_detected_triggered("FP_FRB30");
  }
}

void on_fragment_remove_headers() {
  report_reached("H59");
  uint32_t ptr = reg_state[5];
  uint32_t buf_len = frb_mem_read(ptr + 0xc, 2);
  uint32_t datagram_type = frb_mem_read(ptr + 8, 1);
  int hdr_len = 0;

  if (datagram_type & 0xf8 == 0xc0) {
    hdr_len = 4;
  } else {
    hdr_len = 5;
  }

  if (buf_len < hdr_len) {
    report_detected_triggered("H59");
  }
}

void on_net_if_config_ipv6_get() {
  report_reached("H60");
  if (reg_state[0] == 0) {
    report_detected_triggered("H60");
  }
}

void on_net_if_ipv6_calc_reachable_time() {
  report_reached("H61");
  if (reg_state[0] == 0) {
    report_detected_triggered("H61");
  }
}

void on_z_work_q_main() {
  report_reached("FP_FRB18");
  if (reg_state[2] == 0) {
    report_detected_triggered("FP_FRB18");
  }
}

void on_remove_timeout() {
  report_reached("FP_FRB19");
  if (reg_state[2] == 0 || reg_state[3] == 0) {
    report_detected_triggered("FP_FRB19");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0040daba, on_CVE_2020_10064);
    frb_add_reflection_point(0x0040dfa4, on_CVE_2021_3320);
    frb_add_reflection_point(0x00407918, on_CVE_2021_3322);
    frb_add_reflection_point(0x00404826, on_fragment_remove_headers);
    frb_add_reflection_point(0x004051c0, on_net_if_config_ipv6_get);
    frb_add_reflection_point(0x0040e76c, on_net_if_ipv6_calc_reachable_time);
    frb_add_reflection_point(0x0040daba, on_CVE_2021_3321);
    frb_add_reflection_point(0x004112fe, on_z_handle_obj_poll_events);
    frb_add_reflection_point(0x0040bf28, on_z_work_q_main);
    frb_add_reflection_point(0x0040ba2c, on_remove_timeout);
}
