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


void on_CVE_2021_3322() {
  // Check for NULL ptr in pkt->frags
  report_reached("FW52");
  uint32_t frags = frb_mem_read(reg_state[0] + 0x10, 4);
  if (frags == 0) {
    report_detected_triggered("FW52");
  }
}

void check_compressed_hdr_size(uint32_t compressed_hdr_size) {
  // CVE-2021-3323
  report_reached("FW53");
  uint32_t net_buf = reg_state[6];
  uint32_t pkt_buf_len_addr = (net_buf + 0x8) + 0x4;
  uint32_t pkt_buf_len = frb_mem_read(pkt_buf_len_addr, 2);

  if (pkt_buf_len < compressed_hdr_size) {
    report_reached("FW53");
  }
}

void on_CVE_2021_3323_callsite_1() {
  // CVE_2021_3323
  check_compressed_hdr_size(reg_state[3]);
}

void on_CVE_2021_3323_callsite_2() {
  // CVE_2021_3323
  check_compressed_hdr_size(reg_state[4]);
}

void on_CVE_2021_3320() {
  // Check for unexpected frame type
  report_reached("FW50");
  if (reg_state[3] == 2) {
    report_detected_triggered("FW50");
  }
}

uint32_t mhr_src_addr_ptr = false;

void on_CVE_2021_3319() {
  report_reached("FW49");
  // CVE_2021_3319
  // Catch NULL return from validate_addr outside IEEE802154_ADDR_MODE_NONE
  // https://github.com/zephyrproject-rtos/zephyr/blob/0aaae4a039cab54df84c1f0371d44d6045ff58d8/subsys/net/l2/ieee802154/ieee802154_frame.c#L120

  // validate_addr is inlined in ieee802154_validate_frame for source and
  // destination addresses This is why we catch both cases (src and dest NULL
  // assignment) Source Address is combined as 0x0040d420 is reachable via
  // multiple paths
  if (reg_state[15] == 0x0040d302) {
    // Reset tracking of whether we have a pointer when entering
    // ieee802154_validate_frame
    mhr_src_addr_ptr = false;
  } else if (reg_state[15] == 0x0040d3c4) {
    // We are in the "is a pointer" path
    mhr_src_addr_ptr = true;
  } else if (reg_state[15] == 0x0040d41a) {
    // Source address pointer assignment path triggered
    if (mhr_src_addr_ptr) {
      report_detected_triggered("FW49");
    }
  } else if (reg_state[15] == 0x0040d416) {
    // Destination address (NULL assignment only reached in buggy case)
    report_detected_triggered("FW49");
  }
}

void on_CVE_2021_3321() {
  // Check for size underflow in memmove call from ieee802154_reassemble
  report_reached("FW51");
  if (reg_state[2] > 0xf0000000 && reg_state[14] == 0x00403c78) {
    report_detected_triggered("FW51");
  }
}

void on_ieee802154_validate_frame() {
  report_reached("FP_FRB17");
  if (reg_state[8] == 0) {
    report_detected_triggered("FP_FRB17");
  }
}

void on_ieee802154_recv() {
  report_reached("FP_FRB16");
  // MPDU->dst = 0
  frb_print_regs();
  uint32_t sp = reg_state[13];
  uint32_t mpdu_dst = frb_mem_read(sp + 8, 4);
  uint32_t mpdu_src = frb_mem_read(sp + 12, 4);

  if (mpdu_dst == 0 || mpdu_src == 0) {
    report_detected_triggered("FP_FRB16");
  }
}

void on_net_buf_simple_pull() {
  report_reached("H62");
  if (reg_state[2] < reg_state[1]) {
    report_detected_triggered("H62");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x00406c58, on_CVE_2021_3322);
    frb_add_reflection_point(0x00406c96, on_CVE_2021_3323_callsite_1);
    frb_add_reflection_point(0x00406c9e, on_CVE_2021_3323_callsite_2);
    frb_add_reflection_point(0x0040cf4c, on_CVE_2021_3321);
    frb_add_reflection_point(0x0040d302, on_CVE_2021_3319);
    frb_add_reflection_point(0x0040d3c4, on_CVE_2021_3319);
    frb_add_reflection_point(0x0040d41a, on_CVE_2021_3319);
    frb_add_reflection_point(0x0040d416, on_CVE_2021_3319);
    frb_add_reflection_point(0x0040d130, on_CVE_2021_3320);
    frb_add_reflection_point(0x0040d4c4, on_ieee802154_validate_frame);
    frb_add_reflection_point(0x0040d110, on_ieee802154_recv);
    frb_add_reflection_point(0x0040d070, on_net_buf_simple_pull);
}
