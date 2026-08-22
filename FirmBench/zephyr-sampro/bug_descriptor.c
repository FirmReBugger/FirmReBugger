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


void on_CVE_2021_3323_memmove() {
  // MISLABELED as CVE-2020-10064 originally -- CORRECTED 2026-07-14 (see
  // bug_analysis/bugs/FW46.md). Live-traced: lr==0x00407987 resolves to
  // uncompress_IPHC_header (6lo.c:1356), and the hooked memmove was
  // observed live with n=0xFFFFFFFB (an underflowed size). This is
  // CVE-2021-3323 (GHSA-89j6-qpxf-pfpc, Integer Underflow in 6LoWPAN IPHC
  // Header Uncompression) -- the SAME CVE as FW53 below, just hooked at
  // the downstream memmove consequence instead of FW53's upstream
  // size-check point. CVE-2020-10064 is a different, unrelated bug
  // (stack overflow in drivers/ieee802154/ieee802154_nrf5.c's nrf5_tx,
  // GHSA-rf6q-rhhp-pqhf) that this binary's rf2xx driver doesn't even use.
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
  // CVE-2021-3321: reject fragments shorter than the 4/5-byte 6LoWPAN
  // fragmentation header before frag->len - hdr_len can underflow.
  report_reached("FW51");
  uint32_t frag = reg_state[5];
  uint32_t data = frb_mem_read(frag + 0x8, 4);
  uint32_t buf_len = frb_mem_read(frag + 0xc, 2);
  if (data == 0) {
    return;
  }
  uint32_t datagram_type = frb_mem_read(data, 1);
  uint32_t hdr_len = ((datagram_type & 0xf8) == 0xc0) ? 4 : 5;

  if (buf_len < hdr_len) {
    report_detected_triggered("FW51");
  }
}

void on_preinit_gmac_tx_interrupt() {
  report_reached("FP_FRB30");
  // At queue0_isr+0x10, r4 is eth0_data and r8 is GMAC_ISR. Either a
  // transmit-error status (0x70) or transmit-complete status (0x80) will
  // give r4+0x48. A zero limit and NULL poll-list head prove that the IRQ
  // was injected before eth0_iface_init initialized that semaphore.
  uint32_t tx_sem = reg_state[4] + 0x48;
  uint32_t limit = frb_mem_read(tx_sem + 0xc, 4);
  uint32_t poll_head = frb_mem_read(tx_sem + 0x10, 4);
  uint32_t tx_status = reg_state[8] & 0xf0;
  if (tx_status != 0 && limit == 0 && poll_head == 0) {
    report_detected_triggered("FP_FRB30");
  }
}

void check_compressed_hdr_size(uint32_t compressed_hdr_size) {
  // CVE-2021-3323
  uint32_t net_buf = reg_state[6];
  uint32_t pkt_buf_len_addr = (net_buf + 0x8) + 0x4;
  uint32_t pkt_buf_len = frb_mem_read(pkt_buf_len_addr, 2);

  if (pkt_buf_len < compressed_hdr_size) {
    report_detected_triggered("FW53");
  }
}

void on_CVE_2021_3323_callsite_1() {
  report_reached("FW53");
  uint32_t compressed_hdr_size = reg_state[3];

  check_compressed_hdr_size(compressed_hdr_size);
}

void on_CVE_2021_3323_callsite_2() {
  report_reached("FW53");
  uint32_t compressed_hdr_size = reg_state[4];

  check_compressed_hdr_size(compressed_hdr_size);
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
  // The rehosting-only failure begins when DAD work is submitted before
  // iface_ipv6_dad_init has installed dad_timeout as its handler. This root
  // predicate covers both the later NULL callback and cleared-list-node
  // manifestations formerly tracked separately as FP_FRB18/FP_FRB19.
  uint32_t dad_timer = frb_symbolize("dad_timer", 0);
  if (reg_state[1] == dad_timer && frb_mem_read(dad_timer + 0x4, 4) == 0) {
    report_detected_triggered("FP_FRB18");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0040daba, on_CVE_2021_3323_memmove);  // renamed from on_CVE_2020_10064 -- see FW46.md
    frb_add_reflection_point(0x0040dfbc, on_CVE_2021_3320);
    frb_add_reflection_point(0x00407918, on_CVE_2021_3322);
    frb_add_reflection_point(0x00404826, on_CVE_2021_3321);
    frb_add_reflection_point(0x004051c0, on_net_if_config_ipv6_get);
    frb_add_reflection_point(0x0040e76c, on_net_if_ipv6_calc_reachable_time);
    frb_add_reflection_point(0x0040d796, on_preinit_gmac_tx_interrupt);
    frb_add_reflection_point(0x0040b980, on_z_work_q_main);
    frb_add_reflection_point(0x00407956, on_CVE_2021_3323_callsite_1);
    frb_add_reflection_point(0x0040795e, on_CVE_2021_3323_callsite_2);
}
