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

void H19() {
  report_reached("H19");
  uint32_t rh = reg_state[1];
  uint8_t len = frb_mem_read(rh + 1, 1);
  uint8_t compre = frb_mem_read(rh + 4, 1) & 0x0F;
  uint8_t padding = frb_mem_read(rh + 5, 1) >> 4;

  if (len * 8 < padding + (16 - compre)) {
    report_detected_triggered("H19");
  }
}

void H20() {
  report_reached("H20");

  /* r7 preserves src_len at the matched-return branch.  A zero-length key
   * can only match the zero-initialized entry sentinel. */
  if (reg_state[7] == 0) {
    report_detected_triggered("H20");
  }
}

void H21() {
  report_reached("H21");
  uint32_t ipv6 = reg_state[6];
  uint32_t ipv6_size = frb_mem_read(ipv6 + 8, 4);
  uint32_t uncomp_header_len = reg_state[5];
  uint32_t copy_size = reg_state[2];

  if (uncomp_header_len + copy_size > ipv6_size) {
    report_detected_triggered("H21");
  }
}

void H22() {
  report_reached("H22");
  uint32_t sixlo_size = reg_state[2];
  uint32_t payload_offset = reg_state[4];

  if (payload_offset > sixlo_size) {
    // subtraction causes integer underflow
    report_detected_triggered("H22");
  }
}

void H23() {
  report_reached("H23");
  uint32_t frag_size = reg_state[4];

  if (frag_size > 0x80000000) {
    // Integer underflow detected
    report_detected_triggered("H23");
  }
}

void H24() {
  report_reached("H24");
  uint32_t pkt = reg_state[7];
  uint32_t next = frb_mem_read(pkt, 4);
  uint32_t next_next = frb_mem_read(next, 4);

  if (next_next == 0) {
    // Null pointer detected
    report_detected_triggered("H24");
  }
}

void H25() {
  report_reached("H25");
  uint32_t snippet = reg_state[3];
  uint32_t size = frb_mem_read(snippet + 8, 4);
  uint32_t pkt = reg_state[7];
  uint32_t ipv6_snip = frb_mem_read(pkt, 4);
  uint32_t ipv6_data = frb_mem_read(ipv6_snip + 4, 4);
  uint8_t nh = frb_mem_read(ipv6_data + 6, 1);
  bool compressible_non_udp = (nh == 0) || (nh == 41) || (nh == 43) ||
                              (nh == 44) || (nh == 60) || (nh == 135);

  if (size > 8 && compressible_non_udp) {
    /* The UNDEF branch reserves only sizeof(udp_hdr_t), but the next-header
     * value will route this larger snippet through an NHC encoder. */
    report_detected_triggered("H25");
  }
}

void H26() {
  report_reached("H26");

  /* At the pkt->data store, r3 is the exact new data pointer.  NULL means the
   * complete snippet was consumed but the old node remains linked. */
  if (reg_state[3] == 0) {
    report_detected_triggered("H26");
  }
}

void H27() {
  report_reached("H27");
  uint32_t timer = 0x2000c9dc; // timer
  uint32_t callback = frb_mem_read(timer + 8, 4);

  if (callback == 0) {
    // Timer is not initialized but gets scheduled
    report_detected_triggered("H27");
  }
}

void impossible_rf_event_assert() {
  report_reached("FP_FRB31");
  /* All invalid RF event/state combinations converge on this assertion-only
   * basic block.  Normal CC2538 interrupt states branch around it. */
  report_detected_triggered("FP_FRB31");
}

void FRB68() {
  report_reached("FRB68");
  /* r7 preserves argc at the del-only argv[2] load. */
  if (reg_state[7] < 3) {
    report_detected_triggered("FRB68");
  }
}

void illegal_isr_mutex_wait() {
  report_reached("FRB32");
  uint32_t sp = reg_state[13];

  /* Blocking on a contended mutex from an ISR links the interrupted thread
   * into the waiter list even though it can resume after the interrupt. */
  if (sp >= 0x20000000 && sp < 0x20000200) {
    report_detected_triggered("FRB32");
  }
}

void rfcore_assert_with_contended_stdio() {
  report_reached("FRB32");
  uint32_t sp = reg_state[13];
  uint32_t ethos_out_mutex = frb_mem_read(0x200071c0, 4);

  /* RFCORE_ASSERT_failure prints through stdio_ethos.  If the output mutex is
   * already locked, this ISR call is guaranteed to enter mutex_lock's blocking
   * path and enqueue the interrupted active thread as though it were a caller. */
  if (sp >= 0x20000000 && sp < 0x20000200 && ethos_out_mutex != 0) {
    report_detected_triggered("FRB32");
  }
}

void FRB37() {
  report_reached("FRB37");
  // Check NULL pointer deref on sixlo->data
  if (reg_state[11] == 0) {
    report_detected_triggered("FRB37");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0020c994, H19);
    frb_add_reflection_point(0x0020ea4e, H20);
    frb_add_reflection_point(0x0020fbea, H21);
    frb_add_reflection_point(0x0020fbe2, H22);
    frb_add_reflection_point(0x0020d682, H23);
    frb_add_reflection_point(0x0020f156, H24);
    frb_add_reflection_point(0x0020f10e, H25);
    frb_add_reflection_point(0x0020ae1e, H26);
    frb_add_reflection_point(0x0020dd20, H27);
    frb_add_reflection_point(0x00200b4a, impossible_rf_event_assert);
    frb_add_reflection_point(0x0021415a, FRB68);
    frb_add_reflection_point(0x00200468, rfcore_assert_with_contended_stdio);
    frb_add_reflection_point(0x002013f0, illegal_isr_mutex_wait);
    frb_add_reflection_point(0x0020fbde, FRB37);
}
