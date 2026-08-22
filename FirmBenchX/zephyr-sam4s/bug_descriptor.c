#include <tcclib.h>
#include <stdint.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_report_detected_triggered(const char *bug_id);
extern void frb_report_reached(const char *bug_id);
extern void frb_add_reflection_point(uint32_t address,
                                     void (*introspection_point)(void));

static void report_detected_triggered(const char *bug_id) {
  frb_report_detected_triggered(bug_id);
}

static void report_reached(const char *bug_id) {
  frb_report_reached(bug_id);
}

/* CVE-2021-3322 is the sole retained Fuzzware defect in this rebuild.
 * Completion of a one-fragment datagram aliases cache->pkt with the input
 * pkt, so the following ownership transfer clears its own pkt->buffer. */
static void on_CVE_2021_3322(void) {
  report_reached("FW64");

  uint32_t cache = reg_state[4];
  uint32_t pkt = reg_state[5];
  uint32_t cached_pkt = frb_mem_read(cache + 0x30, 4);
  if (cached_pkt == pkt) {
    report_detected_triggered("FW64");
  }
}

void register_reflection_points(void) {
  frb_add_reflection_point(0x00403b70, on_CVE_2021_3322);
}
