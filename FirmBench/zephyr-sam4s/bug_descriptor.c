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

/* CVE-2021-3319: validate_addr() returned NULL for a truncated address but
 * ieee802154_validate_frame() accepted it.  These are the two inlined
 * assignment sites.  lr holds mhr->fs in this optimized leaf function. */
static void on_CVE_2021_3319_dst(void) {
  report_reached("FW49");

  uint32_t address = reg_state[8];
  uint32_t fs = reg_state[14];
  uint32_t address_mode = (frb_mem_read(fs + 1, 1) >> 2) & 0x3;
  if (address == 0 && address_mode != 0) {
    report_detected_triggered("FW49");
  }
}

static void on_CVE_2021_3319_src(void) {
  report_reached("FW49");

  uint32_t address = reg_state[10];
  uint32_t fs = reg_state[14];
  uint32_t address_mode = (frb_mem_read(fs + 1, 1) >> 6) & 0x3;
  if (address == 0 && address_mode != 0) {
    report_detected_triggered("FW49");
  }
}

/* CVE-2021-3320: an ACK has passed validation and scanning checks and is
 * about to fall through the data-frame receive path. */
static void on_CVE_2021_3320(void) {
  report_reached("FW62");
  if (reg_state[3] == 2) {
    report_detected_triggered("FW62");
  }
}

/* CVE-2021-3321: fragment_add_to_cache() is about to accept a fragment whose
 * buffer is shorter than its four-byte FRAG1 or five-byte FRAGN header. */
static void on_CVE_2021_3321(void) {
  report_reached("FW63");

  uint32_t type = reg_state[2];
  uint32_t frag = reg_state[10];
  uint32_t len = frb_mem_read(frag + 0x0c, 2);
  if ((type == 0xc0 && len < 4) || (type == 0xe0 && len < 5)) {
    report_detected_triggered("FW63");
  }
}

/* CVE-2021-3322: completion of a one-fragment datagram aliases cache->pkt
 * with the input pkt.  The following ownership transfer therefore clears
 * the same pkt->buffer it just assigned. */
static void on_CVE_2021_3322(void) {
  report_reached("FW64");

  uint32_t cache = reg_state[4];
  uint32_t pkt = reg_state[5];
  uint32_t cached_pkt = frb_mem_read(cache + 0x30, 4);
  if (cached_pkt == pkt) {
    report_detected_triggered("FW64");
  }
}

/* CVE-2021-3323: compressed_hdr_size is complete in r4 on both IPHC paths;
 * r6 is pkt->buffer.  Pulling a larger header underflows net_buf::len. */
static void on_CVE_2021_3323(void) {
  report_reached("FW65");

  uint32_t compressed_hdr_size = reg_state[4];
  uint32_t net_buf = reg_state[6];
  uint32_t len = frb_mem_read(net_buf + 0x0c, 2);
  if (compressed_hdr_size > len) {
    report_detected_triggered("FW65");
  }
}

void register_reflection_points(void) {
  frb_add_reflection_point(0x0040d356, on_CVE_2021_3319_dst);
  frb_add_reflection_point(0x0040d398, on_CVE_2021_3319_src);
  frb_add_reflection_point(0x0040d13a, on_CVE_2021_3320);
  frb_add_reflection_point(0x00403a82, on_CVE_2021_3321);
  frb_add_reflection_point(0x00403b56, on_CVE_2021_3322);
  frb_add_reflection_point(0x00406c9e, on_CVE_2021_3323);
}
