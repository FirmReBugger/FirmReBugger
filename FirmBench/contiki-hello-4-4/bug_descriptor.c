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

static uint32_t PACKETBUF_ALIGNED = 0x200006b0;
static uint32_t PACKETBUF_ALIGNED_LEN = 32 * 4;

static uint32_t UIP_BUF = 0x200025c8;
static uint32_t UIP_BUFSIZE = 1280;

// Bug: new-Bug-l2cap_mtu_6lo_output_packetbuf_oob_write
// We hook memcpy calls with LRs known to originate from 6lo (checks relying on
// BLE_L2CAP_NODE_MTU) and l2cap (missing check) PORTING: memcpy call in
// function "output" (inlined compress_hdr_iphc) with variable size and related
// to the "hc06_ptr" variable
static uint32_t MEMCPY_CALL_LOC_COMPRESS_HDR_IPHC_PACKETBUF_OOB = 0x207AF0;
// PORTING: memcpy call in function "output" (!frag_needed case) with variable
// size which is followed by function "send_packet"
static uint32_t MEMCPY_CALL_LOC_OUTPUT_PACKETBUF_OOB = 0x207C92;
// PORTING: memcpy call in function "process_thread_ble_l2cap_tx_process" with
// variable size which is followed by packetbuf_set_datalen / ... / send
static uint32_t MEMCPY_CALL_LOC_BLE_L2CAP_TX_PROCESS = 0x205638;
// PORTING: memcpy call in function "fragment_copy_payload_and_send". These OOBs
// (always) originate from output->fragment_copy_payload_and_send->memcpy
static uint32_t MEMCPY_CALL_LOC_fragment_copy_payload_and_send = 0x204bae;
// PORTING: memcpy call in function "packetbuf_copyfrom". These OOBs (always)
// originate from
// output->fragment_copy_payload_and_send->queuebuf_to_packetbuf->packetbuf_copyfrom->memcpy
static uint32_t MEMCPY_CALL_LOC_packetbuf_copyfrom = 0x207512;
// PORTING: memcpy call in function "compress_addr_64" (first call with constant
// size 2). These OOBs (always) originate from output->compress_addr_64->memcpy
static uint32_t MEMCPY_CALL_LOC_output_compress_addr_64_1 = 0x20748a;
// PORTING: memcpy call in function "compress_addr_64" (second call with
// constant size 8). These OOBs (always) originate from
// output->compress_addr_64->memcpy
static uint32_t MEMCPY_CALL_LOC_output_compress_addr_64_2 = 0x20749e;
// There are different, fixed/small-sized memcpy calls which may OOB in more
// niche situations create a catch-all here PORTING: sicslowpan_driver.output
// (mem.u32(symbols["sicslowpan_driver"]+0xc))
static uint32_t SICSLOWPAN_DRIVER_OUTPUT_FN = 0x207564;
static uint32_t SICSLOWPAN_DRIVER_OUTPUT_FN_END = 0x207cb8;

// memcpy packetbuf OOB cases
// PORTING: Hook return from memcpy call in input following packetbuf_dataptr
// (this matches the return for call hooked for unchecked_sdu_length)
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_UNCHECKED_SDU = 0x205b7e;
// PORTING: Hook return matching the first FW58 hook memcpy call in input
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_FW58_1 = 0x205b28;
// PORTING: Hook return matching the second FW58 hook memcpy call in input
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_FW58_2 = 0x205b4a;
// PORTING: Return from memcpy in input following assignment of
// packetbuf_payload_len and other OOB against IP packet length Fix:
// https://github.com/contiki-ng/contiki-ng/commit/c76aa9bc
static uint32_t MEMCPY_CALL_LOC_SICSLOWPAN_FIRSTFRAG_OR_UNFRAG_OOB = 0x208514;
// PORTING: memcpy call in function "input" with variable size and related to
// the "hc06_ptr" variable
static uint32_t MEMCPY_CALL_LOC_UNCOMPRESS_HDR_IPHC = 0x208398;

// Bugs: H07
// PORTING: Symbol: frag_info
static uint32_t FRAG_INFO = 0x20000a10;
// sicslowpan_frag_info frag_info[2]
static uint32_t FRAG_INFO_SIZE = 2 * 0xb8;

void H03() {
  uint32_t packetbuf_dataptr = reg_state[0];
  uint32_t channel = reg_state[5];
  report_reached("H03");
  uint32_t sdu_length = frb_mem_read(channel + 0xa14, 2);
  // Fix:
  // https://github.com/contiki-ng/contiki-ng/commit/506f9def7cdff853fa24cf6d88e1f4e5619dc46c
  if ((packetbuf_dataptr + sdu_length) >
      (PACKETBUF_ALIGNED + PACKETBUF_ALIGNED_LEN)) {
    report_detected_triggered("H03");
  }
}

static int recusion_depth = 0;

void H04_enter() {
  report_reached("H04");
  recusion_depth++;
  if (recusion_depth > 10) {
    report_detected_triggered("H04");
  }
}

void H04_return() { recusion_depth--; }

void FW58_1() {
  // CVE-2020-12140
  uint32_t sp = reg_state[13];
  uint32_t len = frb_mem_read(sp + 4, 2);
  uint32_t res = len - 2;
  report_reached("FW58");
  if (res > 0x500 || res < 0) {
    report_detected_triggered("FW58");
  }
}

void FW58_2() {
  uint32_t sp = reg_state[13];
  uint32_t len = frb_mem_read(sp + 4, 2);

  uint32_t current_index = frb_mem_read(reg_state[9] + 0xa16, 2);
  uint32_t res = current_index + len;
  report_reached("FW58");
  if (res > 0x500 || res < 0) {
    report_detected_triggered("FW58");
  }
}

void on_packetbuf_oob_writes() {
  uint32_t dst = reg_state[0];
  uint32_t lr = reg_state[14];
  report_reached("H06");
  report_reached("H07");

  // Check for any copies targeting packetbuf
  if ((dst >= PACKETBUF_ALIGNED) &&
      (dst < PACKETBUF_ALIGNED + PACKETBUF_ALIGNED_LEN)) {
    // Remaining buffer size: buffer len minus buffer cursor offset
    uint32_t buf_size = PACKETBUF_ALIGNED_LEN - (dst - PACKETBUF_ALIGNED);
    uint32_t n = reg_state[2];

    if (n > buf_size) {
      bool is_FW58 = (lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_FW58_1 | 1)) ||
                     (lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_FW58_2 | 1));

      bool is_ble_l2cap_MTU_output_OOB = false;

      // output OOB: Specific output call sites
      is_ble_l2cap_MTU_output_OOB =
          is_ble_l2cap_MTU_output_OOB ||
          (lr == (MEMCPY_CALL_LOC_COMPRESS_HDR_IPHC_PACKETBUF_OOB | 1) ||
           lr == (MEMCPY_CALL_LOC_OUTPUT_PACKETBUF_OOB | 1) ||
           lr == (MEMCPY_CALL_LOC_BLE_L2CAP_TX_PROCESS | 1));

      // output OOB: Specific OOBs in fragment_copy_payload_and_send
      is_ble_l2cap_MTU_output_OOB =
          is_ble_l2cap_MTU_output_OOB ||
          (lr == (MEMCPY_CALL_LOC_fragment_copy_payload_and_send | 1) ||
           lr == (MEMCPY_CALL_LOC_packetbuf_copyfrom | 1));

      // output OOB: Specific OOBs in compress_addr_64
      is_ble_l2cap_MTU_output_OOB =
          is_ble_l2cap_MTU_output_OOB ||
          (lr == (MEMCPY_CALL_LOC_output_compress_addr_64_1 | 1) ||
           lr == (MEMCPY_CALL_LOC_output_compress_addr_64_2 | 1));

      // output OOB: Catch-all for Niche OOBs with small and constant-size
      // memcpy calls
      is_ble_l2cap_MTU_output_OOB = is_ble_l2cap_MTU_output_OOB ||
                                    ((lr >= SICSLOWPAN_DRIVER_OUTPUT_FN &&
                                      lr < SICSLOWPAN_DRIVER_OUTPUT_FN_END) &&
                                     (n > 0 && n < 0x20));

      // Conditions to ignore known packetbuf OOB write sources
      if (is_FW58 ||
          lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_UNCHECKED_SDU | 1) ||
          lr == (MEMCPY_CALL_LOC_SICSLOWPAN_FIRSTFRAG_OR_UNFRAG_OOB | 1)) {
        return;
      } else if (lr == (MEMCPY_CALL_LOC_UNCOMPRESS_HDR_IPHC | 1)) {
        // Log a specific bug related to uncompress_hdr_iphc_oob_write
        report_detected_triggered("H07");
      } else if (is_ble_l2cap_MTU_output_OOB) {
        report_detected_triggered("H06");
      }
    }
  }
}

void on_fraginfo_oob_writes() {
  uint32_t dst = reg_state[0];
  report_reached("H07");
  report_reached("H08");
  // Check for any copies targeting fragment buffers
  if ((dst >= FRAG_INFO) && (dst < FRAG_INFO + FRAG_INFO_SIZE)) {
    // Remaining buffer size: buffer len minus buffer cursor offset
    uint32_t buf_size = FRAG_INFO_SIZE - (dst - FRAG_INFO);
    uint32_t n = reg_state[2];

    if (n > buf_size) {
      uint32_t lr = reg_state[14];
      if (lr == (MEMCPY_CALL_LOC_UNCOMPRESS_HDR_IPHC | 1)) {
        // Fix commits:
        // uncompress_hdr_iphc retval:
        // https://github.com/contiki-ng/contiki-ng/commit/971354a
        // uncompress_hdr_iphc bufsize arg:
        // https://github.com/contiki-ng/contiki-ng/commit/b88e5c3 Main checks:
        // https://github.com/contiki-ng/contiki-ng/commit/668f244 Off-by-one
        // fix: https://github.com/contiki-ng/contiki-ng/commit/79cd1d6
        report_detected_triggered("H07");
      } else if (lr ==
                 (MEMCPY_CALL_LOC_SICSLOWPAN_FIRSTFRAG_OR_UNFRAG_OOB | 1)) {
        // buffer_size tracking:
        // https://github.com/contiki-ng/contiki-ng/commit/b88e5c3 buffer_size
        // oob check: https://github.com/contiki-ng/contiki-ng/commit/c76aa9bc
        report_detected_triggered("H08");
      }
    }
  }
}

void on_rpl_ext_header_srh_update() {
  report_reached("H09");
  report_reached("H10");
  uint8_t RPL_RH_LEN = 4;
  uint8_t RPL_SRH_LEN = 4;

  uint32_t rh_header = reg_state[0];
  // Read rh_header->len
  uint8_t len = frb_mem_read(rh_header + 1, 1);

  uint8_t ext_len = len * 8 + 8;
  uint32_t srh_header = rh_header + RPL_RH_LEN;

  // Read rh_header->seg_left
  uint8_t segments_left = frb_mem_read(rh_header + 3, 1);

  // Read srh_header->cmpr
  uint8_t cmpr = frb_mem_read(srh_header + 0, 1);

  uint8_t cmpri = cmpr >> 4;
  uint8_t cmpre = cmpr & 0x0f;

  // Read srh_header->pad
  uint8_t padding = frb_mem_read(srh_header + 1, 1) >> 4;

  uint8_t path_len =
      ((ext_len - padding - RPL_RH_LEN - RPL_SRH_LEN - (16 - cmpre)) /
       (16 - cmpri)) +
      1;

  // Check for too many segments left
  if (segments_left > path_len) {
    // Fix:
    // https://github.com/contiki-ng/contiki-ng/commit/f0bb7f314c424630837d2ed08ec0bc90e1ccb15e
    report_detected_triggered("H09");
  }

  uint8_t i = path_len - segments_left;
  cmpr = (segments_left == 1) ? cmpre : cmpri;
  uint32_t rh_offset = rh_header - (uint32_t)UIP_BUF;
  uint32_t addr_offset = RPL_RH_LEN + RPL_SRH_LEN + (i * (16 - cmpri));

  // Check for invalid SRH address pointer
  if (rh_offset + addr_offset + 16 - cmpr > UIP_BUFSIZE) {
    // Fix:
    // https://github.com/contiki-ng/contiki-ng/commit/99a9257421ca5305ef6a360c02f63561e63ecc60
    report_detected_triggered("H10");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x00205b6e, H03);
    frb_add_reflection_point(0x00206972, H04_return);
    frb_add_reflection_point(0x0020696e, H04_enter);
    frb_add_reflection_point(0x00205b10, FW58_1);
    frb_add_reflection_point(0x00205b32, FW58_2);
    frb_add_reflection_point(0x0020aa58, on_packetbuf_oob_writes);
    frb_add_reflection_point(0x0020aa58, on_fraginfo_oob_writes);
    frb_add_reflection_point(0x002097f0, on_rpl_ext_header_srh_update);
}
