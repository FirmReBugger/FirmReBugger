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

// Bug: new-Bug-l2cap_mtu_6lo_output_packetbuf_oob_write
// We hook memcpy calls with LRs known to originate from 6lo (checks relying on
// BLE_L2CAP_NODE_MTU) and l2cap (missing check) PORTING: memcpy call in
// function "output" (inlined compress_hdr_iphc) with variable size and related
// to the "hc06_ptr" variable
static uint32_t MEMCPY_CALL_LOC_COMPRESS_HDR_IPHC_PACKETBUF_OOB = 0x00207d98;
// PORTING: memcpy call in function "output" (!frag_needed case) with variable
// size which is followed by function "send_packet"
static uint32_t MEMCPY_CALL_LOC_OUTPUT_PACKETBUF_OOB = 0x00207f3a;
// PORTING: memcpy call in function "process_thread_ble_l2cap_tx_process" with
// variable size which is followed by packetbuf_set_datalen / ... / send
static uint32_t MEMCPY_CALL_LOC_BLE_L2CAP_TX_PROCESS = 0x002057b6;
// PORTING: memcpy call in function "fragment_copy_payload_and_send". These OOBs
// (always) originate from output->fragment_copy_payload_and_send->memcpy
static uint32_t MEMCPY_CALL_LOC_fragment_copy_payload_and_send = 0x002077ba;
// PORTING: memcpy call in function "packetbuf_copyfrom". These OOBs (always)
// originate from
// output->fragment_copy_payload_and_send->queuebuf_to_packetbuf->packetbuf_copyfrom->memcpy
static uint32_t MEMCPY_CALL_LOC_packetbuf_copyfrom = 0x00204cfe;
// PORTING: memcpy call in function "compress_addr_64" (first call with constant
// size 2). These OOBs (always) originate from output->compress_addr_64->memcpy
static uint32_t MEMCPY_CALL_LOC_output_compress_addr_64_1 = 0x00207732;
// PORTING: memcpy call in function "compress_addr_64" (second call with
// constant size 8). These OOBs (always) originate from
// output->compress_addr_64->memcpy
static uint32_t MEMCPY_CALL_LOC_output_compress_addr_64_2 = 0x00207746;
// There are different, fixed/small-sized memcpy calls which may OOB in more
// niche situations create a catch-all here PORTING: sicslowpan_driver.output
// (mem.u32(symbols["sicslowpan_driver"]+0xc))
static uint32_t SICSLOWPAN_DRIVER_OUTPUT_FN = 0x0020780c;
static uint32_t SICSLOWPAN_DRIVER_OUTPUT_FN_END = 0x00207f60;

// memcpy packetbuf OOB cases
// PORTING: Hook return from memcpy call in input following packetbuf_dataptr
// (this matches the return for call hooked for unchecked_sdu_length)
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_UNCHECKED_SDU = 0x00205d06;
void H65() {
  uint32_t packetbuf_dataptr = reg_state[0];
  uint32_t channel = reg_state[6];
  report_reached("H65");
  uint32_t sdu_length = frb_mem_read(channel + 0xa14, 2);
  // Fix: https://github.com/contiki-ng/contiki-ng/commit/20ae1a06f2fa13acfba43da73adb71dc61fcef84
  if ((packetbuf_dataptr + sdu_length) >
      (PACKETBUF_ALIGNED + PACKETBUF_ALIGNED_LEN)) {
    report_detected_triggered("H65");
  }
}

static int recusion_depth = 0;

void H66_enter() {
  report_reached("H66");
  recusion_depth++;
  if (recusion_depth > 10) {
    report_detected_triggered("H66");
  }
}

void H66_return() { recusion_depth--; }

void H67() {
  report_reached("H67");
  uint32_t dst = reg_state[0];
  uint32_t lr = reg_state[14];

  // Check for any copies targeting packetbuf
  if ((dst >= PACKETBUF_ALIGNED) &&
      (dst < PACKETBUF_ALIGNED + PACKETBUF_ALIGNED_LEN)) {
    // Remaining buffer size: buffer len minus buffer cursor offset
    uint32_t buf_size = PACKETBUF_ALIGNED_LEN - (dst - PACKETBUF_ALIGNED);
    uint32_t n = reg_state[2];

    if (n > buf_size) {
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
      if (lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_UNCHECKED_SDU | 1)) {
        return;
      } else if (is_ble_l2cap_MTU_output_OOB) {
        report_detected_triggered("H67");
      }
    }
  }
}

void H11() {
  // CVE-2022-41873
  report_reached("H11");
  uint32_t r8 = reg_state[8];
  if (((r8 >> 8) & 0xff) != 0) {
    report_detected_triggered("H11");
  }
}

void H12() {
  // CVE-2022-41972
  report_reached("H12");
  uint32_t r5 = reg_state[5];
  if (r5 == 0) {
    report_detected_triggered("H12");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x00205cf6, H65);
    frb_add_reflection_point(0x00206c0a, H66_return);
    frb_add_reflection_point(0x00206c06, H66_enter);
    frb_add_reflection_point(0x0020ac5c, H67);
    frb_add_reflection_point(0x00205c32, H11);
    frb_add_reflection_point(0x0020b4a8, H12);
}
