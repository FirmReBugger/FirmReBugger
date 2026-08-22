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

void BUG_H18() {
  // CVE-2022-39274
  report_reached("H18");
  if (reg_state[6] == 0) {
    report_detected_triggered("H18");
  }
}

void on_LoRaMacCryptoHandleJoinAccept() {
  report_reached("FP_FRB25");
  // joinEUI = SecureElementGetJoinEui() = SeNvm+8 when SeNvm is still NULL
  // (uninitialized SecureElement context) - not exactly 0, so check for any
  // implausibly-small pointer, not just literal NULL. Proven via TriAgent
  // triage of crash 0x80085f3_0x80085fe_read_error (see bug_analysis/bugs/FRB25.md).
  if (reg_state[3] < 0x1000) {
    report_detected_triggered("FP_FRB25");
  }
}

void on_GetLastFcntDown() {
  report_reached("FP_FRB26");
  if (reg_state[3] == 0) {
    report_detected_triggered("FP_FRB26");
  }
}

void mcpsidication_failed() {
  report_reached("FP_FRB58");
  report_detected_triggered("FP_FRB58");
}

// FRB60: cbpprintf_external (zephyr/lib/os/cbprintf_packaged.c) walks a
// packaged log message's inline-string region reading index-byte+string+NUL
// triples, and for each one stores a freshly-computed string pointer into
// packaged_base + index_byte*4 with NO bounds check against the message's
// real argument-slot count. Proven root cause (TriAgent-rendered report:
// reports/loramac-node/crashes/0x800bb09_0x800bb08_jump_invalid) - the index
// byte, when the cursor is walking non-string data, is arbitrary, and the
// resulting write can land anywhere; observed landing on log_buffer+24
// (mpsc_pbuf's own callback pointer), corrupting it to a data address that
// later SIGILLs when called. See bug_analysis/bugs/FRB60.md.
static uint32_t frb60_package_base;
static uint32_t frb60_argument_slots;

void frb60_capture_package_bounds() {
  // Capture the immutable header before any pointer-patching store can
  // overwrite byte zero of the package itself.
  frb60_package_base = reg_state[3];
  frb60_argument_slots = frb_mem_read(reg_state[3], 1);
}

void frb60_cbpprintf_external_unbounded_index() {
  report_reached("FRB60");
  // At the store, r3 is the inline-string word index and r5 is the package
  // base. Use the entry snapshot because an earlier bad index can rewrite the
  // live header and make a later out-of-bounds index appear in bounds.
  if (reg_state[5] == frb60_package_base &&
      reg_state[3] >= frb60_argument_slots) {
    report_detected_triggered("FRB60");
  }
}

// FRB69: ids_print indexes the five-entry severity table with the log
// message's three-bit level field without checking that it is a defined
// Zephyr level (0..4). Corrupt/stale log-pool metadata can therefore make the
// following load read beyond the table and pass an invalid pointer to "%s".
void frb69_ids_print_unbounded_level() {
  report_reached("FRB69");
  if (reg_state[9] > 4) {
    report_detected_triggered("FRB69");
  }
}

// The same vulnerable overwrite-mode reuse can replace a claimed message's
// package while log_output_msg2_process is still consuming it. At this call
// site r3 is the package base and package[1] is the printf format pointer.
void frb69_cbpprintf_corrupt_package() {
  report_reached("FRB69");
  uint32_t package = reg_state[3];
  // This caller always passes msg->data inside the 256-word buf32 ring.
  // Packets are contiguous and never wrap, so their declared argument words
  // must fit between the package base and the end of that ring.
  if (package < 0x200002b0 || package > 0x200006ac || (package & 3) != 0) {
    report_detected_triggered("FRB69");
    return;
  }

  uint32_t argument_slots = frb_mem_read(package, 1);
  uint32_t contiguous_words = (0x200006b0 - package) / 4;
  if (argument_slots > contiguous_words) {
    report_detected_triggered("FRB69");
    return;
  }

  uint32_t format = frb_mem_read(package + 4, 4);
  bool in_flash = format >= 0x08000000 && format < 0x08040000;
  bool in_sram = format >= 0x20000000 && format < 0x20010000;
  if (!in_flash && !in_sram) {
    report_detected_triggered("FRB69");
  }
}

// A reused package can retain a mapped format string while replacing a "%s"
// argument with a non-address scalar. Limit this Raven to strlen's cbvprintf
// call site so unrelated strlen callers are never attributed to FRB69.
void frb69_cbvprintf_corrupt_string_argument() {
  report_reached("FRB69");
  uint32_t string = reg_state[3];
  bool from_cbvprintf = reg_state[14] == 0x080018bd;
  bool in_flash = string >= 0x08000000 && string < 0x08040000;
  bool in_sram = string >= 0x20000000 && string < 0x20010000;
  if (from_cbvprintf && !in_flash && !in_sram) {
    report_detected_triggered("FRB69");
  }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08006c62, BUG_H18);
    frb_add_reflection_point(0x080085fe, on_LoRaMacCryptoHandleJoinAccept);
    frb_add_reflection_point(0x080081fc, on_GetLastFcntDown);
    frb_add_reflection_point(0x080030b2, mcpsidication_failed);
    frb_add_reflection_point(0x0800b5d6, frb60_capture_package_bounds);
    frb_add_reflection_point(0x0800b614, frb60_cbpprintf_external_unbounded_index);
    frb_add_reflection_point(0x0800206c, frb69_ids_print_unbounded_level);
    frb_add_reflection_point(0x080021fc, frb69_cbpprintf_corrupt_package);
    frb_add_reflection_point(0x08000bb6, frb69_cbvprintf_corrupt_string_argument);
}
