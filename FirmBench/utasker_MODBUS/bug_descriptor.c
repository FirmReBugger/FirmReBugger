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

void BUG_FP_FW40() {
    report_reached("FP_FW40");
    // (FP) A fuzz-injected timer or receive callback can run before the
    // corresponding MODBUS serial handle is published. At each handoff r0 is
    // the 1-based driver ID; zero underflows the driver-table index. Fuzzware
    // listed the three paths separately, but they share this one root cause.
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FW40");
    }
}

void BUG_S03() {
    report_reached("S03");
    // Direct byte, halfword, or word store through an address parsed from the
    // debug console's memory-modification command, with no address allowlist.
    report_detected_triggered("S03");
}

void BUG_FRB61() {
    report_reached("FRB61");
    // fnMODBUS maps a request port field to an index into the two-byte
    // SerialHandle array. At both loads r4 is that index; values >= 2 are OOB.
    if (reg_state[4] >= 2) {
        report_detected_triggered("FRB61");
    }
}

void BUG_FRB62() {
    report_reached("FRB62");
    // Raw byte, halfword, or word load through an address parsed from the
    // debug console's memory-display command, with no readable-range check.
    report_detected_triggered("FRB62");
}

void BUG_FP_FRB63() {
    report_reached("FP_FRB63");
    // At the first descriptor load, a non-NULL pointer outside main SRAM will
    // fault immediately. NULL is readable in this rehosting map and abstains.
    if (reg_state[7] != 0 &&
        (reg_state[7] < 0x20000000 || reg_state[7] >= 0x20030000)) {
        report_detected_triggered("FP_FRB63");
    }
}

void BUG_FP_FRB63_COPY() {
    report_reached("FP_FRB63");
    // If a NULL simulated descriptor survived its field reads, r0 is the
    // derived packet-copy destination at the call-site harm boundary.
    if (reg_state[2] != 0 &&
        (reg_state[0] < 0x20000000 || reg_state[0] >= 0x20030000)) {
        report_detected_triggered("FP_FRB63");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08011ad4, BUG_FP_FW40);
    frb_add_reflection_point(0x08011b0a, BUG_FP_FW40);
    frb_add_reflection_point(0x08011a48, BUG_FP_FW40);
    frb_add_reflection_point(0x0800fe60, BUG_S03);
    frb_add_reflection_point(0x0800fe66, BUG_S03);
    frb_add_reflection_point(0x0800fe94, BUG_S03);
    frb_add_reflection_point(0x0800fe52, BUG_S03);
    frb_add_reflection_point(0x08011416, BUG_FRB61);
    frb_add_reflection_point(0x0801142e, BUG_FRB61);
    frb_add_reflection_point(0x0800ff9e, BUG_FRB62);
    frb_add_reflection_point(0x0800ffbc, BUG_FRB62);
    frb_add_reflection_point(0x0800ffdc, BUG_FRB62);
    frb_add_reflection_point(0x0800ff98, BUG_FRB62);
    frb_add_reflection_point(0x0800ffb0, BUG_FRB62);
    frb_add_reflection_point(0x0800ffd0, BUG_FRB62);
    frb_add_reflection_point(0x0800c78a, BUG_FP_FRB63);
    frb_add_reflection_point(0x0800c7b4, BUG_FP_FRB63_COPY);
}
