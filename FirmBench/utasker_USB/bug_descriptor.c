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

void BUG_FW27() {
    report_reached("FW27");
    // Buffer overflow in fnExtractFIFO: a hardware/peripheral-reported receive
    // length (r3 at hook, ldrh [r1,#268] a few instructions earlier) is used
    // unchecked as a word-copy count into a fixed 64-byte-per-endpoint slot.
    // TriAgent live-proved lengths >64 overrun the slot and corrupt adjacent
    // RAM (observed smashing a global endpoint-table pointer, later causing
    // an unrelated crash in fnActivateHWEndpoint). Was previously marked FP;
    // reclassified confirmed after live proof of the overflow actually
    // occurring (see bug_analysis/bugs/FW27.md).
    if (reg_state[3] > 64) {
        report_detected_triggered("FW27");
    }
}

void  BUG_FP_FW45() {
    report_reached("FP_FW45");
    //(FP) Out-of-bounds access in fnUSB_handle_frame from GRXSTSPR.CHNUM value
    if (reg_state[2] > 1) {
        report_detected_triggered("FP_FW45");
    }
}

void BUG_MF04() {
    report_reached("MF04");
    // Out-of-bounds access from interface index in control_callback
    if (reg_state[1] > 1) {
        report_detected_triggered("MF04");
    }
}

// BUG_FP_MF05 removed: its predicate read the global `SerialHandle`
// (0x20000948), but that global is only ever referenced by the MODBUS layer
// (fnMODBUS/fnMODBUS_transmit/fnHandleMODBUS_input/fnTimer_RTS_0) -- it is
// never touched by fnSciTxByte/fnSciRxByte, the functions this raven was
// hooked inside of. TriAgent triage of the crashes this ID was meant to
// explain found no "uninitialized SerialHandle" mechanism at all: both
// examined instances traced to unrelated memory corruption reaching the
// channel queue struct these functions actually use (one is a downstream
// symptom of FW27's/FW45's already-documented overflows; the other remains
// an open, not-fully-traced fnFillBuf-side corruption). Since the predicate
// checked memory with no relationship to the hook site and no correct
// replacement could be established from available evidence, the raven was
// removed rather than left checking the wrong thing. See
// bug_analysis/bugs/MF05.md for the full investigation.

void BUG_S04() {
    report_reached("S04");
    // Direct manipulation of memory using I/O menu
    if (reg_state[1] > 1) {
        report_detected_triggered("S04");
    }
}

void BUG_FP_FRB06() {
    // (FP) fnRead 
    report_reached("FP_FRB06");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB06");
    }
}

void BUG_FP_FRB07() {
    // (FP) fnMsgs
    report_reached("FP_FRB07");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB07");
    }
}

void BUG_FP_FRB08() {
    // (FP) fndriver 
    report_reached("FP_FRB08");
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FRB08");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0800d65e, BUG_FW27);
    frb_add_reflection_point(0x0800fc2c, BUG_FP_FW45);
    frb_add_reflection_point(0x08011c10, BUG_MF04);
    frb_add_reflection_point(0x080127c4, BUG_S04);
    frb_add_reflection_point(0x0800f29c, BUG_FP_FRB06);
    frb_add_reflection_point(0x0800f2d4, BUG_FP_FRB07);
    frb_add_reflection_point(0x0800f1f2, BUG_FP_FRB08);
}
