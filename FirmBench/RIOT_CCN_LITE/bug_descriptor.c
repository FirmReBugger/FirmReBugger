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

void BUG_MF19() {
    // Stdio initialization race: __swsetup_r is about to write through a
    // read-only fake FILE object exposed by partially initialized newlib state.
    report_reached("MF19");
    uint32_t stream = reg_state[4];
    if (stream == frb_symbolize("__sf_fake_stdin", 0) ||
        stream == frb_symbolize("__sf_fake_stdout", 0) ||
        stream == frb_symbolize("__sf_fake_stderr", 0)) {
        report_detected_triggered("MF19");
    }
}

void BUG_MF19_flush() {
    // The partially published stdout has no write callback yet, and
    // __sflush_r is about to dispatch it.
    report_reached("MF19");
    uint32_t reent = frb_symbolize("impure_data", 0);
    if (reg_state[12] == 0 &&
        reg_state[4] == frb_mem_read(reent + 8, 4) &&
        frb_mem_read(reent + 24, 4) == 1) {
        report_detected_triggered("MF19");
    }
}

void BUG_MF22() {
    // _ccnl_content does not check a failed NDN-TLV reparse before wrapping
    // and caching the returned packet.
    report_reached("MF22");
    if (reg_state[0] == 0) {
        report_detected_triggered("MF22");
    }
}

void BUG_MF20() {
    // Reinitialization of shared global timer
    report_reached("MF20");
    uint32_t evtimer = frb_symbolize("ccnl_evtimer", 0);
    if (frb_mem_read(evtimer + 24, 4) != 0) {
        report_detected_triggered("MF20");
    }
}

void BUG_MF21() {
    // ccnl_face_remove must not free a face while its embedded timeout event
    // remains linked in the global evtimer list.
    report_reached("MF21");
    uint32_t face_event = reg_state[0] + 68;
    uint32_t evtimer = frb_symbolize("ccnl_evtimer", 0);
    uint32_t event = frb_mem_read(evtimer + 24, 4);

    for (uint32_t i = 0; event != 0 && i < 64; i++) {
        if (event == face_event) {
            report_detected_triggered("MF21");
            return;
        }
        if ((event & 3) != 0 || event < 0x20000000 || event >= 0x20010000) {
            return;
        }
        event = frb_mem_read(event, 4);
    }
}

void BUG_FP_MF22() {
    // Uninitialized RTC Overflow Callback
    report_reached("FP_MF22");
    if (reg_state[3] == 0x0) {
        report_detected_triggered("FP_MF22");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0001372a, BUG_MF22);
    frb_add_reflection_point(0x0001356c, BUG_MF20);
    frb_add_reflection_point(0x000168f6, BUG_MF21);
    frb_add_reflection_point(0x00012aa6, BUG_FP_MF22);
    frb_add_reflection_point(0x00012a8e, BUG_FP_MF22);
    frb_add_reflection_point(0x0001a0cc, BUG_MF19);
    frb_add_reflection_point(0x00019488, BUG_MF19_flush);
}
