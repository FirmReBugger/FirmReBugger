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

// void BUG_MF19() {
//     report_reached("MF19");
//     // 	Stdio initialization race
//     if (frb_mem_read(reg_state[3]+ 0x11c, 4) == 0x0) {
//         report_detected_triggered("MF19");
//     }
// }

int std_flag = 0;

void BUG_MF19_fin() {
    // 	Stdio initialization race
    std_flag = 1;
}

void BUG_MF19_check() {
    // 	Stdio initialization race
    report_reached("MF19");
    if (std_flag == 0) {
        report_detected_triggered("MF19");
    }
}

void BUG_MF22() {
    report_reached("MF22");
    // Issue with % encoded characters in ccnl_cs
    if (reg_state[3] == 0x25) {
        report_detected_triggered("MF22");
    }
}

void BUG_MF20() {
    // Reinitialization of shared global timer
    report_reached("MF20");
    report_detected_triggered("MF20");
}

void BUG_MF21() {
    // Missing removal from evtimer struct
    report_reached("MF21");
    report_detected_triggered("MF21");
}

void BUG_FP_MF22() {
    // Uninitialized RTC Overflow Callback
    report_reached("FP_MF22");
    if (reg_state[3] == 0x0) {
        report_detected_triggered("FP_MF22");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x00016216, BUG_MF22);
    frb_add_reflection_point(0x0001356c, BUG_MF20);
    frb_add_reflection_point(0x000168f6, BUG_MF21);
    frb_add_reflection_point(0x00012aa6, BUG_FP_MF22);
    frb_add_reflection_point(0x00012a8e, BUG_FP_MF22);
    frb_add_reflection_point(0x00019578, BUG_MF19_fin);
    frb_add_reflection_point(0x00019b90, BUG_MF19_check);
    frb_add_reflection_point(0x00019a5c, BUG_MF19_check);
}
