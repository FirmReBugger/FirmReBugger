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

void BUG_FW30() {
    report_reached("FW30");
    // Unbounded VLA in USB_SendStringDescriptor crosses below the static-data end.
    uint32_t w_len = reg_state[1];
    uint32_t sp = reg_state[13];
    uint32_t aligned_len = (w_len + 7u) & ~7u;
    if ((int32_t)w_len > 1 &&
        (aligned_len > sp || sp - aligned_len < 0x2007a838u)) {
        report_detected_triggered("FW30");
    }
}

void BUG_FW31() {
    report_reached("FW31");
    //strstr not checked for NULL in gsm_get_imei
    if (reg_state[0] == 0) {
        report_detected_triggered("FW31");
    }
}

void BUG_S01() {
    report_reached("S01");
    //strok not checked for NULL in gsm_get_imei
    if (reg_state[0] == 0) {
        report_detected_triggered("S01");
    }
}

void BUG_MF02() {
    report_reached("MF02");
    //strstr not checked for NULL in sms_check
    if (reg_state[5] == 0) {
        report_detected_triggered("MF02");
    }
}

void BUG_S02() {
    report_reached("S02");
    //strstr not checked for NULL in gsm_get_time
    if (reg_state[0] == 0) {
        report_detected_triggered("S02");
    }
}

void BUG_MF03() {
    report_reached("MF03");
    // strtok result reaches strlcpy only when gpsData.timerFirstFix is nonzero.
    if (reg_state[0] == 0 && frb_mem_read(0x20079a38u, 1) != 0) {
        report_detected_triggered("MF03");
    }
}

// void strex() {
//     report_reached("strex");
//     report_detected_triggered("strex");
// }

void register_reflection_points() {
    frb_add_reflection_point(0x0008424e, BUG_FW30);
    frb_add_reflection_point(0x00080ae2, BUG_FW31);
    frb_add_reflection_point(0x00080ae8, BUG_S01);
    frb_add_reflection_point(0x00081cf0, BUG_MF02);
    frb_add_reflection_point(0x00080eb4, BUG_S02);
    frb_add_reflection_point(0x00080ebc, BUG_MF03);

}
