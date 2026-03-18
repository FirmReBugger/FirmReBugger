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
    //Stack overflow in USB_SendString_descriptor
    uint32_t w_len = reg_state[1];
    if (w_len > 0xc000) {
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
    //strok not checked for NULL in gsm_get_time
    if (reg_state[0] == 0) {
        report_detected_triggered("MF03");
    }
}

void strex() {
    report_reached("ERROR:strex");
    report_detected_triggered("ERROR:strex");
}

const

void register_reflection_points() {
    frb_add_reflection_point(0x00084336, BUG_FW30);
    frb_add_reflection_point(0x00080b12, BUG_FW31);
    frb_add_reflection_point(0x00080b18, BUG_S01);
    frb_add_reflection_point(0x00081d6c, BUG_MF02);
    frb_add_reflection_point(0x00080f30, BUG_S02);
    frb_add_reflection_point(0x00080f38, BUG_MF03);
    frb_add_reflection_point(0x0008405e, strex);
}
