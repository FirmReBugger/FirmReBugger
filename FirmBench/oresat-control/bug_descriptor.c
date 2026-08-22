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

void on_lfs() {
    report_reached("FRB48");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB48");
    }
}

void on_time_utc() {
    report_reached("FRB49");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB49");
    }
}

void on_time_scet() {
    report_reached("FRB50");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB50");
    }
}

void on_time_unix() {
    report_reached("FRB51");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB51");
    }
}

void on_CO_CANtx_cb() {
    report_reached("FP_FRB71");
    if (reg_state[5] == 0) {
        report_detected_triggered("FP_FRB71");
    }
}

void on_invalid_flash_size() {
    report_reached("FP_FRB65");
    report_detected_triggered("FP_FRB65");
}

void on_vector88(){
    report_reached("FP_FRB72");
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB72");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08016404, on_lfs);
    frb_add_reflection_point(0x08015f28, on_time_utc);
    frb_add_reflection_point(0x08015ec2, on_time_scet);
    frb_add_reflection_point(0x08015e5e, on_time_unix);
    frb_add_reflection_point(0x0802c22a, on_CO_CANtx_cb);
    frb_add_reflection_point(0x0801f298, on_invalid_flash_size);
    frb_add_reflection_point(0x08020742, on_vector88);
}
