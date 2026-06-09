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

void modbus1() {
    report_reached("DI1");
    uint32_t res = reg_state[2] + reg_state[3];
    if (reg_state[3] > 0x200045e4) {
        report_detected_triggered("DI1");
    }
}

void modbus2() {
    report_reached("DI2");
    if (reg_state[3] >= 0x100) {
        report_detected_triggered("DI2");
    }
}

void modbus3() {
    report_reached("DI3");
    uint32_t res = reg_state[3] + reg_state[1];
    if (res > 0x200045e4) {
        report_detected_triggered("DI3");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0800289c, modbus1);
    frb_add_reflection_point(0x080028e0, modbus2);
    frb_add_reflection_point(0x0800297e, modbus3);
}
