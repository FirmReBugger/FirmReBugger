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

void BUG_FW29() {
    report_reached("FW29");
    //Buffer overflow in set_code
    if (reg_state[4] == 16) {
        report_detected_triggered("FW29");
    }
}

void BUG_FP_FW38() {
    // Infinite recursion in error handler
    report_reached("FP_FW38");
    uint32_t stdio_uart_inited = frb_mem_read(0x20000f04, 4);
    if (stdio_uart_inited == 0) {
        report_detected_triggered("FP_FW38");
    }
}

void BUG_FRB09() {
    report_reached("FRB09");
    uint32_t buffer_start = reg_state[13] + 8;
    uint32_t puvar4 = reg_state[4];
    int idx = puvar4 - buffer_start;
    if (idx == 16) {
        report_detected_triggered("FRB09");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0000042c, BUG_FW29);
    frb_add_reflection_point(0x00001894, BUG_FP_FW38);
    frb_add_reflection_point(0x000003da, BUG_FRB09);
}
