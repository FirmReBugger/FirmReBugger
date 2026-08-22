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

#define MODBUS_RX_TX_BUFFER_START 0x200041a8u
#define MODBUS_RX_TX_BUFFER_END   0x200042a8u

void BUG_DI01() {
    report_reached("DI01");
    uint32_t destination = reg_state[2] + reg_state[3];
    if (destination < MODBUS_RX_TX_BUFFER_START ||
        destination >= MODBUS_RX_TX_BUFFER_END) {
        report_detected_triggered("DI01");
    }
}

void BUG_DI02() {
    report_reached("DI02");
    if (reg_state[3] >= 0x100u) {
        report_detected_triggered("DI02");
    }
}

void BUG_DI03() {
    report_reached("DI03");
    uint32_t source = reg_state[1] + reg_state[3];
    if (source < MODBUS_RX_TX_BUFFER_START ||
        source >= MODBUS_RX_TX_BUFFER_END) {
        report_detected_triggered("DI03");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x080029de, BUG_DI01);
    frb_add_reflection_point(0x0800290a, BUG_DI02);
    frb_add_reflection_point(0x0800297e, BUG_DI03);
}
