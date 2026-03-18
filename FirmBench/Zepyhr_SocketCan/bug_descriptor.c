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

void BUG_FW43() {
    report_reached("FW43");
    //Unchecked error handler in z_impl_can_attach_msgq
    if (reg_state[2] == 0) {
        report_detected_triggered("FW43");
    }
}

void BUG_FP_FW44() {
    report_reached("FP_FW44");
    //(FP) Initialization race in log_backend_enable
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FW44");
    }
}

void BUG_MF06() {
    report_reached("MF06");
    //canbus subcommands fail to validate argument count
    // attach
    if (reg_state[0] == 0) {
        report_detected_triggered("MF06");
    }
}

void BUG_MF07() {
    report_reached("MF07");
    //canbus subcommands fail to validate argument count
    // cmd_config
    if (reg_state[0] == 0) {
        report_detected_triggered("MF07");
    }
}

void BUG_MF08() {
    report_reached("MF08");
    //canbus subcommands fail to validate argument count
    // cmd_deatch
    if (reg_state[0] == 0) {
        report_detected_triggered("MF08");
    }
}

void BUG_FP_MF09() {
    report_reached("FP_MF09");
    //(FP) Out-of-bounds write in can_stm32_attach
    if (reg_state[6] > 4) {
        report_detected_triggered("FP_MF09");
    }
}

void BUG_E03() {
    report_reached("E03");
    //Incorrect comparison used for bounds check in execute
    uint32_t read_addr = reg_state[13] + 0x14;
    if (reg_state[2] != 0 && frb_mem_read(read_addr,4) == 12) {
        report_detected_triggered("E03");
    }
}

void BUG_S05() {
    report_reached("S05");
    //net pkt command dereferences a user provided pointer
    uint32_t read_addr = reg_state[5] + 0x10;
    if (frb_mem_read(read_addr,4) == 0) {
        report_detected_triggered("S05");
    }
}

void BUG_MF10() {
    report_reached("MF10");
    //canbus subcommands fail to verify device type
    // config
    uint32_t read_addr = reg_state[0] + 0x4;
    if (frb_mem_read(read_addr,4) != 0x0800f7e4){
        report_detected_triggered("MF10");
    }
}

void BUG_MF11() {
    report_reached("MF11");
    //canbus subcommands fail to verify device type
    // attach
    uint32_t read_addr = reg_state[0] + 0x4;
    if (frb_mem_read(read_addr,4) != 0x0800f7e4){
        report_detected_triggered("MF11");
    }
}

void BUG_MF12() {
    report_reached("MF12");
    //canbus subcommands fail to verify device type
    // detach
    uint32_t read_addr = reg_state[0] + 0x4;
    if (frb_mem_read(read_addr,4) != 0x0800f7e4){
        report_detected_triggered("MF12");
    }
}

void BUG_MF13() {
    report_reached("MF13");
    //canbus subcommands fail to verify device type
    // config
    uint32_t read_addr = reg_state[0] + 0x4;
    if (frb_mem_read(read_addr,4) != 0x0800f7e4){
        report_detected_triggered("MF13");
    }
}

void BUG_MF14() {
    report_reached("MF14");
    //pwm subcommand fail to verify device type
    // usec
    if (reg_state[3] != 0x0800fe34) {
        report_detected_triggered("MF14");
    }
}

void BUG_MF15() {
    report_reached("MF15");
    //pwm subcommand fail to verify device type
    // nsec
    if (reg_state[3] != 0x0800fe34) {
        report_detected_triggered("MF15");
    }
}

void BUG_MF16() {
    report_reached("MF16");
    //pwm subcommand fail to verify device type
    // cycle
    if (reg_state[4] != 0x0800fe34) {
        report_detected_triggered("MF16");
    }
}

void div_by_zero() {
    report_reached("FP_FRB11");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB11");
    }
}

void div_by_zero_2() {
    report_reached("FP_FRB12");
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FRB12");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08004964, BUG_FW43);
    frb_add_reflection_point(0x0800c538, BUG_FP_FW44);
    frb_add_reflection_point(0x08005ba2, BUG_MF06);
    frb_add_reflection_point(0x08005dfe, BUG_MF07);
    frb_add_reflection_point(0x08005d52, BUG_MF08);
    frb_add_reflection_point(0x080058e6, BUG_FP_MF09);
    frb_add_reflection_point(0x08001e36, BUG_E03);
    frb_add_reflection_point(0x08008c4e, BUG_S05);
    frb_add_reflection_point(0x08005e28, BUG_MF10);
    frb_add_reflection_point(0x08005c6c, BUG_MF11);
    frb_add_reflection_point(0x08005d80, BUG_MF12);
    frb_add_reflection_point(0x08005f74, BUG_MF13);
    frb_add_reflection_point(0x0800945a, BUG_MF14);
    frb_add_reflection_point(0x080004fa, BUG_MF15);
    frb_add_reflection_point(0x080093be, BUG_MF16);
    frb_add_reflection_point(0x0800c02c, div_by_zero);
    frb_add_reflection_point(0x080023ce, div_by_zero_2);
}
