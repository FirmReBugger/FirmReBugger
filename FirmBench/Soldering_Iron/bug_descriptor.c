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

static uint32_t expired_read_ptr;
static uint32_t expired_write_ptr;
static bool expired_read_valid;
static bool expired_write_valid;


void BUG_FP_I02() {
    // (FP) Overflow of OLED screen buffer when rendering heat indicator
    report_reached("FP_I02");
    // drawHeatSymbol divides its uint8_t input by 12, then computes 10-value.
    // Inputs >= 132 wrap that lower rectangle bound; the only callers pass the
    // getTipPWM result, which setTipPWM clamps to 100.
    if (reg_state[1] >= 132) {
        report_detected_triggered("FP_I02");
    }
}

void HAL_I2C_Mem_Read_ret(){
    report_reached("FP_FW19");
    expired_read_ptr = frb_mem_read(0x200030cc, 4);
    expired_read_valid = true;
    expired_write_valid = false;
}

void HAL_I2C_Mem_Write_ret(){
    report_reached("FP_H01");
    expired_write_ptr = frb_mem_read(0x200030cc, 4);
    expired_write_valid = true;
    expired_read_valid = false;
}

static void check_expired_i2c_ptr(void) {
    uint32_t ptr = frb_mem_read(0x200030cc, 4);

    // Attribute the emulator's synthetically delivered handler to the stale
    // pointer defect. The FP_ classification records that real hardware
    // cannot deliver this handler after the blocking call has returned.
    if (expired_read_valid && ptr - expired_read_ptr <= 6u) {
        report_detected_triggered("FP_FW19");
    } else if (expired_write_valid && ptr - expired_write_ptr <= 6u) {
        report_detected_triggered("FP_H01");
    }
}

void check_I2C_ITError() {
    check_expired_i2c_ptr();
}

void check_I2C_MasterReceive_RXNE() {
    check_expired_i2c_ptr();
}

void check_I2C_MasterReceive_BTF () {
    check_expired_i2c_ptr();
}

void check_I2C_MasterTransmit_BTF() {
    check_expired_i2c_ptr();
}

void check_I2C_MasterTransmit_TXE(){
    check_expired_i2c_ptr();
}

void underflow1() {
    // (FP) Underflow in hi2c->xfercount in HAL_I2C_Mem_Read
    report_reached("FP_FRB05");
    uint32_t xcount = frb_mem_read(0x200030d2, 2);
    if (xcount == 0) {
        report_detected_triggered("FP_FRB05");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08000edc, BUG_FP_I02);
    frb_add_reflection_point(0x0800c9b0, HAL_I2C_Mem_Read_ret);
    frb_add_reflection_point(0x0800c560, HAL_I2C_Mem_Write_ret);
    frb_add_reflection_point(0x0800b0c0, check_I2C_ITError);
    frb_add_reflection_point(0x0800b022, check_I2C_ITError);
    frb_add_reflection_point(0x0800bdec, check_I2C_MasterReceive_RXNE);
    frb_add_reflection_point(0x0800bf2e, check_I2C_MasterReceive_BTF);
    frb_add_reflection_point(0x0800bd02, check_I2C_MasterTransmit_BTF);
    frb_add_reflection_point(0x0800bb10, check_I2C_MasterTransmit_TXE);
    frb_add_reflection_point(0x0800c79e, underflow1);
    frb_add_reflection_point(0x0800c7f0, underflow1);
    frb_add_reflection_point(0x0800c820, underflow1);
    frb_add_reflection_point(0x0800c862, underflow1);
    frb_add_reflection_point(0x0800c8ba, underflow1);
    frb_add_reflection_point(0x0800c8ea, underflow1);
    frb_add_reflection_point(0x0800c93a, underflow1);
    frb_add_reflection_point(0x0800c976, underflow1);
}
