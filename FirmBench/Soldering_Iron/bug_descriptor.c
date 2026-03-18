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


void BUG_FP_I02() {
    // (FP) Overflow of OLED screen buffer when rendering heat indicator
    report_reached("FP_I02");
    if (reg_state[7] > 162) {
        report_detected_triggered("FP_I02");
    }
}

void BUG_FP_MF02() {
    report_reached("FP_MF02");
    // (FP) Buffer overflow in I2C error handling
    if (reg_state[3] > 0x20004f70) {
        report_detected_triggered("FP_MF02");
    }
}

void HAL_I2C_Mem_Read_ret(){
    report_reached("FW19");
    frb_mem_write(0x200030cc,0xDEADBEEF,4);
}

void HAL_I2C_Mem_Write_ret(){
    report_reached("H01");
    frb_mem_write(0x200030cc,0xDEADBEEE,4);
}

void check_I2C_ITError() {
    // check I2C_ITError uses invalid pointer
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void check_I2C_MasterReceive_RXNE() {
    //check I2C_MasterReceive_RXNE uses invalid pointer
    uint32_t ptr  = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void check_I2C_MasterReceive_BTF () {
    // check I2C_MasterReceive_BTF uses invalid pointer
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void check_I2C_MasterTransmit_BTF() {
    // check I2C_MasterReceive_BTF uses invalid pointer
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void check_I2C_MasterTransmit_TXE(){
    // check I2C_MasterTransmit_TXE uses invalid pointer
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void underflow1() {
    // (FP) Underflow in hi2c->xfercount in HAL_I2C_Mem_Read
    report_reached("FP_FRB05");
    uint32_t xcount = frb_mem_read(0x200030d2,4);
    if (xcount == 0) {
        report_detected_triggered("FP_FRB05");
    }
}

void flag_mem_write() {
    report_reached("H01");
    frb_mem_write(0x200030cc, 0xDEADBEEE, 4);
}

void check_mem_read() {
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void check_HAL_I2C_Master_Transmit() {
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void check_mem_write() {
    uint32_t ptr = frb_mem_read(0x200030cc,4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    } else if (ptr == 0xDEADBEEE) {
        report_detected_triggered("H01");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08005236, BUG_FP_I02);
    frb_add_reflection_point(0x0800b0c0, BUG_FP_MF02);
    frb_add_reflection_point(0x0800b022, BUG_FP_MF02);
    frb_add_reflection_point(0x0800c9b0, HAL_I2C_Mem_Read_ret);
    frb_add_reflection_point(0x0800c560, HAL_I2C_Mem_Write_ret);
    frb_add_reflection_point(0x0800af0c, check_I2C_ITError);
    frb_add_reflection_point(0x0800bdec, check_I2C_MasterReceive_RXNE);
    frb_add_reflection_point(0x0800bf2e, check_I2C_MasterReceive_BTF);
    frb_add_reflection_point(0x0800bd02, check_I2C_MasterTransmit_BTF);
    frb_add_reflection_point(0x0800bb10, check_I2C_MasterTransmit_TXE);
    frb_add_reflection_point(0x0800c56c, underflow1);
    frb_add_reflection_point(0x08004e68, flag_mem_write);
    frb_add_reflection_point(0x0800c780, check_mem_read);
    frb_add_reflection_point(0x0800c91a, check_mem_read);
    frb_add_reflection_point(0x0800c48c, check_mem_write);
    frb_add_reflection_point(0x0800ccb4, check_HAL_I2C_Master_Transmit);
}
