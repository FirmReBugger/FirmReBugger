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


void BUG_FW12() {
    report_reached("FW12");
    // User provided pin argument is not bounds checked
    if (reg_state[1] >= 60) {
        report_detected_triggered("FW12");
    }
}

void BUG_FP_FW21() {
    report_reached("FP_FW21");
    // (FP) initialization race in HAL_UART_TxCpltCallback
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FW21");
    }
}

void BUG_FP_FW22() {
    report_reached("FP_FW22");
    // (FP) Uninitialized use of hi2c->pBuffPtrc in I2C_ITError
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FW22");
    }
}

// -------------FW23-------------
// Dangling pointer from pwm_start
int pwm_start = 0;
void pwm_ret() {
    //PWM_START_RETURN
    pwm_start = 0;
    report_reached("FW23");
    // timer_handles[1]
    frb_mem_write(0x20000610,0xDEADBEEF,4);

}
void pwm_started() {
    report_reached("FW23");
    pwm_start=1;
}

void check_FW23_use(){
    uint32_t ptr = frb_mem_read(0x20000610,4);
    if (ptr == 0xDEADBEEF || pwm_start == 1) {
        report_detected_triggered("FW23");
    }
}
// -------------FW23-------------

void BUG_E01() {
    report_reached("E01");
    // Unchecked error in decodeByteStream
    if (reg_state[0] != 0) {
        report_detected_triggered("E01");
    }
}

void BUG_MF01() {
    report_reached("MF01");
    // Incorrect handling of zero length sysex messages
    if (reg_state[1] < 1) {
        report_detected_triggered("MF01");
    }
}

void BUG_FP_FRB01() {
    report_reached("FP_FRB01");
    // unitilised DMA use in I2C_Slave_STOPF
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FRB01");
    }
}

void BUG_FP_FRB02() {
    report_reached("FP_FRB02");
    // unitilised DMA use in I2C_IT_ERROR
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB02");
    }
}

void BUG_FP_FRB03() {
    report_reached("FP_FRB03");
    // pbuffptr exceeds paser buff
    if (reg_state[2] > 0x200003d0) {
        report_detected_triggered("FP_FRB03");
    }
}

void BUG_FP_FRB04() {
    report_reached("FP_FRB04");
    // Uninitialized DMA use in I2C_MasterReceive_BTF
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB04");
    }
}

void three_wire(){
    report_reached("FP_FRB10");
    uint32_t wire_len = frb_mem_read(0x200003b4,4);
    if (wire_len + 1 > 7) {
    report_detected_triggered("FP_FRB10");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08002fc6, BUG_FW12);
    frb_add_reflection_point(0x0800878e, BUG_FP_FW21);
    frb_add_reflection_point(0x08008768, BUG_FP_FW21);
    frb_add_reflection_point(0x080050da, BUG_FP_FW22);
    frb_add_reflection_point(0x0800501c, BUG_FP_FW22);
    frb_add_reflection_point(0x080071ac, pwm_ret);
    frb_add_reflection_point(0x08005e72, check_FW23_use);
    frb_add_reflection_point(0x0800348a, BUG_E01);
    frb_add_reflection_point(0x08003422, BUG_MF01);
    frb_add_reflection_point(0x0800515a, BUG_FP_FRB01);
    frb_add_reflection_point(0x080050da, BUG_FP_FRB01);
    frb_add_reflection_point(0x08004f8e, BUG_FP_FRB02);
    frb_add_reflection_point(0x080050da, BUG_FP_FRB03);
    frb_add_reflection_point(0x0800501c, BUG_FP_FRB03);
    frb_add_reflection_point(0x08004e5e, BUG_FP_FRB04);
    frb_add_reflection_point(0x0800711c, pwm_started);
    frb_add_reflection_point(0x08002890, three_wire);
}
