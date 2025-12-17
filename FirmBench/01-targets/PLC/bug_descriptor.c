#include <tcclib.h>
#include <stdint.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_report_detected_triggered(char* bug_id);
extern void frb_report_reached(char* bug_id);

typedef void (*func_ptr_t)(void);

typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;

static void report_detected_triggered(char* bug_id) {
    frb_report_detected_triggered(bug_id);
}

static void report_reached(char* bug_id) {
    frb_report_reached(bug_id);
}

void BUG_FW14() {
    report_reached("FW14");
    // Buffer overflow in process_FC1
    uint32_t u16Coilno = reg_state[0];
    int ADD_LOW = 0x3;
    if (((u16Coilno / 8) + ADD_LOW) > 64) {
        report_detected_triggered("FW14");
    }
}

void BUG_FW15() {
    report_reached("FW15");
    // Buffer overflow in process_FC3
    uint32_t offset = reg_state[6];
    uint32_t len = reg_state[0];
    if ((offset+len) > 64) {
        report_detected_triggered("FW15");
    }
}

void BUG_FW16() {
    report_reached("FW16");
    // Buffer overflow in process_FC15
    uint32_t offset = reg_state[6];
    uint32_t len = reg_state[0];
    if ((offset+len) > 16) {
        report_detected_triggered("FW16");
    }
}

void BUG_FW17() {
    report_reached("FW17");
    // Buffer overflow in process_FC16
    uint32_t offset = reg_state[7];
    uint32_t len = reg_state[6];
    if ((offset+len) > 16) {
        report_detected_triggered("FW17");
    }
}

void BUG_FP_FW25 () {
    report_reached("FP_FW25");
    // (FP) Initialization race in HAL_UART_TxCpltCallback
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FW25");
    }
}

context_struct context_array[] = {
    {0x80008da, BUG_FW14},
    {0x8000990, BUG_FW15},
    {0x8000a72, BUG_FW16},
    {0x8000af0, BUG_FW17},
    {0x8003f30, BUG_FP_FW25}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}

// static void print_reg_state(uint32_t *reg_state){
//     printf("Register State:\n");
//     printf("r0:  0x%08X\n", reg_state[0]);
//     printf("r1:  0x%08X\n", reg_state[1]);
//     printf("r2:  0x%08X\n", reg_state[2]);
//     printf("r3:  0x%08X\n", reg_state[3]);
//     printf("r4:  0x%08X\n", reg_state[4]);
//     printf("r5:  0x%08X\n", reg_state[5]);
//     printf("r6:  0x%08X\n", reg_state[6]);
//     printf("r7:  0x%08X\n", reg_state[7]);
//     printf("r8:  0x%08X\n", reg_state[8]);
//     printf("r9:  0x%08X\n", reg_state[9]);
//     printf("r10: 0x%08X\n", reg_state[10]);
//     printf("r11: 0x%08X\n", reg_state[11]);
//     printf("r12: 0x%08X\n", reg_state[12]);
//     printf("sp:  0x%08X\n", reg_state[13]);
//     printf("lr:  0x%08X\n", reg_state[14]);
//     printf("pc:  0x%08X\n", reg_state[15]);
// }