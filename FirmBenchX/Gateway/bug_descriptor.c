#include <tcclib.h>
#include <stdint.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern uint32_t frb_mem_write(uint32_t write_addr, uint32_t value, size_t size);
extern void frb_report_detected_triggered(char* bug_id);
extern void frb_report_reached(char* bug_id);
typedef void (*func_ptr_t)(void);

typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;


static void print_reg_state(uint32_t *reg_state){
    printf("Register State:\n");
    printf("r0:  0x%08X\n", reg_state[0]);
    printf("r1:  0x%08X\n", reg_state[1]);
    printf("r2:  0x%08X\n", reg_state[2]);
    printf("r3:  0x%08X\n", reg_state[3]);
    printf("r4:  0x%08X\n", reg_state[4]);
    printf("r5:  0x%08X\n", reg_state[5]);
    printf("r6:  0x%08X\n", reg_state[6]);
    printf("r7:  0x%08X\n", reg_state[7]);
    printf("r8:  0x%08X\n", reg_state[8]);
    printf("r9:  0x%08X\n", reg_state[9]);
    printf("r10: 0x%08X\n", reg_state[10]);
    printf("r11: 0x%08X\n", reg_state[11]);
    printf("r12: 0x%08X\n", reg_state[12]);
    printf("sp:  0x%08X\n", reg_state[13]);
    printf("lr:  0x%08X\n", reg_state[14]);
    printf("pc:  0x%08X\n", reg_state[15]);
}

static void report_detected_triggered(char* bug_id) {
    frb_report_detected_triggered(bug_id);
    fflush(stdout);
}

static void report_reached(char* bug_id) {
    frb_report_reached(bug_id);
    fflush(stdout);
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


context_struct context_array[] = {
    {0x08002fc6, BUG_FW12},
    {0x08008796, BUG_FP_FW21},
    {0x08008770, BUG_FP_FW21},
    {0x080050da, BUG_FP_FW22},
    {0x0800501c, BUG_FP_FW22},
    {0x080071b4, pwm_ret},
    {0x08005e7a, check_FW23_use}, 
    {0x0800348a, BUG_E01},
    {0x08003422, BUG_MF01},
    {0x0800515a, BUG_FP_FRB01},
    {0x080050da, BUG_FP_FRB01},
    {0x08004f8e, BUG_FP_FRB02},
    {0x080050da, BUG_FP_FRB03},
    {0x0800501c, BUG_FP_FRB03},
    {0x08004e5e, BUG_FP_FRB04},
    {0x08007124, pwm_started},
    {0x08002890, three_wire}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
    
}

